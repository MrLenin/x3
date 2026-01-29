/*
 * x3_kc_adapter.c - Bridge between X3's ioset/timeq and libkc's event adapter
 *
 * Maps libkc's abstract kc_event_ops interface to X3's concrete event loop:
 *   - kc_event_ops.socket_*  →  ioset (epoll/select/kevent)
 *   - kc_event_ops.timer_*   →  timeq (binary heap timer queue)
 *   - kc_event_ops.now        →  X3's global `now` variable
 *   - kc_event_ops.poll_hint  →  ioset_set_poll_hint_ms()
 *   - kc_log_ops.log          →  log_module()
 *
 * ioset dispatches read and write events separately: readable_cb for EPOLLIN,
 * writable_cb for EPOLLOUT. We register both callbacks so libkc receives the
 * correct event direction for curl_multi_socket_action().
 * EPOLLOUT is only registered when writable_cb is non-NULL (controlled by
 * fd_wants_writes()), so we set/clear writable_cb as curl's interest changes.
 */

#include "x3_kc_adapter.h"
#include "common.h"
#include "ioset.h"
#include "timeq.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

/* --- Socket adapter --- */

/*
 * Wraps libkc's socket callback into ioset's readable_cb pattern.
 * We maintain an array indexed by fd for O(1) lookup.
 */
struct x3_kc_socket {
    int fd;
    void (*kc_callback)(int fd, int events, void *data);
    void *kc_data;
    struct io_fd *io_fd;
    int events;  /* KC_EVENT_READ | KC_EVENT_WRITE */
};

#define MAX_KC_SOCKETS 256
static struct x3_kc_socket *kc_sockets[MAX_KC_SOCKETS];

static struct log_type *x3_kc_log_type = NULL;

/* ioset readable_cb: fired when the socket has data to read */
static void
x3_kc_socket_read_ready(struct io_fd *fd)
{
    struct x3_kc_socket *sock = fd->data;
    if (!sock || !sock->kc_callback)
        return;

    sock->kc_callback(sock->fd, KC_EVENT_READ, sock->kc_data);
}

/* ioset writable_cb: fired when the socket is ready for writing */
static void
x3_kc_socket_write_ready(struct io_fd *fd)
{
    struct x3_kc_socket *sock = fd->data;
    if (!sock || !sock->kc_callback)
        return;

    sock->kc_callback(sock->fd, KC_EVENT_WRITE, sock->kc_data);
}

static int
x3_socket_add(int fd, int events,
              void (*callback)(int fd, int events, void *data), void *data)
{
    struct x3_kc_socket *sock;
    struct io_fd *io;

    if (fd < 0 || fd >= MAX_KC_SOCKETS)
        return -1;

    sock = calloc(1, sizeof(*sock));
    if (!sock)
        return -1;

    io = ioset_add(fd);
    if (!io) {
        free(sock);
        return -1;
    }

    sock->fd = fd;
    sock->kc_callback = callback;
    sock->kc_data = data;
    sock->events = events;
    sock->io_fd = io;

    io->state = IO_CONNECTED;  /* Already connected by curl */
    io->line_reads = 0;        /* Raw socket, no line buffering */
    io->readable_cb = x3_kc_socket_read_ready;
    io->data = sock;

    /* Set writable_cb if curl wants write events; this also causes
     * fd_wants_writes() to return true so EPOLLOUT gets registered. */
    if (events & KC_EVENT_WRITE)
        io->writable_cb = x3_kc_socket_write_ready;

    kc_sockets[fd] = sock;

    /* Update epoll registration now that callbacks are configured */
    ioset_update(io);

    return 0;
}

static int
x3_socket_update(int fd, int events)
{
    struct x3_kc_socket *sock;

    if (fd < 0 || fd >= MAX_KC_SOCKETS || !kc_sockets[fd])
        return -1;

    sock = kc_sockets[fd];
    sock->events = events;

    /* Update writable_cb to match curl's write interest.
     * This controls whether fd_wants_writes() includes this fd,
     * which in turn controls EPOLLOUT registration. */
    if (sock->io_fd) {
        sock->io_fd->writable_cb = (events & KC_EVENT_WRITE)
            ? x3_kc_socket_write_ready : NULL;
        ioset_update(sock->io_fd);
    }

    return 0;
}

static void
x3_socket_remove(int fd)
{
    struct x3_kc_socket *sock;

    if (fd < 0 || fd >= MAX_KC_SOCKETS)
        return;

    sock = kc_sockets[fd];
    if (!sock)
        return;

    if (sock->io_fd) {
        ioset_close(sock->io_fd, 0);  /* Remove from epoll; don't close fd (curl owns it) */
        sock->io_fd = NULL;
    }

    kc_sockets[fd] = NULL;
    free(sock);
}

/* --- Timer adapter --- */

/*
 * Wraps libkc's timer callback for timeq.
 * timeq uses second-precision scheduling, so we also set
 * poll_hint_ms for sub-second precision.
 */
struct x3_kc_timer {
    void (*kc_callback)(void *data);
    void *kc_data;
    time_t when;
};

static void
x3_timer_fired(void *data)
{
    struct x3_kc_timer *timer = data;
    void (*cb)(void *) = timer->kc_callback;
    void *cb_data = timer->kc_data;

    /* Free timer before invoking callback — callback may re-add timers */
    free(timer);
    cb(cb_data);
}

static void *
x3_timer_add(unsigned long ms, void (*callback)(void *data), void *data)
{
    struct x3_kc_timer *timer;

    timer = calloc(1, sizeof(*timer));
    if (!timer)
        return NULL;

    timer->kc_callback = callback;
    timer->kc_data = data;

    /* timeq has second precision; round up to not fire early */
    timer->when = now + (ms / 1000) + (ms % 1000 ? 1 : 0);
    timeq_add(timer->when, x3_timer_fired, timer);

    return timer;
}

static void
x3_timer_cancel(void *handle)
{
    struct x3_kc_timer *timer = handle;
    if (!timer)
        return;

    timeq_del(0, x3_timer_fired, timer, TIMEQ_IGNORE_WHEN);
    free(timer);
}

/* --- Time adapter --- */

static unsigned long
x3_now(void)
{
    return (unsigned long)now;
}

/* --- Poll hint adapter --- */

static void
x3_poll_hint(long timeout_ms)
{
    ioset_set_poll_hint_ms(timeout_ms);
}

/* --- Log adapter --- */

static void
x3_kc_log_fn(enum kc_log_level level, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    enum log_severity sev;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    switch (level) {
    case KC_LOG_DEBUG:   sev = LOG_DEBUG;   break;
    case KC_LOG_INFO:    sev = LOG_INFO;    break;
    case KC_LOG_WARNING: sev = LOG_WARNING; break;
    case KC_LOG_ERROR:   sev = LOG_ERROR;   break;
    default:             sev = LOG_INFO;    break;
    }

    if (x3_kc_log_type)
        log_module(x3_kc_log_type, sev, "%s", buf);
}

/* --- Ops structs --- */

static struct kc_event_ops x3_event_ops = {
    .socket_add    = x3_socket_add,
    .socket_update = x3_socket_update,
    .socket_remove = x3_socket_remove,
    .timer_add     = x3_timer_add,
    .timer_cancel  = x3_timer_cancel,
    .now           = x3_now,
    .poll_hint_ms  = x3_poll_hint,
};

static struct kc_log_ops x3_log_ops = {
    .log = x3_kc_log_fn,
};

/* --- Public API --- */

void
x3_kc_adapter_init(void)
{
    x3_kc_log_type = log_register_type("libkc", "file:keycloak.log");
    memset(kc_sockets, 0, sizeof(kc_sockets));
}

const struct kc_event_ops *
x3_kc_get_event_ops(void)
{
    return &x3_event_ops;
}

const struct kc_log_ops *
x3_kc_get_log_ops(void)
{
    return &x3_log_ops;
}

void
x3_kc_adapter_cleanup(void)
{
    int i;

    /* Clean up any lingering socket wrappers */
    for (i = 0; i < MAX_KC_SOCKETS; i++) {
        if (kc_sockets[i]) {
            if (kc_sockets[i]->io_fd)
                ioset_close(kc_sockets[i]->io_fd, 0);
            free(kc_sockets[i]);
            kc_sockets[i] = NULL;
        }
    }
}
