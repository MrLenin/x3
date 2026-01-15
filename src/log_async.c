/*
 * log_async.c - Asynchronous logging subsystem
 * Copyright 2024 AfterNET Development Team
 *
 * Ring buffer + dedicated writer thread for non-blocking log writes.
 * Based on Nefarious ircd_log_async pattern.
 */

#include "config.h"

#ifdef HAVE_PTHREAD_H

#include "log_async.h"
#include "common.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>

/* Log entry in the ring buffer */
struct log_async_entry {
    int fd;                              /* File descriptor (-1 = skip) */
    int syslog_priority;                 /* Syslog priority (0 = skip) */
    size_t len;                          /* Message length */
    char message[LOG_ASYNC_MAX_ENTRY];   /* Pre-formatted message */
};

/* Ring buffer state */
static struct {
    struct log_async_entry *entries;     /* Ring buffer array */
    unsigned int size;                   /* Number of entries */
    unsigned int head;                   /* Next write position (producer) */
    unsigned int tail;                   /* Next read position (consumer) */

    pthread_t writer_thread;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;            /* Signal: data available */
    pthread_cond_t not_full;             /* Signal: space available */
    pthread_cond_t flushed;              /* Signal: flush complete */

    int running;                         /* 1 if thread active */
    int flush_requested;                 /* Flush in progress */

    unsigned long written;               /* Statistics: entries written */
    unsigned long dropped;               /* Statistics: entries dropped */
} log_async;

/* Ring buffer helpers */
static inline unsigned int buffer_count(void)
{
    if (log_async.head >= log_async.tail)
        return log_async.head - log_async.tail;
    return log_async.size - log_async.tail + log_async.head;
}

static inline int buffer_full(void)
{
    return ((log_async.head + 1) % log_async.size) == log_async.tail;
}

static inline int buffer_empty(void)
{
    return log_async.head == log_async.tail;
}

/* Writer thread main loop */
static void *log_async_writer(UNUSED_ARG(void *arg))
{
    pthread_mutex_lock(&log_async.mutex);

    while (log_async.running || !buffer_empty()) {
        /* Wait for data if buffer empty */
        while (buffer_empty() && log_async.running) {
            pthread_cond_wait(&log_async.not_empty, &log_async.mutex);
        }

        /* Process entries */
        while (!buffer_empty()) {
            struct log_async_entry *entry = &log_async.entries[log_async.tail];
            int fd = entry->fd;
            int priority = entry->syslog_priority;
            size_t len = entry->len;
            char msg[LOG_ASYNC_MAX_ENTRY];

            /* Copy message while holding lock */
            memcpy(msg, entry->message, len);

            /* Advance tail */
            log_async.tail = (log_async.tail + 1) % log_async.size;

            /* Signal that space is available */
            pthread_cond_signal(&log_async.not_full);

            /* Release lock during I/O */
            pthread_mutex_unlock(&log_async.mutex);

            /* Perform actual I/O (blocking is OK here) */
            if (fd >= 0 && len > 0) {
                (void)!write(fd, msg, len);
            }
            if (priority > 0) {
                syslog(priority, "%.*s", (int)len, msg);
            }

            pthread_mutex_lock(&log_async.mutex);
            log_async.written++;
        }

        /* Signal flush completion if requested */
        if (log_async.flush_requested && buffer_empty()) {
            log_async.flush_requested = 0;
            pthread_cond_broadcast(&log_async.flushed);
        }
    }

    pthread_mutex_unlock(&log_async.mutex);
    return NULL;
}

int log_async_init(unsigned int buffer_size)
{
    int rc;

    if (log_async.running) {
        return 0;  /* Already initialized */
    }

    if (buffer_size == 0) {
        buffer_size = LOG_ASYNC_BUFFER_SIZE_DEFAULT;
    }

    /* Allocate ring buffer */
    log_async.entries = calloc(buffer_size, sizeof(struct log_async_entry));
    if (!log_async.entries) {
        return -1;
    }

    log_async.size = buffer_size;
    log_async.head = 0;
    log_async.tail = 0;
    log_async.written = 0;
    log_async.dropped = 0;
    log_async.flush_requested = 0;

    /* Initialize synchronization primitives */
    if (pthread_mutex_init(&log_async.mutex, NULL) != 0) {
        free(log_async.entries);
        log_async.entries = NULL;
        return -1;
    }

    if (pthread_cond_init(&log_async.not_empty, NULL) != 0 ||
        pthread_cond_init(&log_async.not_full, NULL) != 0 ||
        pthread_cond_init(&log_async.flushed, NULL) != 0) {
        pthread_mutex_destroy(&log_async.mutex);
        free(log_async.entries);
        log_async.entries = NULL;
        return -1;
    }

    log_async.running = 1;

    /* Create writer thread */
    rc = pthread_create(&log_async.writer_thread, NULL, log_async_writer, NULL);
    if (rc != 0) {
        log_async.running = 0;
        pthread_cond_destroy(&log_async.flushed);
        pthread_cond_destroy(&log_async.not_full);
        pthread_cond_destroy(&log_async.not_empty);
        pthread_mutex_destroy(&log_async.mutex);
        free(log_async.entries);
        log_async.entries = NULL;
        return -1;
    }

    return 0;
}

void log_async_shutdown(void)
{
    if (!log_async.running) {
        return;
    }

    pthread_mutex_lock(&log_async.mutex);
    log_async.running = 0;
    pthread_cond_signal(&log_async.not_empty);  /* Wake writer thread */
    pthread_mutex_unlock(&log_async.mutex);

    /* Wait for thread to finish draining buffer */
    pthread_join(log_async.writer_thread, NULL);

    /* Cleanup */
    pthread_cond_destroy(&log_async.flushed);
    pthread_cond_destroy(&log_async.not_full);
    pthread_cond_destroy(&log_async.not_empty);
    pthread_mutex_destroy(&log_async.mutex);
    free(log_async.entries);
    log_async.entries = NULL;
}

int log_async_write(int fd, int syslog_priority, const char *message, size_t len)
{
    struct log_async_entry *entry;
    struct timespec timeout;

    if (!log_async.running || !log_async.entries) {
        return -1;
    }

    if (len > LOG_ASYNC_MAX_ENTRY - 1) {
        len = LOG_ASYNC_MAX_ENTRY - 1;
    }

    pthread_mutex_lock(&log_async.mutex);

    /* Wait briefly if buffer is full */
    if (buffer_full()) {
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_nsec += 1000000;  /* 1ms wait */
        if (timeout.tv_nsec >= 1000000000) {
            timeout.tv_sec++;
            timeout.tv_nsec -= 1000000000;
        }

        if (pthread_cond_timedwait(&log_async.not_full, &log_async.mutex, &timeout) != 0) {
            /* Still full after timeout - do sync fallback */
            log_async.dropped++;
            pthread_mutex_unlock(&log_async.mutex);

            /* Sync fallback: write directly */
            if (fd >= 0 && len > 0) {
                (void)!write(fd, message, len);
            }
            if (syslog_priority > 0) {
                syslog(syslog_priority, "%.*s", (int)len, message);
            }

            return 1;  /* Sync fallback used */
        }
    }

    /* Queue the entry */
    entry = &log_async.entries[log_async.head];
    entry->fd = fd;
    entry->syslog_priority = syslog_priority;
    entry->len = len;
    memcpy(entry->message, message, len);

    log_async.head = (log_async.head + 1) % log_async.size;

    /* Signal writer thread */
    pthread_cond_signal(&log_async.not_empty);

    pthread_mutex_unlock(&log_async.mutex);
    return 0;  /* Successfully queued */
}

void log_async_flush(void)
{
    if (!log_async.running) {
        return;
    }

    pthread_mutex_lock(&log_async.mutex);

    if (!buffer_empty()) {
        log_async.flush_requested = 1;
        pthread_cond_signal(&log_async.not_empty);

        /* Wait for flush completion */
        while (log_async.flush_requested && log_async.running) {
            pthread_cond_wait(&log_async.flushed, &log_async.mutex);
        }
    }

    pthread_mutex_unlock(&log_async.mutex);
}

int log_async_available(void)
{
    return log_async.running && log_async.entries != NULL;
}

void log_async_stats(unsigned long *queued, unsigned long *written, unsigned long *dropped)
{
    pthread_mutex_lock(&log_async.mutex);
    if (queued) *queued = buffer_count();
    if (written) *written = log_async.written;
    if (dropped) *dropped = log_async.dropped;
    pthread_mutex_unlock(&log_async.mutex);
}

#endif /* HAVE_PTHREAD_H */
