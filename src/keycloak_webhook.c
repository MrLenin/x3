/*
 * Keycloak Webhook Handler for X3
 * Copyright (C) 2025 AfterNET Development Team
 *
 * Receives Keycloak Admin Events via HTTP POST for real-time cache invalidation.
 */

#include "keycloak_webhook.h"

#if WITH_KEYCLOAK_WEBHOOK

#include "ioset.h"
#include "log.h"
#include "conf.h"
#include "common.h"
#include "x3_lmdb.h"
#include "nickserv.h"
#include "chanserv.h"  /* For chanserv_queue_keycloak_sync, kc_group_path_to_channel */
#include "timeq.h"     /* For async event processing */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <jansson.h>

/* Log module */
static struct log_type *webhook_log;

/* Configuration */
static int webhook_port = KC_WEBHOOK_PORT_DEFAULT;
static char *webhook_secret = NULL;
static char *webhook_bind_address = NULL;

/* Listener socket */
static struct io_fd *webhook_listener = NULL;

/* Statistics */
static struct kc_webhook_stats stats = {0};

/* Async event queue */
#define WEBHOOK_QUEUE_MAX 1000  /* Max queued events before dropping */

struct webhook_event {
    char *payload;
    size_t payload_len;
    struct webhook_event *next;
};

static struct webhook_event *event_queue_head = NULL;
static struct webhook_event *event_queue_tail = NULL;
static unsigned int event_queue_size = 0;
static int process_scheduled = 0;

/* HTTP connection state */
struct webhook_conn {
    struct io_fd *fd;
    char *buffer;
    size_t buf_size;
    size_t buf_used;
    int headers_complete;
    size_t content_length;
    char method[16];
    char path[256];
    char content_type[128];
    char auth_header[256];
};

/* Forward declarations */
static void webhook_accept(struct io_fd *listener, struct io_fd *new_fd);
static void webhook_readable(struct io_fd *fd);
static void webhook_destroy(struct io_fd *fd);
static int process_webhook_request(struct webhook_conn *conn);
static int parse_http_headers(struct webhook_conn *conn);
static int handle_keycloak_event(const char *body, size_t body_len);
static void send_http_response(struct io_fd *fd, int status, const char *message);
static void webhook_process_queue(void *data);
static int webhook_queue_event(const char *payload, size_t len);

/*
 * Initialize webhook listener
 */
int
keycloak_webhook_init(void)
{
    struct addrinfo hints, *ai;
    char port_str[16];
    int res;

    webhook_log = log_register_type("Webhook", "file:webhook.log");

    if (webhook_port <= 0) {
        log_module(webhook_log, LOG_DEBUG, "Keycloak webhook disabled (port=0)");
        return 0;
    }

    /* Close existing listener if any */
    if (webhook_listener) {
        ioset_close(webhook_listener, 1);
        webhook_listener = NULL;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;  /* IPv4 for simplicity */
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", webhook_port);
    res = getaddrinfo(webhook_bind_address, port_str, &hints, &ai);
    if (res) {
        log_module(webhook_log, LOG_ERROR,
                   "Failed to resolve webhook address [%s]:%s: %s",
                   webhook_bind_address ? webhook_bind_address : "*",
                   port_str, gai_strerror(res));
        return -1;
    }

    webhook_listener = ioset_listen(ai->ai_addr, ai->ai_addrlen, NULL, webhook_accept);
    freeaddrinfo(ai);

    if (!webhook_listener) {
        log_module(webhook_log, LOG_ERROR,
                   "Failed to listen on [%s]:%d for Keycloak webhook",
                   webhook_bind_address ? webhook_bind_address : "*",
                   webhook_port);
        return -1;
    }

    log_module(webhook_log, LOG_INFO,
               "Keycloak webhook listening on port %d", webhook_port);
    return 0;
}

/*
 * Shutdown webhook listener
 */
void
keycloak_webhook_shutdown(void)
{
    struct webhook_event *evt, *next;

    if (webhook_listener) {
        ioset_close(webhook_listener, 1);
        webhook_listener = NULL;
        log_module(webhook_log, LOG_INFO, "Keycloak webhook listener closed");
    }

    /* Drain the event queue */
    for (evt = event_queue_head; evt; evt = next) {
        next = evt->next;
        free(evt->payload);
        free(evt);
    }
    event_queue_head = event_queue_tail = NULL;
    event_queue_size = 0;
    process_scheduled = 0;

    free(webhook_secret);
    webhook_secret = NULL;
    free(webhook_bind_address);
    webhook_bind_address = NULL;
}

/*
 * Check if webhook is running
 */
int
keycloak_webhook_is_running(void)
{
    return webhook_listener != NULL;
}

/*
 * Get webhook statistics
 */
const struct kc_webhook_stats *
keycloak_webhook_get_stats(void)
{
    return &stats;
}

/*
 * Configuration accessors
 */
int keycloak_webhook_get_port(void) { return webhook_port; }
const char *keycloak_webhook_get_secret(void) { return webhook_secret ? webhook_secret : ""; }

void
keycloak_webhook_set_port(int port)
{
    webhook_port = port;
}

void
keycloak_webhook_set_secret(const char *secret)
{
    free(webhook_secret);
    webhook_secret = secret ? strdup(secret) : NULL;
}

/*
 * Accept new webhook connection
 */
static void
webhook_accept(UNUSED_ARG(struct io_fd *listener), struct io_fd *new_fd)
{
    struct webhook_conn *conn;

    conn = calloc(1, sizeof(*conn));
    if (!conn) {
        ioset_close(new_fd, 1);
        return;
    }

    conn->fd = new_fd;
    conn->buf_size = 4096;  /* Initial buffer size */
    conn->buffer = malloc(conn->buf_size);
    if (!conn->buffer) {
        free(conn);
        ioset_close(new_fd, 1);
        return;
    }

    new_fd->data = conn;
    new_fd->line_reads = 0;  /* Binary mode - we parse HTTP ourselves */
    new_fd->readable_cb = webhook_readable;
    new_fd->destroy_cb = webhook_destroy;

    log_module(webhook_log, LOG_DEBUG, "Webhook connection accepted");
}

/*
 * Read and process webhook data
 */
static void
webhook_readable(struct io_fd *fd)
{
    struct webhook_conn *conn = fd->data;
    char readbuf[4096];
    int nbytes;

    /* Read available data */
    nbytes = recv(fd->fd, readbuf, sizeof(readbuf), 0);
    if (nbytes <= 0) {
        ioset_close(fd, 1);
        return;
    }

    /* Expand buffer if needed */
    if (conn->buf_used + nbytes > conn->buf_size) {
        size_t new_size = conn->buf_size * 2;
        if (new_size > KC_WEBHOOK_MAX_REQUEST) {
            log_module(webhook_log, LOG_WARNING, "Webhook request too large");
            send_http_response(fd, 413, "Request Too Large");
            ioset_close(fd, 3);  /* Flush response then close */
            return;
        }
        char *new_buf = realloc(conn->buffer, new_size);
        if (!new_buf) {
            ioset_close(fd, 1);
            return;
        }
        conn->buffer = new_buf;
        conn->buf_size = new_size;
    }

    memcpy(conn->buffer + conn->buf_used, readbuf, nbytes);
    conn->buf_used += nbytes;

    /* Try to parse headers if not done yet */
    if (!conn->headers_complete) {
        if (parse_http_headers(conn) < 0) {
            send_http_response(fd, 400, "Bad Request");
            ioset_close(fd, 3);  /* Flush response then close */
            return;
        }
        if (!conn->headers_complete) {
            /* Need more data */
            return;
        }
    }

    /* Check if we have the complete body */
    char *body_start = strstr(conn->buffer, "\r\n\r\n");
    if (!body_start)
        return;
    body_start += 4;

    size_t headers_len = body_start - conn->buffer;
    size_t body_received = conn->buf_used - headers_len;

    if (body_received < conn->content_length) {
        /* Need more body data */
        return;
    }

    /* Process the complete request */
    stats.events_received++;
    if (process_webhook_request(conn) == 0) {
        send_http_response(fd, 200, "OK");
    } else {
        send_http_response(fd, 400, "Bad Request");
    }

    /* Use flag 3 to flush pending writes (2) and close socket (1) */
    ioset_close(fd, 3);
}

/*
 * Cleanup webhook connection
 */
static void
webhook_destroy(struct io_fd *fd)
{
    struct webhook_conn *conn = fd->data;
    if (conn) {
        free(conn->buffer);
        free(conn);
    }
}

/*
 * Parse HTTP headers
 */
static int
parse_http_headers(struct webhook_conn *conn)
{
    char *line_end;
    char *p = conn->buffer;

    /* Null-terminate for string operations (temporary) */
    if (conn->buf_used >= conn->buf_size)
        return -1;
    conn->buffer[conn->buf_used] = '\0';

    /* Parse request line */
    line_end = strstr(p, "\r\n");
    if (!line_end)
        return 0;  /* Need more data */

    /* Parse "METHOD /path HTTP/1.x" */
    if (sscanf(p, "%15s %255s", conn->method, conn->path) != 2)
        return -1;

    p = line_end + 2;

    /* Parse headers */
    while ((line_end = strstr(p, "\r\n")) != NULL) {
        if (p == line_end) {
            /* Empty line = end of headers */
            conn->headers_complete = 1;
            return 0;
        }

        *line_end = '\0';

        /* Parse header */
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            conn->content_length = atoi(p + 15);
        } else if (strncasecmp(p, "Content-Type:", 13) == 0) {
            const char *val = p + 13;
            while (*val == ' ') val++;
            snprintf(conn->content_type, sizeof(conn->content_type), "%s", val);
        } else if (strncasecmp(p, "Authorization:", 14) == 0) {
            const char *val = p + 14;
            while (*val == ' ') val++;
            snprintf(conn->auth_header, sizeof(conn->auth_header), "%s", val);
        } else if (strncasecmp(p, "X-Webhook-Secret:", 17) == 0) {
            const char *val = p + 17;
            while (*val == ' ') val++;
            snprintf(conn->auth_header, sizeof(conn->auth_header), "%s", val);
        }

        *line_end = '\r';  /* Restore */
        p = line_end + 2;
    }

    return 0;  /* Need more data */
}

/*
 * Queue an event for async processing
 */
static int
webhook_queue_event(const char *payload, size_t len)
{
    struct webhook_event *evt;

    if (event_queue_size >= WEBHOOK_QUEUE_MAX) {
        log_module(webhook_log, LOG_WARNING,
                   "Webhook queue full (%u events), dropping event", event_queue_size);
        return -1;
    }

    evt = calloc(1, sizeof(*evt));
    if (!evt)
        return -1;

    evt->payload = malloc(len + 1);
    if (!evt->payload) {
        free(evt);
        return -1;
    }

    memcpy(evt->payload, payload, len);
    evt->payload[len] = '\0';
    evt->payload_len = len;
    evt->next = NULL;

    /* Add to tail of queue */
    if (event_queue_tail) {
        event_queue_tail->next = evt;
    } else {
        event_queue_head = evt;
    }
    event_queue_tail = evt;
    event_queue_size++;
    stats.events_queued = event_queue_size;

    /* Schedule processing if not already scheduled */
    if (!process_scheduled) {
        process_scheduled = 1;
        timeq_add(now, webhook_process_queue, NULL);
    }

    return 0;
}

/*
 * Process queued events (called from timeq)
 */
static void
webhook_process_queue(UNUSED_ARG(void *data))
{
    struct webhook_event *evt;
    int batch = 0;
    const int batch_max = 10;  /* Process up to 10 events per iteration */

    process_scheduled = 0;

    while (event_queue_head && batch < batch_max) {
        evt = event_queue_head;
        event_queue_head = evt->next;
        if (!event_queue_head)
            event_queue_tail = NULL;
        event_queue_size--;

        /* Process the event */
        handle_keycloak_event(evt->payload, evt->payload_len);

        free(evt->payload);
        free(evt);
        batch++;
    }

    stats.events_queued = event_queue_size;

    /* If more events remain, schedule another processing round */
    if (event_queue_head && !process_scheduled) {
        process_scheduled = 1;
        timeq_add(now, webhook_process_queue, NULL);
    }
}

/*
 * Process a complete webhook request
 */
static int
process_webhook_request(struct webhook_conn *conn)
{
    char *body;
    size_t body_len;

    /* Verify method */
    if (strcmp(conn->method, "POST") != 0) {
        log_module(webhook_log, LOG_DEBUG, "Ignoring non-POST request: %s", conn->method);
        return 0;  /* Not an error, just ignore */
    }

    /* Verify path */
    if (strcmp(conn->path, "/keycloak-webhook") != 0 &&
        strcmp(conn->path, "/webhook") != 0 &&
        strcmp(conn->path, "/") != 0) {
        log_module(webhook_log, LOG_DEBUG, "Ignoring request to unknown path: %s", conn->path);
        return 0;
    }

    /* Verify secret if configured */
    if (webhook_secret && webhook_secret[0]) {
        if (!conn->auth_header[0] || strcmp(conn->auth_header, webhook_secret) != 0) {
            log_module(webhook_log, LOG_WARNING,
                       "Webhook request with invalid/missing secret");
            stats.events_invalid++;
            return -1;
        }
    }

    /* Find body */
    body = strstr(conn->buffer, "\r\n\r\n");
    if (!body) {
        stats.events_invalid++;
        return -1;
    }
    body += 4;
    body_len = conn->content_length;

    /* Queue the event for async processing - return immediately */
    if (webhook_queue_event(body, body_len) < 0) {
        stats.events_invalid++;
        return -1;
    }

    log_module(webhook_log, LOG_DEBUG, "Webhook event queued (queue size: %u)", event_queue_size);
    return 0;
}

/*
 * Handle a Keycloak admin event
 *
 * Expected JSON format from Keycloak Admin Events:
 * {
 *   "id": "event-uuid",
 *   "time": 1234567890000,
 *   "realmId": "realm-uuid",
 *   "authDetails": { "userId": "...", "username": "..." },
 *   "resourceType": "USER" | "CREDENTIAL" | "CLIENT_SCOPE_MAPPING",
 *   "operationType": "CREATE" | "UPDATE" | "DELETE" | "ACTION",
 *   "resourcePath": "users/user-uuid/credentials/cred-id",
 *   "representation": "{...}" (JSON string of the resource)
 * }
 */
static int
handle_keycloak_event(const char *body, size_t body_len)
{
    json_t *root = NULL;
    json_error_t error;
    const char *resource_type = NULL;
    const char *operation_type = NULL;
    const char *resource_path = NULL;
    const char *representation = NULL;
    int result = 0;

    /* Parse JSON */
    root = json_loadb(body, body_len, 0, &error);
    if (!root) {
        log_module(webhook_log, LOG_WARNING,
                   "Failed to parse webhook JSON: %s", error.text);
        stats.events_invalid++;
        return -1;
    }

    /* Extract event fields */
    json_t *rt = json_object_get(root, "resourceType");
    json_t *ot = json_object_get(root, "operationType");
    json_t *rp = json_object_get(root, "resourcePath");
    json_t *rep = json_object_get(root, "representation");

    if (rt && json_is_string(rt))
        resource_type = json_string_value(rt);
    if (ot && json_is_string(ot))
        operation_type = json_string_value(ot);
    if (rp && json_is_string(rp))
        resource_path = json_string_value(rp);
    if (rep && json_is_string(rep))
        representation = json_string_value(rep);

    log_module(webhook_log, LOG_DEBUG,
               "Webhook event: resourceType=%s operationType=%s path=%s",
               resource_type ? resource_type : "(null)",
               operation_type ? operation_type : "(null)",
               resource_path ? resource_path : "(null)");

    if (!resource_type || !operation_type) {
        log_module(webhook_log, LOG_DEBUG, "Missing resourceType or operationType");
        json_decref(root);
        stats.events_invalid++;
        return -1;
    }

    stats.last_event_time = time(NULL);

    /* Handle different event types */
    if (strcmp(resource_type, "USER") == 0) {
        /* User events - extract username from authDetails or representation */
        const char *username = NULL;
        char *username_alloc = NULL;  /* Track if we allocated username */
        json_t *auth = json_object_get(root, "authDetails");
        if (auth) {
            json_t *uname = json_object_get(auth, "username");
            if (uname && json_is_string(uname))
                username = json_string_value(uname);
        }

        /* Try to get username from representation if not in authDetails */
        if (!username && representation) {
            json_t *rep_json = json_loads(representation, 0, NULL);
            if (rep_json) {
                json_t *uname = json_object_get(rep_json, "username");
                if (uname && json_is_string(uname)) {
                    /* Must strdup because rep_json will be freed */
                    username_alloc = strdup(json_string_value(uname));
                    username = username_alloc;
                }
                json_decref(rep_json);
            }
        }

        if (username) {
            if (strcmp(operation_type, "DELETE") == 0) {
                /* User deleted - clear all caches */
                log_module(webhook_log, LOG_INFO,
                           "User deleted via Keycloak: %s", username);
                keycloak_invalidate_user_caches(username, 1, 1);
            } else if (strcmp(operation_type, "UPDATE") == 0) {
                /* User updated - check for x3-specific attribute changes */
                int invalidated = 0;

                if (representation) {
                    json_t *rep_json = json_loads(representation, 0, NULL);
                    if (rep_json) {
                        json_t *attrs = json_object_get(rep_json, "attributes");
                        if (attrs && json_is_object(attrs)) {
                            /* Check for x3_opserv_level change */
                            if (json_object_get(attrs, "x3_opserv_level")) {
                                log_module(webhook_log, LOG_INFO,
                                           "OpServ level changed for %s via Keycloak", username);
                                /* Note: OpServ level is checked live from Keycloak,
                                 * but we log for tracking. Could add a local cache later. */
                                stats.opserv_invalidations++;
                                stats.cache_invalidations++;
                                invalidated = 1;
                            }
                            /* Check for x3_metadata changes */
                            if (json_object_get(attrs, "x3_metadata")) {
                                log_module(webhook_log, LOG_INFO,
                                           "Metadata changed for %s via Keycloak - invalidating cache", username);
                                /* Immediately purge all metadata entries for this user from LMDB */
                                int deleted = x3_lmdb_metadata_delete_by_user(username);
                                if (deleted > 0) {
                                    log_module(webhook_log, LOG_DEBUG,
                                               "Deleted %d metadata entries for %s", deleted, username);
                                }
                                stats.metadata_invalidations++;
                                stats.cache_invalidations++;
                                invalidated = 1;
                            }

                            /* Check for x3.channel.* attribute changes (bidirectional access sync) */
                            const char *key;
                            json_t *value;
                            json_object_foreach(attrs, key, value) {
                                if (strncmp(key, "x3.channel.", 11) == 0) {
                                    const char *channel = key + 11;  /* "#channelname" */
                                    unsigned short level = 0;

                                    /* Extract level from attribute value array */
                                    if (json_is_array(value) && json_array_size(value) > 0) {
                                        json_t *first = json_array_get(value, 0);
                                        if (first && json_is_string(first)) {
                                            level = (unsigned short)atoi(json_string_value(first));
                                        }
                                    }

                                    log_module(webhook_log, LOG_INFO,
                                               "Channel access changed for %s via Keycloak: %s = %u",
                                               username, channel, level);

                                    /* Apply to X3's internal access list */
                                    chanserv_keycloak_access_update(channel, username, level);
                                    stats.cache_invalidations++;
                                    invalidated = 1;
                                }
                            }
                        }
                        json_decref(rep_json);
                    }
                }

                if (invalidated) {
                    log_module(webhook_log, LOG_DEBUG,
                               "User updated via Keycloak: %s (caches invalidated)", username);
                } else {
                    log_module(webhook_log, LOG_DEBUG,
                               "User updated via Keycloak: %s (no x3 attributes)", username);
                }
            }
        }
        free(username_alloc);  /* Free if we allocated from representation */
    } else if (strcmp(resource_type, "CREDENTIAL") == 0) {
        /* Credential events - password or cert changes */
        if (strcmp(operation_type, "DELETE") == 0) {
            /* Credential deleted - might be a certificate fingerprint */
            if (representation) {
                json_t *rep_json = json_loads(representation, 0, NULL);
                if (rep_json) {
                    json_t *type = json_object_get(rep_json, "type");
                    json_t *cred_data = json_object_get(rep_json, "credentialData");

                    if (type && json_is_string(type) &&
                        strcmp(json_string_value(type), "x509") == 0 && cred_data) {
                        /* X.509 certificate credential - extract fingerprint */
                        json_t *cd = json_loads(json_string_value(cred_data), 0, NULL);
                        if (cd) {
                            json_t *fp = json_object_get(cd, "fingerprint");
                            if (fp && json_is_string(fp)) {
                                const char *fingerprint = json_string_value(fp);
                                log_module(webhook_log, LOG_INFO,
                                           "Certificate revoked via Keycloak: %.32s...",
                                           fingerprint);
                                x3_lmdb_fingerprint_delete(fingerprint);
                                stats.fingerprint_deletions++;
                                stats.cache_invalidations++;
                            }
                            json_decref(cd);
                        }
                    }
                    json_decref(rep_json);
                }
            }
        } else if (strcmp(operation_type, "UPDATE") == 0 ||
                   strcmp(operation_type, "CREATE") == 0) {
            /* Credential created or updated - check type and handle accordingly */
            if (representation) {
                json_t *rep_json = json_loads(representation, 0, NULL);
                if (rep_json) {
                    json_t *type = json_object_get(rep_json, "type");
                    const char *cred_type = type && json_is_string(type) ? json_string_value(type) : NULL;

                    /* Try to get username from representation or authDetails */
                    const char *username = NULL;
                    json_t *user_uname = json_object_get(rep_json, "username");
                    if (user_uname && json_is_string(user_uname)) {
                        username = json_string_value(user_uname);
                    }
                    if (!username) {
                        json_t *auth = json_object_get(root, "authDetails");
                        if (auth) {
                            json_t *uname = json_object_get(auth, "username");
                            if (uname && json_is_string(uname))
                                username = json_string_value(uname);
                        }
                    }

                    if (cred_type && strcmp(cred_type, "password") == 0 && username) {
                        /* Password credential changed - invalidate SCRAM caches */
                        log_module(webhook_log, LOG_INFO,
                                   "Password changed for %s via Keycloak - invalidating SCRAM caches",
                                   username);
                        x3_lmdb_scram_revoke_all(username);
                        x3_lmdb_scram_acct_delete_all(username);
                        stats.scram_invalidations++;
                        stats.cache_invalidations++;
                    } else if (cred_type && strcmp(cred_type, "x509") == 0 &&
                               strcmp(operation_type, "CREATE") == 0) {
                        /* New X.509 certificate - pre-warm fingerprint cache */
                        json_t *cred_data = json_object_get(rep_json, "credentialData");
                        if (cred_data && json_is_string(cred_data)) {
                            json_t *cd = json_loads(json_string_value(cred_data), 0, NULL);
                            if (cd) {
                                json_t *fp = json_object_get(cd, "fingerprint");
                                if (fp && json_is_string(fp) && username) {
                                    const char *fingerprint = json_string_value(fp);
                                    log_module(webhook_log, LOG_INFO,
                                               "Pre-warming fingerprint cache for %s: %.32s...",
                                               username, fingerprint);
                                    /* Pre-warm the fingerprint cache with the account name */
                                    x3_lmdb_fingerprint_set(fingerprint, username, now, 0);
                                    stats.fingerprint_additions++;
                                    stats.cache_invalidations++;
                                }
                                json_decref(cd);
                            }
                        }
                    }
                    json_decref(rep_json);
                }
            }
        }
    } else if (strcmp(resource_type, "USER_SESSION") == 0 ||
               strcmp(resource_type, "ADMIN_EVENT") == 0) {
        /* Session management events */
        if (operation_type && strcmp(operation_type, "DELETE") == 0) {
            /* Logout - might be a "logout all" action */
            /* Extract username and revoke X3 sessions */
            const char *username = NULL;
            json_t *auth = json_object_get(root, "authDetails");
            if (auth) {
                json_t *uname = json_object_get(auth, "username");
                if (uname && json_is_string(uname))
                    username = json_string_value(uname);
            }

            if (username) {
                log_module(webhook_log, LOG_INFO,
                           "Session logout via Keycloak for: %s", username);
                x3_lmdb_session_revoke_all(username);
                stats.session_revocations++;
                stats.cache_invalidations++;
            }
        }
    } else if (strcmp(resource_type, "GROUP_MEMBERSHIP") == 0) {
        /* Group membership change - sync affected channel */
        const char *group_path = NULL;

        /* Try to get group path from representation */
        if (representation) {
            json_t *rep_json = json_loads(representation, 0, NULL);
            if (rep_json) {
                json_t *gpath = json_object_get(rep_json, "path");
                if (gpath && json_is_string(gpath)) {
                    group_path = json_string_value(gpath);
                }

                if (group_path) {
                    /* Convert group path to channel name */
                    char *channel = kc_group_path_to_channel(group_path);
                    if (channel) {
                        log_module(webhook_log, LOG_INFO,
                                   "Group membership %s for channel %s (via webhook)",
                                   operation_type, channel);

                        /* Queue immediate sync for this channel */
                        int rc = chanserv_queue_keycloak_sync(channel, KC_SYNC_PRIORITY_IMMEDIATE);
                        if (rc == 0) {
                            stats.group_syncs++;
                            stats.cache_invalidations++;
                        }
                        free(channel);
                    }
                }
                json_decref(rep_json);
            }
        }
    } else if (strcmp(resource_type, "GROUP") == 0) {
        /* Group settings changed - might affect access level configuration */
        if (strcmp(operation_type, "UPDATE") == 0 && representation) {
            json_t *rep_json = json_loads(representation, 0, NULL);
            if (rep_json) {
                json_t *gpath = json_object_get(rep_json, "path");
                if (gpath && json_is_string(gpath)) {
                    const char *group_path = json_string_value(gpath);

                    /* Convert group path to channel name */
                    char *channel = kc_group_path_to_channel(group_path);
                    if (channel) {
                        log_module(webhook_log, LOG_INFO,
                                   "Group attributes changed for %s - queueing re-sync", channel);

                        /* Queue high-priority sync (not immediate, give time for batch changes) */
                        int rc = chanserv_queue_keycloak_sync(channel, KC_SYNC_PRIORITY_HIGH);
                        if (rc == 0) {
                            stats.group_syncs++;
                        }
                        free(channel);
                    }
                }
                json_decref(rep_json);
            }
        }
    }

    stats.events_processed++;
    json_decref(root);
    return result;
}

/*
 * Send HTTP response
 */
static void
send_http_response(struct io_fd *fd, int status, const char *message)
{
    char response[512];
    const char *status_text;

    switch (status) {
    case 200: status_text = "OK"; break;
    case 400: status_text = "Bad Request"; break;
    case 401: status_text = "Unauthorized"; break;
    case 403: status_text = "Forbidden"; break;
    case 404: status_text = "Not Found"; break;
    case 413: status_text = "Payload Too Large"; break;
    case 500: status_text = "Internal Server Error"; break;
    default: status_text = "Unknown"; break;
    }

    snprintf(response, sizeof(response),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: text/plain\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             status, status_text, strlen(message), message);

    ioset_write(fd, response, strlen(response));
}

/*
 * Manual cache invalidation function
 */
int
keycloak_invalidate_user_caches(const char *username,
                                 int invalidate_fingerprints,
                                 int invalidate_sessions)
{
    int count = 0;
    char keybuf[256];

    if (!username || !username[0])
        return 0;

    log_module(webhook_log, LOG_DEBUG,
               "Invalidating caches for user: %s (fp=%d, sess=%d)",
               username, invalidate_fingerprints, invalidate_sessions);

    /* Clear auth failure cache entries for this user */
    /* Note: We're using a simple approach - in practice we'd need
     * to iterate all authfail: keys and check if they match this user.
     * For now, auth failures are keyed by hash, not username, so we
     * can't easily clear them by username. This is by design to prevent
     * timing attacks. */

    /* Clear fingerprint cache if requested */
    if (invalidate_fingerprints) {
        struct lmdb_fingerprint_entry *fps = NULL;
        int fp_count = x3_lmdb_fingerprint_list_account(username, &fps);
        if (fp_count > 0 && fps) {
            struct lmdb_fingerprint_entry *fp = fps;
            while (fp) {
                x3_lmdb_fingerprint_delete(fp->fingerprint);
                count++;
                fp = fp->next;
            }
            x3_lmdb_free_fingerprint_entries(fps);
        }
        stats.fingerprint_deletions += count;
    }

    /* Revoke session tokens if requested */
    if (invalidate_sessions) {
        if (x3_lmdb_session_revoke_all(username) == LMDB_SUCCESS) {
            count++;
            stats.session_revocations++;
        }
    }

    /* Clear failed fingerprint lookup cache */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_FPFAIL, username);
    /* Note: fpfail is keyed by fingerprint, not username, so same issue */

    stats.cache_invalidations += count;
    return count;
}

#endif /* WITH_KEYCLOAK_WEBHOOK */
