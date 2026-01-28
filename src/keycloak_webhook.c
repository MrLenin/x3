/*
 * Keycloak Webhook Handler for X3
 * Copyright (C) 2025 AfterNET Development Team
 *
 * X3-specific business logic for Keycloak webhook events.
 * TCP/HTTP/queue infrastructure is provided by libkc's kc_webhook module.
 */

#include "keycloak_webhook.h"

#if WITH_KEYCLOAK_WEBHOOK

#include "log.h"
#include "common.h"
#include "x3_lmdb.h"
#include "nickserv.h"
#include "chanserv.h"  /* For chanserv_queue_keycloak_sync, kc_group_path_to_channel */
#include "keycloak.h"  /* For kc_user_repr_cache_put/remove */
#include "timeq.h"     /* For access queue timer */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <jansson.h>

#include <kc/kc_webhook.h>

/* Log module */
static struct log_type *webhook_log;

/* X3-specific statistics */
static struct x3_webhook_stats x3_stats = {0};

/* Access update queue - decouples webhook receipt from chanserv processing */
#define ACCESS_QUEUE_MAX 5000
#define ACCESS_QUEUE_BATCH 20
#define ACCESS_QUEUE_INTERVAL 1

struct access_update_entry {
    char channel[CHANNELLEN+1];
    char username[NICKSERV_HANDLE_LEN+1];
    unsigned short level;
    struct access_update_entry *next;
};

static struct access_update_entry *access_queue_head = NULL;
static struct access_update_entry *access_queue_tail = NULL;
static unsigned int access_queue_size = 0;
static int access_queue_scheduled = 0;

/* Forward declarations */
static void access_queue_process(void *data);
static void x3_webhook_handle_event(const struct kc_webhook_event *event, void *data);

/*
 * Queue an access update for deferred processing.
 * Deduplicates by channel+username - if already queued, updates level.
 */
static int
queue_access_update(const char *channel, const char *username, unsigned short level)
{
    struct access_update_entry *entry;

    /* Check for existing entry (deduplication) */
    for (entry = access_queue_head; entry; entry = entry->next) {
        if (strcasecmp(entry->channel, channel) == 0 &&
            strcasecmp(entry->username, username) == 0) {
            if (entry->level != level) {
                log_module(webhook_log, LOG_DEBUG,
                           "access_queue: Updating queued entry %s/%s: %u -> %u",
                           channel, username, entry->level, level);
                entry->level = level;
            }
            return 0;
        }
    }

    if (access_queue_size >= ACCESS_QUEUE_MAX) {
        log_module(webhook_log, LOG_WARNING,
                   "access_queue: Queue full (%u), dropping update for %s/%s",
                   access_queue_size, channel, username);
        x3_stats.access_updates_dropped++;
        return -1;
    }

    entry = malloc(sizeof(*entry));
    if (!entry)
        return -1;

    strncpy(entry->channel, channel, CHANNELLEN);
    entry->channel[CHANNELLEN] = '\0';
    strncpy(entry->username, username, NICKSERV_HANDLE_LEN);
    entry->username[NICKSERV_HANDLE_LEN] = '\0';
    entry->level = level;
    entry->next = NULL;

    if (access_queue_tail) {
        access_queue_tail->next = entry;
    } else {
        access_queue_head = entry;
    }
    access_queue_tail = entry;
    access_queue_size++;
    x3_stats.access_updates_queued++;

    if (!access_queue_scheduled) {
        access_queue_scheduled = 1;
        timeq_add(now + ACCESS_QUEUE_INTERVAL, access_queue_process, NULL);
    }

    log_module(webhook_log, LOG_DEBUG,
               "access_queue: Queued %s/%s level %u (queue size: %u)",
               channel, username, level, access_queue_size);
    return 0;
}

/*
 * Process queued access updates - called via timeq timer.
 */
static void
access_queue_process(UNUSED_ARG(void *data))
{
    struct access_update_entry *entry;
    int batch = 0;

    access_queue_scheduled = 0;

    while (access_queue_head && batch < ACCESS_QUEUE_BATCH) {
        entry = access_queue_head;
        access_queue_head = entry->next;
        if (!access_queue_head)
            access_queue_tail = NULL;
        access_queue_size--;

        log_module(webhook_log, LOG_DEBUG,
                   "access_queue: Processing %s/%s level %u",
                   entry->channel, entry->username, entry->level);

        chanserv_keycloak_access_update(entry->channel, entry->username, entry->level);
        x3_stats.access_updates_processed++;

        free(entry);
        batch++;
    }

    x3_stats.access_queue_depth = access_queue_size;

    if (access_queue_head && !access_queue_scheduled) {
        access_queue_scheduled = 1;
        timeq_add(now + ACCESS_QUEUE_INTERVAL, access_queue_process, NULL);
    }
}

/*
 * Handle a parsed Keycloak event from libkc.
 * This is the callback passed to kc_webhook_init().
 * All TCP/HTTP/JSON parsing is done by libkc — we just handle the business logic.
 */
static void
x3_webhook_handle_event(const struct kc_webhook_event *event, UNUSED_ARG(void *data))
{
    x3_stats.last_event_time = time(NULL);

    log_module(webhook_log, LOG_DEBUG,
               "Webhook event: resource=%s operation=%s path=%s",
               event->resource_type_str ? event->resource_type_str : "(null)",
               event->operation_type_str ? event->operation_type_str : "(null)",
               event->resource_path ? event->resource_path : "(null)");

    switch (event->resource_type) {
    case KC_WH_RESOURCE_USER:
        if (event->username) {
            if (event->operation_type == KC_WH_OP_DELETE) {
                /* User deleted - clear all caches */
                log_module(webhook_log, LOG_INFO,
                           "User deleted via Keycloak: %s", event->username);
                keycloak_invalidate_user_caches(event->username, 1, 1);

                /* Remove from user representation cache */
                if (event->user_id)
                    kc_user_repr_cache_remove(event->user_id);

            } else if (event->operation_type == KC_WH_OP_UPDATE) {
                int invalidated = 0;

                if (event->representation) {
                    /* Cache the full user representation for safe attribute updates.
                     * Only cache if not already cached to avoid overwriting with stale data. */
                    json_t *user_id_json = json_object_get(event->representation, "id");
                    if (user_id_json && json_is_string(user_id_json)) {
                        const char *uid = json_string_value(user_id_json);
                        json_t *existing = kc_user_repr_cache_get(uid);
                        if (!existing) {
                            kc_user_repr_cache_put(uid, event->representation);
                            log_module(webhook_log, LOG_DEBUG,
                                       "Cached user representation for %s (id=%s)",
                                       event->username, uid);
                        }
                    }

                    json_t *attrs = json_object_get(event->representation, "attributes");
                    if (attrs && json_is_object(attrs)) {
                        /* Check for x3_opserv_level change */
                        if (json_object_get(attrs, "x3_opserv_level")) {
                            log_module(webhook_log, LOG_INFO,
                                       "OpServ level changed for %s via Keycloak", event->username);
                            x3_stats.opserv_invalidations++;
                            x3_stats.cache_invalidations++;
                            invalidated = 1;
                        }

                        /* Check for x3_metadata changes */
                        if (json_object_get(attrs, "x3_metadata")) {
                            log_module(webhook_log, LOG_INFO,
                                       "Metadata changed for %s via Keycloak - invalidating cache",
                                       event->username);
                            int deleted = x3_lmdb_metadata_delete_by_user(event->username);
                            if (deleted > 0) {
                                log_module(webhook_log, LOG_DEBUG,
                                           "Deleted %d metadata entries for %s",
                                           deleted, event->username);
                            }
                            x3_stats.metadata_invalidations++;
                            x3_stats.cache_invalidations++;
                            invalidated = 1;
                        }

                        /* Check for x3.channel.* attribute changes (bidirectional access sync) */
                        const char *key;
                        json_t *value;
                        json_object_foreach(attrs, key, value) {
                            if (strncmp(key, "x3.channel.", 11) == 0) {
                                const char *channel = key + 11;
                                unsigned short level = 0;

                                if (json_is_array(value) && json_array_size(value) > 0) {
                                    json_t *first = json_array_get(value, 0);
                                    if (first && json_is_string(first))
                                        level = (unsigned short)atoi(json_string_value(first));
                                }

                                /* Skip no-op updates */
                                {
                                    struct chanNode *cn = GetChannel(channel);
                                    if (cn && cn->channel_info) {
                                        struct handle_info *hi = get_handle_info(event->username);
                                        if (hi) {
                                            struct userData *uData = GetChannelUser(cn->channel_info, hi);
                                            if (uData && uData->access == level) {
                                                x3_stats.access_updates_skipped++;
                                                continue;
                                            }
                                        }
                                    }
                                }

                                queue_access_update(channel, event->username, level);
                                x3_stats.cache_invalidations++;
                                invalidated = 1;
                            }
                        }
                    }
                }

                if (invalidated) {
                    log_module(webhook_log, LOG_DEBUG,
                               "User updated via Keycloak: %s (caches invalidated)", event->username);
                }
            }
        }
        break;

    case KC_WH_RESOURCE_CREDENTIAL:
        if (event->operation_type == KC_WH_OP_DELETE && event->representation) {
            /* Credential deleted - check for x509 cert */
            json_t *type = json_object_get(event->representation, "type");
            json_t *cred_data = json_object_get(event->representation, "credentialData");

            if (type && json_is_string(type) &&
                strcmp(json_string_value(type), "x509") == 0 && cred_data) {
                json_t *cd = json_loads(json_string_value(cred_data), 0, NULL);
                if (cd) {
                    json_t *fp = json_object_get(cd, "fingerprint");
                    if (fp && json_is_string(fp)) {
                        log_module(webhook_log, LOG_INFO,
                                   "Certificate revoked via Keycloak: %.32s...",
                                   json_string_value(fp));
                        x3_lmdb_fingerprint_delete(json_string_value(fp));
                        x3_stats.fingerprint_deletions++;
                        x3_stats.cache_invalidations++;
                    }
                    json_decref(cd);
                }
            }
        } else if (event->operation_type == KC_WH_OP_UPDATE ||
                   event->operation_type == KC_WH_OP_CREATE) {
            if (event->representation) {
                json_t *type = json_object_get(event->representation, "type");
                const char *cred_type = (type && json_is_string(type))
                    ? json_string_value(type) : NULL;

                if (cred_type && strcmp(cred_type, "password") == 0 && event->username) {
                    /* Password changed - invalidate all auth caches */
                    log_module(webhook_log, LOG_INFO,
                               "Password changed for %s via Keycloak - invalidating",
                               event->username);
                    invalidate_authsuccess_cache(event->username);
                    x3_lmdb_scram_revoke_all(event->username);
                    x3_lmdb_scram_acct_delete_all(event->username);
                    x3_stats.scram_invalidations++;
                    x3_stats.cache_invalidations++;

                    /* Pre-populate SCRAM cache from webhook payload (Keycloak SPI) */
                    if (event->has_scram) {
                        log_module(webhook_log, LOG_INFO,
                                   "Pre-populating SCRAM cache for %s from webhook",
                                   event->username);
                        int rc = x3_lmdb_scram_acct_set(
                            event->username,
                            event->scram.salt,
                            event->scram.iterations,
                            event->scram.stored_key,
                            event->scram.server_key,
                            now, 0);
                        if (rc == LMDB_SUCCESS) {
                            log_module(webhook_log, LOG_DEBUG,
                                       "SCRAM cache pre-populated for %s", event->username);
                        } else {
                            log_module(webhook_log, LOG_WARNING,
                                       "Failed to pre-populate SCRAM cache for %s: %d",
                                       event->username, rc);
                        }
                    }
                } else if (cred_type && strcmp(cred_type, "x509") == 0 &&
                           event->operation_type == KC_WH_OP_CREATE) {
                    /* New X.509 cert - pre-warm fingerprint cache */
                    json_t *cred_data = json_object_get(event->representation, "credentialData");
                    if (cred_data && json_is_string(cred_data)) {
                        json_t *cd = json_loads(json_string_value(cred_data), 0, NULL);
                        if (cd) {
                            json_t *fp = json_object_get(cd, "fingerprint");
                            if (fp && json_is_string(fp) && event->username) {
                                log_module(webhook_log, LOG_INFO,
                                           "Pre-warming fingerprint cache for %s: %.32s...",
                                           event->username, json_string_value(fp));
                                x3_lmdb_fingerprint_set(json_string_value(fp),
                                                        event->username, now, 0);
                                x3_stats.fingerprint_additions++;
                                x3_stats.cache_invalidations++;
                            }
                            json_decref(cd);
                        }
                    }
                }
            }
        }
        break;

    case KC_WH_RESOURCE_USER_SESSION:
    case KC_WH_RESOURCE_ADMIN_EVENT:
        if (event->operation_type == KC_WH_OP_DELETE) {
            /* Session logout - use username from event or auth details */
            const char *username = event->username;
            if (!username && event->has_auth_details)
                username = event->auth_details.username;

            if (username) {
                log_module(webhook_log, LOG_INFO,
                           "Session logout via Keycloak for: %s", username);
                x3_lmdb_session_revoke_all(username);
                x3_stats.session_revocations++;
                x3_stats.cache_invalidations++;
            }
        }
        break;

    case KC_WH_RESOURCE_GROUP_MEMBERSHIP:
        if (event->representation) {
            json_t *gpath = json_object_get(event->representation, "path");
            if (gpath && json_is_string(gpath)) {
                char *channel = kc_group_path_to_channel(json_string_value(gpath));
                if (channel) {
                    log_module(webhook_log, LOG_INFO,
                               "Group membership %s for channel %s (via webhook)",
                               event->operation_type_str, channel);
                    if (chanserv_queue_keycloak_sync(channel, KC_SYNC_PRIORITY_IMMEDIATE) == 0) {
                        x3_stats.group_syncs++;
                        x3_stats.cache_invalidations++;
                    }
                    free(channel);
                }
            }
        }
        break;

    case KC_WH_RESOURCE_GROUP:
        if (event->operation_type == KC_WH_OP_UPDATE && event->representation) {
            json_t *gpath = json_object_get(event->representation, "path");
            if (gpath && json_is_string(gpath)) {
                char *channel = kc_group_path_to_channel(json_string_value(gpath));
                if (channel) {
                    log_module(webhook_log, LOG_INFO,
                               "Group attributes changed for %s - queueing re-sync", channel);
                    if (chanserv_queue_keycloak_sync(channel, KC_SYNC_PRIORITY_HIGH) == 0)
                        x3_stats.group_syncs++;
                    free(channel);
                }
            }
        }
        break;

    default:
        log_module(webhook_log, LOG_DEBUG,
                   "Ignoring unhandled resource type: %s",
                   event->resource_type_str ? event->resource_type_str : "(null)");
        break;
    }

    x3_stats.events_processed++;
}

/*
 * Initialize webhook listener (thin wrapper around libkc)
 */
int
keycloak_webhook_init(int port, const char *secret, const char *bind_addr)
{
    struct kc_webhook_config cfg;

    webhook_log = log_register_type("Webhook", "file:webhook.log");

    if (port <= 0) {
        log_module(webhook_log, LOG_DEBUG, "Keycloak webhook disabled (port=0)");
        return 0;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.port = port;
    cfg.secret = secret;
    cfg.bind_address = bind_addr;
    /* Use libkc defaults for max_request_size, max_connections, queue_max, batch_size */

    int rc = kc_webhook_init(&cfg, x3_webhook_handle_event, &x3_stats);
    if (rc < 0) {
        log_module(webhook_log, LOG_ERROR,
                   "Failed to start Keycloak webhook on port %d", port);
        return -1;
    }

    log_module(webhook_log, LOG_INFO,
               "Keycloak webhook listening on port %d (via libkc)", port);
    return 0;
}

/*
 * Shutdown webhook listener
 */
void
keycloak_webhook_shutdown(void)
{
    struct access_update_entry *entry, *next;

    kc_webhook_shutdown();

    /* Drain the access queue */
    for (entry = access_queue_head; entry; entry = next) {
        next = entry->next;
        free(entry);
    }
    access_queue_head = access_queue_tail = NULL;
    access_queue_size = 0;
    access_queue_scheduled = 0;

    log_module(webhook_log, LOG_INFO, "Keycloak webhook shut down");
}

/*
 * Check if webhook is running
 */
int
keycloak_webhook_is_running(void)
{
    return kc_webhook_is_running();
}

/*
 * Get X3-specific statistics
 */
const struct x3_webhook_stats *
keycloak_webhook_get_x3_stats(void)
{
    return &x3_stats;
}

/*
 * Update secret at runtime
 */
void
keycloak_webhook_set_secret(const char *secret)
{
    kc_webhook_set_secret(secret);
}

/*
 * Manual cache invalidation function (OpServ command interface)
 */
int
keycloak_invalidate_user_caches(const char *username,
                                 int invalidate_fingerprints,
                                 int invalidate_sessions)
{
    int count = 0;

    if (!username || !username[0])
        return 0;

    log_module(webhook_log, LOG_DEBUG,
               "Invalidating caches for user: %s (fp=%d, sess=%d)",
               username, invalidate_fingerprints, invalidate_sessions);

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
        x3_stats.fingerprint_deletions += count;
    }

    /* Revoke session tokens if requested */
    if (invalidate_sessions) {
        if (x3_lmdb_session_revoke_all(username) == LMDB_SUCCESS) {
            count++;
            x3_stats.session_revocations++;
        }
    }

    x3_stats.cache_invalidations += count;
    return count;
}

#endif /* WITH_KEYCLOAK_WEBHOOK */
