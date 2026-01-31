/*
 * Keycloak Webhook Handler for X3
 * Copyright (C) 2025 AfterNET Development Team
 *
 * Receives real-time events from Keycloak to invalidate caches immediately
 * when credentials change, users are deleted, or fingerprints are revoked.
 *
 * Uses libkc's kc_webhook module for TCP/HTTP/queue infrastructure.
 * This file contains only X3-specific business logic (cache invalidation,
 * SCRAM pre-population, ChanServ access sync).
 */
#ifndef KEYCLOAK_WEBHOOK_H
#define KEYCLOAK_WEBHOOK_H

#include "config.h"
#include <time.h>

/* Webhook is only available when both Keycloak and LMDB are enabled */
#if defined(WITH_KEYCLOAK) && defined(WITH_MDBX)
#define WITH_KEYCLOAK_WEBHOOK 1
#else
#define WITH_KEYCLOAK_WEBHOOK 0
#endif

#if WITH_KEYCLOAK_WEBHOOK

/* X3-specific webhook statistics (libkc tracks transport-level stats separately) */
struct x3_webhook_stats {
    unsigned long events_processed;
    unsigned long cache_invalidations;
    unsigned long fingerprint_deletions;
    unsigned long fingerprint_additions;
    unsigned long session_revocations;
    unsigned long group_syncs;
    unsigned long scram_invalidations;
    unsigned long opserv_invalidations;
    unsigned long metadata_invalidations;
    unsigned long access_updates_skipped;
    unsigned long access_updates_queued;
    unsigned long access_updates_processed;
    unsigned long access_updates_dropped;
    unsigned long access_queue_depth;
    time_t last_event_time;
};

/**
 * Initialize the Keycloak webhook listener (wraps kc_webhook_init)
 * Called from nickserv_init() if webhook_enable is configured
 * @param port      Port to listen on (0 = disabled)
 * @param secret    Shared secret for X-Webhook-Secret validation (NULL = no auth)
 * @param bind_addr Bind address (NULL = all interfaces)
 * @return 0 on success, -1 on failure
 */
int keycloak_webhook_init(int port, const char *secret, const char *bind_addr);

/**
 * Shutdown the webhook listener
 * Called during X3 shutdown
 */
void keycloak_webhook_shutdown(void);

/**
 * Check if webhook listener is running
 * @return 1 if running, 0 otherwise
 */
int keycloak_webhook_is_running(void);

/**
 * Get X3-specific webhook statistics
 * @return Pointer to static stats structure
 */
const struct x3_webhook_stats *keycloak_webhook_get_x3_stats(void);

/**
 * Update the webhook secret at runtime (e.g. on rehash)
 * @param secret New shared secret (NULL = disable auth)
 */
void keycloak_webhook_set_secret(const char *secret);

/**
 * Manual cache invalidation (can be called from OpServ commands)
 * @param username Account name to invalidate caches for
 * @param invalidate_fingerprints Also clear fingerprint caches
 * @param invalidate_sessions Also revoke session tokens
 * @return Number of cache entries invalidated
 */
int keycloak_invalidate_user_caches(const char *username,
                                     int invalidate_fingerprints,
                                     int invalidate_sessions);

#else /* !WITH_KEYCLOAK_WEBHOOK */

/* Stub macros when webhook is not available */
#define keycloak_webhook_init(p, s, b)    (0)
#define keycloak_webhook_shutdown()       do {} while(0)
#define keycloak_webhook_is_running()     (0)
#define keycloak_webhook_get_x3_stats()   ((const struct x3_webhook_stats *)NULL)
#define keycloak_webhook_set_secret(s)    do {} while(0)
#define keycloak_invalidate_user_caches(u, f, s) (0)

#endif /* WITH_KEYCLOAK_WEBHOOK */

#endif /* KEYCLOAK_WEBHOOK_H */
