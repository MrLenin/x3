/*
 * Keycloak Webhook Handler for X3
 * Copyright (C) 2025 AfterNET Development Team
 *
 * Receives real-time events from Keycloak to invalidate caches immediately
 * when credentials change, users are deleted, or fingerprints are revoked.
 *
 * Keycloak Configuration:
 *   1. Go to Realm Settings -> Events -> Admin Events Settings
 *   2. Enable "Include Representation" for UPDATE operations
 *   3. Add an Event Listener SPI or use a custom webhook provider
 *   4. Point webhook URL to: http://x3-host:WEBHOOK_PORT/keycloak-webhook
 */
#ifndef KEYCLOAK_WEBHOOK_H
#define KEYCLOAK_WEBHOOK_H

#include "config.h"
#include <time.h>

/* Webhook is only available when both Keycloak and LMDB are enabled */
#if defined(WITH_KEYCLOAK) && defined(WITH_LMDB)
#define WITH_KEYCLOAK_WEBHOOK 1
#else
#define WITH_KEYCLOAK_WEBHOOK 0
#endif

#if WITH_KEYCLOAK_WEBHOOK

/* Default webhook port (0 = disabled) */
#define KC_WEBHOOK_PORT_DEFAULT 0

/* Maximum HTTP request size (64KB should be plenty for Keycloak events) */
#define KC_WEBHOOK_MAX_REQUEST 65536

/* Webhook event types we handle */
typedef enum {
    KC_EVENT_UNKNOWN = 0,
    KC_EVENT_DELETE_CREDENTIAL,    /* Fingerprint/cert removed */
    KC_EVENT_UPDATE_PASSWORD,      /* Password changed */
    KC_EVENT_LOGOUT_ALL_SESSIONS,  /* User logged out all sessions */
    KC_EVENT_DELETE_USER,          /* User account deleted */
    KC_EVENT_UPDATE_USER,          /* User details updated */
    KC_EVENT_REVOKE_GRANT          /* OAuth grant revoked */
} kc_webhook_event_type;

/* Webhook statistics */
struct kc_webhook_stats {
    unsigned long events_received;
    unsigned long events_processed;
    unsigned long events_invalid;
    unsigned long cache_invalidations;
    unsigned long fingerprint_deletions;
    unsigned long session_revocations;
    time_t last_event_time;
};

/**
 * Initialize the Keycloak webhook listener
 * Called from nickserv_init() if webhook_enable is configured
 * @return 0 on success, -1 on failure
 */
int keycloak_webhook_init(void);

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
 * Get webhook statistics
 * @return Pointer to static stats structure
 */
const struct kc_webhook_stats *keycloak_webhook_get_stats(void);

/**
 * Configuration accessors
 */
int keycloak_webhook_get_port(void);
const char *keycloak_webhook_get_secret(void);
void keycloak_webhook_set_port(int port);
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
#define keycloak_webhook_init()           (0)
#define keycloak_webhook_shutdown()       do {} while(0)
#define keycloak_webhook_is_running()     (0)
#define keycloak_webhook_get_stats()      ((const struct kc_webhook_stats *)NULL)
#define keycloak_webhook_get_port()       (0)
#define keycloak_webhook_get_secret()     ("")
#define keycloak_webhook_set_port(p)      do {} while(0)
#define keycloak_webhook_set_secret(s)    do {} while(0)
#define keycloak_invalidate_user_caches(u, f, s) (0)

#endif /* WITH_KEYCLOAK_WEBHOOK */

#endif /* KEYCLOAK_WEBHOOK_H */
