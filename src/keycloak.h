#ifndef KEYCLOAK_H
#define KEYCLOAK_H

#include "config.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef WITH_KEYCLOAK

#include <curl/curl.h>
#include <jansson.h>

/*
 * =============================================================================
 * Error Codes
 * =============================================================================
 */
enum kc_error {
    KC_SUCCESS = 0,
    KC_ERROR = -1,           /* Generic/unknown error */
    KC_USER_EXISTS = -2,     /* User already exists */
    KC_FORBIDDEN = -3,       /* Invalid credentials / access denied */
    KC_NOT_FOUND = -4,       /* User not found */
    KC_COLLISION = -5,       /* Multiple users matched (e.g., fingerprint collision) */
    KC_TIMEOUT = -6,         /* Connection timeout */
    KC_UNAVAILABLE = -7,     /* Server unavailable */
    KC_TOKEN_ERROR = -8,     /* Token refresh/acquisition failed */
    KC_INVALID_RESPONSE = -9 /* Server returned unexpected response */
};

/*
 * =============================================================================
 * Core Data Structures
 * =============================================================================
 */

struct access_token {
    char* access_token;
    size_t access_token_size;
    long expires_in;
    long refresh_expires_in;
    char* refresh_token;
    size_t refresh_token_size;
    char* token_type;
    size_t token_type_size;
    long not_before_policy;
    char* session_state;
    size_t session_state_size;
    char* scope;
    size_t scope_size;
};

struct kc_user {
    char* id;
    size_t id_size;
    char* username;
    size_t username_size;
    char* email;
    size_t email_size;
    bool emailVerified;
    struct access_token* access_token;
    int opserv_level;           /* Custom attribute: x3_opserv_level */
};

struct kc_token_info {
    bool active;
    char* username;
    size_t username_size;
    char* email;
    size_t email_size;
    char* sub;                  /* Subject (user ID) */
    size_t sub_size;
    int opserv_level;           /* From token claims or user attributes */
    long exp;                   /* Expiration timestamp */
    long iat;                   /* Issued at timestamp */
};

/* struct kc_realm now lives in libkc's kc_realm.h.
 * Compat shim: X3 code uses .base_uri, libkc uses .base_url.
 * This #define allows existing X3 code to keep using base_uri
 * until the mechanical rename in Phase 9D. */
#include "kc/kc_realm.h"
#define base_uri base_url

struct kc_client {
    const char* client_id;
    const char* client_secret;
    struct access_token* access_token;
};

/* Update parameters for keycloak_update_user_representation().
 * Set fields to NULL to skip updating them. */
struct kc_user_update {
    const char* username;       /* Username - REQUIRED for credential updates (Keycloak bug workaround) */
    const char* email;          /* New email address (NULL to skip) */
    const char* cred_data;      /* credentialData JSON from pw_export_keycloak() (NULL to skip) */
    const char* secret_data;    /* secretData JSON - required if cred_data is set */
};

/* Metadata key-value pair for listing attributes */
struct kc_metadata_entry {
    char* key;
    char* value;
    struct kc_metadata_entry* next;
};

/* Group member entry */
struct kc_group_member {
    char* username;
    char* user_id;
    unsigned short access_level;   /* Access level from group attribute (0 if not set) */
    struct kc_group_member* next;
};

/* Group information including attributes */
struct kc_group_info {
    char* id;
    char* name;
    char* path;
    unsigned short access_level;   /* Parsed from x3_access_level attribute */
    struct kc_metadata_entry* attributes;
};

/*
 * =============================================================================
 * Performance Statistics (for STATS KEYCLOAK)
 * =============================================================================
 */

struct kc_stats {
    unsigned long http_requests;      /* Total HTTP requests made */
    unsigned long http_errors;        /* Requests that failed (curl error or HTTP 5xx) */
    unsigned long total_latency_ms;   /* Sum of all request latencies */
    unsigned long max_latency_ms;     /* Maximum single request latency */
    unsigned long min_latency_ms;     /* Minimum single request latency (0 if none) */
    unsigned long jwks_cache_hits;    /* JWT validated locally (no HTTP) */
    unsigned long jwks_cache_misses;  /* JWT required JWKS fetch */
    unsigned long user_cache_hits;    /* User ID found in cache */
    unsigned long user_cache_misses;  /* User ID required HTTP lookup */
    unsigned long token_refreshes;    /* Admin token refreshes */
    time_t last_request_time;         /* Timestamp of last HTTP request */
};

/*
 * =============================================================================
 * Facade API — Lifecycle and Utilities
 * =============================================================================
 */

void init_keycloak(void);
void cleanup_keycloak(void);

void keycloak_user_free_fields(struct kc_user* user);
void keycloak_user_free(struct kc_user* user);

void keycloak_invalidate_user_cache(const char *username);

void keycloak_get_stats(struct kc_stats *stats_out);
void keycloak_reset_stats(void);

/*
 * =============================================================================
 * Submodule Headers
 * =============================================================================
 * Include submodule headers so callers can use keycloak.h as a single include.
 * These must come after struct definitions since submodules reference them.
 */

#include "kc/kc_cache.h"
#include "kc/kc_jwt.h"
#include "kc/kc_url.h"
#include "kc_token.h"
#include "kc_sync.h"
#include "kc_async.h"

/* Compat wrappers: old X3 names → new libkc names.
 * Remove these when all X3 callers are updated. */
#define keycloak_validate_jwt_local kc_jwt_validate_local
#define kc_build_users_endpoint(r)                    kc_url_users(r)
#define kc_build_user_endpoint(r, id)                 kc_url_user(r, id)
#define kc_build_user_by_username_endpoint(r, u, e)   kc_url_user_by_username(r, u, e)
#define kc_build_user_group_endpoint(r, uid, gid)     kc_url_user_group(r, uid, gid)
#define kc_build_groups_endpoint(r)                   kc_url_groups(r)
#define kc_build_group_endpoint(r, id)                kc_url_group(r, id)
#define kc_build_group_members_endpoint(r, id)        kc_url_group_members(r, id)
#define kc_build_group_children_endpoint(r, id)       kc_url_group_children(r, id)
#define kc_build_group_by_path_endpoint(r, p)         kc_url_group_by_path(r, p)
#define kc_build_fingerprint_search_endpoint(r, fp)   kc_url_fingerprint_search(r, fp)
#define kc_build_group_search_endpoint(r, n)          kc_url_group_search(r, n)
#define kc_build_token_endpoint(r)                    kc_url_token(r)
#define kc_build_introspect_endpoint(r)               kc_url_introspect(r)

#endif /* WITH_KEYCLOAK */

#endif /* KEYCLOAK_H */
