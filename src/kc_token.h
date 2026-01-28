/* kc_token.h - Centralized token management for Keycloak modules
 *
 * Manages the admin/client token lifecycle: acquisition, refresh, caching,
 * async waiter queue, introspection, and availability tracking.
 *
 * The token module owns the kc_token_mgr state and the pthread mutex that
 * protects it.  Other modules (keycloak.c, nickserv.c) call the public API
 * declared here.
 *
 * IMPORTANT: This header requires struct definitions from keycloak.h
 * (access_token, kc_token_info, kc_realm, kc_client) to be visible.
 * It is included by keycloak.h after those definitions.  Do not include
 * this header directly without including keycloak.h first.
 */

#ifndef KC_TOKEN_H
#define KC_TOKEN_H

#include "config.h"

#ifdef WITH_KEYCLOAK

/* Forward declarations - full definitions are in keycloak.h */
struct access_token;
struct kc_token_info;
struct kc_realm;
struct kc_client;
struct log_type;

/**
 * Callback type for async token operations.
 * @param ctx    Opaque context pointer
 * @param result KC_SUCCESS on success, error code on failure
 * @param token  The access token (valid only on success)
 */
typedef void (*kc_token_callback)(void *ctx, int result, struct access_token *token);

/* Callback for async client token acquisition.
 * Used by kc_token_async_acquire_fn to break the circular dependency
 * between kc_token.c and kc_async.c. */
typedef int (*kc_client_token_callback)(void *session, int result, struct access_token *access_token);

/* -------------------------------------------------------------------------
 * Token statistics (merged into kc_stats by keycloak_get_stats)
 * ---------------------------------------------------------------------- */
struct kc_token_stats {
    unsigned long token_refreshes;
};

/* -------------------------------------------------------------------------
 * Async acquire callback - function pointer type for breaking the
 * circular dependency between kc_token.c and keycloak.c.
 *
 * keycloak.c sets this to keycloak_get_client_token_async() during init
 * so that keycloak_ensure_token_async() can trigger an async refresh
 * without directly calling into keycloak.c.
 * ---------------------------------------------------------------------- */
typedef int (*kc_token_async_acquire_fn)(struct kc_realm realm,
                                         struct kc_client client,
                                         void *session,
                                         kc_client_token_callback callback);

void kc_token_set_async_acquire(kc_token_async_acquire_fn fn);

/* -------------------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------------- */

/** Initialise the token subsystem.  Call once from init_keycloak(). */
void kc_token_init(struct log_type *log);

/** Shut down the token subsystem.  Call from cleanup_keycloak(). */
void kc_token_cleanup(void);

/** Get a snapshot of token-specific stats. */
void kc_token_stats_get(struct kc_token_stats *out);

/* -------------------------------------------------------------------------
 * Token manager API (re-exported - signatures unchanged from keycloak.h)
 * ---------------------------------------------------------------------- */

void  keycloak_token_manager_init(struct kc_realm realm, struct kc_client client);
void  keycloak_token_manager_shutdown(void);

int   keycloak_ensure_token(void);
int   keycloak_ensure_token_async(kc_token_callback callback, void *ctx);

struct access_token *keycloak_get_cached_token(void);
struct kc_client     keycloak_get_authed_client(void);
struct kc_realm      keycloak_get_realm(void);

void keycloak_set_available(int available);
int  keycloak_is_available(void);

/* -------------------------------------------------------------------------
 * Token acquisition (synchronous)
 * ---------------------------------------------------------------------- */

int keycloak_get_client_token(struct kc_realm realm, struct kc_client client,
                              struct access_token **access_token);
int keycloak_get_user_token(struct kc_realm realm, struct kc_client client,
                            const char *user, const char *passwd,
                            struct access_token **user_access_token);

/* -------------------------------------------------------------------------
 * Token memory management
 * ---------------------------------------------------------------------- */

void keycloak_free_access_token(struct access_token *token);

/* -------------------------------------------------------------------------
 * Token introspection
 * ---------------------------------------------------------------------- */

int  keycloak_introspect_token(struct kc_realm realm, struct kc_client client,
                               const char *bearer_token,
                               struct kc_token_info **info_out);
void keycloak_free_token_info(struct kc_token_info *info);

/* -------------------------------------------------------------------------
 * Token JSON parsing (internal, but non-static for reuse by keycloak.c
 * async completion handler)
 * ---------------------------------------------------------------------- */

int json_read_kc_access_token(const char *response,
                              struct access_token **token_out);
int json_read_token_info(const char *response,
                         struct kc_token_info **info_out);

/* -------------------------------------------------------------------------
 * Thread-safe bearer token copy (internal helper, used by keycloak.c
 * async functions to safely read kc_token_mgr.token from any thread)
 * ---------------------------------------------------------------------- */

char *kc_get_token_copy(void);

#endif /* WITH_KEYCLOAK */
#endif /* KC_TOKEN_H */
