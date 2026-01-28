/* kc_token.c - Centralized Keycloak token management
 *
 * Extracted from keycloak.c.  Owns:
 *   - kc_token_mgr state (realm, client, cached token, expiry, availability)
 *   - kc_token_lock mutex protecting the cached token
 *   - Token waiter queue for async refresh
 *   - Synchronous token acquisition (client credentials & user password grant)
 *   - Token introspection (sync)
 *   - Token JSON parsing
 *   - Endpoint URL builders for token & introspect
 *   - Token memory helpers
 */

#include "config.h"

#ifdef WITH_KEYCLOAK

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include "keycloak.h"       /* struct definitions + includes kc_token.h */
#include "kc_http_internal.h"
#include "common.h"
#include "log.h"

/* Module-local logger */
static struct log_type *token_log;

/* -------------------------------------------------------------------------
 * Token statistics
 * ---------------------------------------------------------------------- */
static struct kc_token_stats token_stats = {0};

void
kc_token_stats_get(struct kc_token_stats *out)
{
    if (out)
        *out = token_stats;
}

/* -------------------------------------------------------------------------
 * Token Manager State
 *
 * Thread-safety: The token pointer can be read by worker threads (for HTTP
 * auth header).  kc_token_lock protects reads/writes to the token field.
 * ---------------------------------------------------------------------- */
#ifdef HAVE_PTHREAD_H
static pthread_mutex_t kc_token_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

static struct {
    int initialized;                       /* 1 if initialized */
    struct kc_realm realm;                 /* Cached realm config */
    struct kc_client client;               /* Cached client config */
    struct access_token *token;            /* Cached admin token */
    time_t token_expires;                  /* When token expires */
    int refresh_pending;                   /* 1 if refresh in progress */
    int available;                         /* Keycloak availability flag */
} kc_token_mgr = {0};

/* -------------------------------------------------------------------------
 * Thread-safe bearer token copy
 * ---------------------------------------------------------------------- */
char *
kc_get_token_copy(void)
{
    char *token_copy = NULL;

#ifdef HAVE_PTHREAD_H
    pthread_mutex_lock(&kc_token_lock);
#endif

    if (kc_token_mgr.token && kc_token_mgr.token->access_token) {
        token_copy = strdup(kc_token_mgr.token->access_token);
    }

#ifdef HAVE_PTHREAD_H
    pthread_mutex_unlock(&kc_token_lock);
#endif

    return token_copy;
}

/* -------------------------------------------------------------------------
 * Async acquire function pointer (set by keycloak.c to break circular dep)
 * ---------------------------------------------------------------------- */
static kc_token_async_acquire_fn async_acquire_fn = NULL;

void
kc_token_set_async_acquire(kc_token_async_acquire_fn fn)
{
    async_acquire_fn = fn;
}

/* -------------------------------------------------------------------------
 * Token Waiter Queue
 * ---------------------------------------------------------------------- */

struct kc_token_waiter {
    kc_token_callback callback;
    void *context;
    struct kc_token_waiter *next;
};
static struct kc_token_waiter *kc_token_waiters = NULL;
static unsigned int kc_token_waiter_count = 0;

/* Backpressure: max waiters queued during token refresh */
#define KC_TOKEN_WAITER_LIMIT 100

/* Forward declaration */
static int kc_token_refresh_cb(void *session, int result, struct access_token *token);

/* Notify all waiters that token refresh completed */
static void
kc_notify_waiters(int result, struct access_token *token)
{
    struct kc_token_waiter *waiter, *next;

    kc_token_mgr.refresh_pending = 0;

    waiter = kc_token_waiters;
    kc_token_waiters = NULL;
    kc_token_waiter_count = 0;

    while (waiter) {
        next = waiter->next;
        if (waiter->callback) {
            waiter->callback(waiter->context, result, token);
        }
        free(waiter);
        waiter = next;
    }
}

/* -------------------------------------------------------------------------
 * Token JSON Parsing
 * ---------------------------------------------------------------------- */

int
json_read_kc_access_token(const char *response, struct access_token **token_out)
{
    if (!response || !token_out) {
        log_module(token_log, LOG_DEBUG, "json_read_kc_access_token: Invalid arguments");
        return KC_ERROR;
    }

    *token_out = NULL;

    json_t *root = NULL;
    json_error_t error;

    root = json_loads(response, 0, &error);

    if (!root) {
        log_module(token_log, LOG_DEBUG, "json_read_kc_access_token: Failed to parse JSON: %s", error.text);
        return KC_ERROR;
    }

    int result = KC_ERROR;

    if (!json_is_object(root)) {
        log_module(token_log, LOG_DEBUG, "json_read_kc_access_token: Response is not an object");
        goto cleanup;
    }

    /* Allocate the token struct */
    struct access_token *token = malloc(sizeof(struct access_token));
    if (!token) {
        log_module(token_log, LOG_DEBUG, "json_read_kc_access_token: Failed to allocate token struct");
        goto cleanup;
    }
    memset(token, 0, sizeof(*token));

    /* Required field: access_token */
    if (json_read_object_string(root, "access_token", &token->access_token, &token->access_token_size) != KC_SUCCESS) {
        free(token);
        goto cleanup;
    }

    /* Optional string fields - read but don't fail if missing */
    json_read_object_string(root, "refresh_token", &token->refresh_token, &token->refresh_token_size);
    json_read_object_string(root, "token_type", &token->token_type, &token->token_type_size);
    json_read_object_string(root, "session_state", &token->session_state, &token->session_state_size);
    json_read_object_string(root, "scope", &token->scope, &token->scope_size);

    /* Optional integer fields */
    json_t *expires_in = json_object_get(root, "expires_in");
    if (expires_in && json_is_integer(expires_in)) {
        token->expires_in = json_integer_value(expires_in);
    }

    json_t *not_before_policy = json_object_get(root, "not-before-policy");
    if (not_before_policy && json_is_integer(not_before_policy)) {
        token->not_before_policy = json_integer_value(not_before_policy);
    }

    json_t *refresh_expires_in = json_object_get(root, "refresh_expires_in");
    if (refresh_expires_in && json_is_integer(refresh_expires_in)) {
        token->refresh_expires_in = json_integer_value(refresh_expires_in);
    }

    *token_out = token;
    result = KC_SUCCESS;

cleanup:
    if (root) {
        json_decref(root);
    }
    return result;
}

int
json_read_token_info(const char *response, struct kc_token_info **info_out)
{
    if (!response || !info_out) {
        log_module(token_log, LOG_DEBUG, "json_read_token_info: Invalid arguments");
        return KC_ERROR;
    }

    *info_out = NULL;
    json_error_t error;
    json_t *root = json_loads(response, 0, &error);
    if (!root) {
        log_module(token_log, LOG_DEBUG, "json_read_token_info: Failed to parse JSON: %s", error.text);
        return KC_ERROR;
    }

    int result = KC_ERROR;

    if (!json_is_object(root)) {
        log_module(token_log, LOG_DEBUG, "json_read_token_info: Response is not an object");
        goto cleanup;
    }

    struct kc_token_info *info = malloc(sizeof(struct kc_token_info));
    if (!info) {
        log_module(token_log, LOG_DEBUG, "json_read_token_info: Failed to allocate token info");
        goto cleanup;
    }
    memset(info, 0, sizeof(*info));

    /* Check if token is active */
    json_t *active = json_object_get(root, "active");
    info->active = active && json_is_boolean(active) && json_boolean_value(active);

    if (!info->active) {
        log_module(token_log, LOG_DEBUG, "json_read_token_info: Token is not active");
        *info_out = info;
        result = KC_FORBIDDEN;
        goto cleanup;
    }

    /* Extract optional fields */
    json_read_object_string(root, "username", &info->username, &info->username_size);
    json_read_object_string(root, "email", &info->email, &info->email_size);
    json_read_object_string(root, "sub", &info->sub, &info->sub_size);

    /* Extract timestamps */
    json_t *exp = json_object_get(root, "exp");
    if (exp && json_is_integer(exp)) {
        info->exp = json_integer_value(exp);
    }

    json_t *iat = json_object_get(root, "iat");
    if (iat && json_is_integer(iat)) {
        info->iat = json_integer_value(iat);
    }

    /* Try to extract opserv_level from token claims (custom claim) */
    json_t *oslevel = json_object_get(root, "x3_opserv_level");
    if (oslevel && json_is_integer(oslevel)) {
        info->opserv_level = (int)json_integer_value(oslevel);
    } else if (oslevel && json_is_string(oslevel)) {
        info->opserv_level = atoi(json_string_value(oslevel));
    }

    *info_out = info;
    result = KC_SUCCESS;

cleanup:
    json_decref(root);
    return result;
}

/* -------------------------------------------------------------------------
 * Token Memory Management
 * ---------------------------------------------------------------------- */

void
keycloak_free_access_token(struct access_token *token)
{
    if (!token) {
        return;
    }

    if (token->access_token) {
        memset(token->access_token, 0, token->access_token_size);
        free(token->access_token);
    }
    if (token->refresh_token) {
        memset(token->refresh_token, 0, token->refresh_token_size);
        free(token->refresh_token);
    }
    if (token->token_type) {
        free(token->token_type);
    }
    if (token->session_state) {
        free(token->session_state);
    }
    if (token->scope) {
        free(token->scope);
    }

    free(token);
}

void
keycloak_free_token_info(struct kc_token_info *info)
{
    if (!info) {
        return;
    }

    if (info->username) {
        free(info->username);
    }
    if (info->email) {
        free(info->email);
    }
    if (info->sub) {
        free(info->sub);
    }

    free(info);
}

/* -------------------------------------------------------------------------
 * Synchronous Token Acquisition
 * ---------------------------------------------------------------------- */

/* Still needed: called by keycloak_ensure_token() */
int
keycloak_get_client_token(struct kc_realm realm, struct kc_client client,
                          struct access_token **access_token)
{
    /* Input validation */
    if (!realm.base_uri || !realm.realm || !client.client_id || !client.client_secret || !access_token) {
        log_module(token_log, LOG_DEBUG, "keycloak_get_client_token: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    struct memory chunk = {0};
    static const char query_params[] = "grant_type=client_credentials";

    /* Build URI using endpoint builder */
    char *uri = kc_build_token_endpoint(realm);
    if (!uri) {
        log_module(token_log, LOG_DEBUG, "keycloak_get_client_token: Failed to build uri");
        return KC_ERROR;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.post_fields = query_params;
    opts.auth_user = client.client_id;
    opts.auth_passwd = client.client_secret;
    opts.method = HTTP_POST;
    opts.max_retries = 1;

    long http_code = curl_perform(opts, &chunk);

    if (http_code != 200 || !chunk.response) {
        log_module(token_log, LOG_DEBUG, "keycloak_get_client_token: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
        goto cleanup;
    } else {
        log_module(token_log, LOG_DEBUG, "keycloak_get_client_token: Token retrieved successfully (HTTP 200)");
        result = json_read_kc_access_token(chunk.response, access_token);
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }

    if (uri) {
        free(uri);
    }

    return result;
}

int
keycloak_get_user_token(struct kc_realm realm, struct kc_client client,
                        const char *user, const char *passwd,
                        struct access_token **user_access_token)
{
    /* Input validation */
    if (!realm.base_uri || !realm.realm || !user || !passwd || !user_access_token) {
        log_module(token_log, LOG_DEBUG, "keycloak_get_user_token: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = NULL;
    char *user_enc = NULL;
    char *passwd_enc = NULL;
    char *query_params = NULL;
    struct memory chunk = {0};

    /* URL-encode credentials */
    user_enc = curl_easy_escape(NULL, user, 0);
    if (!user_enc) {
        log_module(token_log, LOG_DEBUG, "keycloak_get_user_token: Failed to escape user");
        goto cleanup;
    }

    passwd_enc = curl_easy_escape(NULL, passwd, 0);
    if (!passwd_enc) {
        log_module(token_log, LOG_DEBUG, "keycloak_get_user_token: Failed to escape passwd");
        goto cleanup;
    }

    static const char query_params_tmpl[] = "grant_type=password&username=%s&password=%s";

    /* Build URI using endpoint builder */
    uri = kc_build_token_endpoint(realm);
    if (!uri) {
        log_module(token_log, LOG_DEBUG, "keycloak_get_user_token: Failed to build uri");
        goto cleanup;
    }

    /* Build query parameters safely */
    int query_params_len = snprintf(NULL, 0, query_params_tmpl, user_enc, passwd_enc) + 1;
    query_params = malloc(query_params_len);
    if (!query_params) {
        log_module(token_log, LOG_DEBUG, "keycloak_get_user_token: Failed to build query_params");
        goto cleanup;
    }
    snprintf(query_params, query_params_len, query_params_tmpl, user_enc, passwd_enc);

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.post_fields = query_params;
    opts.auth_user = client.client_id;
    opts.auth_passwd = client.client_secret;
    opts.method = HTTP_POST;
    opts.max_retries = 1;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 200 && chunk.response) {
        log_module(token_log, LOG_DEBUG, "keycloak_get_user_token: Token retrieved successfully (HTTP 200)");
        result = json_read_kc_access_token(chunk.response, user_access_token);
    } else if (http_code == 401) {
        /* 401 Unauthorized = invalid credentials */
        log_module(token_log, LOG_DEBUG, "keycloak_get_user_token: Invalid credentials (HTTP 401)");
        result = KC_FORBIDDEN;
    } else {
        log_module(token_log, LOG_DEBUG, "keycloak_get_user_token: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
        /* result stays KC_ERROR */
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (passwd_enc) {
        memset(passwd_enc, 0, strlen(passwd_enc));
        curl_free(passwd_enc);
    }
    if (query_params) {
        memset(query_params, 0, strlen(query_params));
        free(query_params);
    }
    if (user_enc) {
        curl_free(user_enc);
    }
    if (uri) {
        free(uri);
    }

    return result;
}

/* -------------------------------------------------------------------------
 * Token Introspection (synchronous)
 * ---------------------------------------------------------------------- */

int
keycloak_introspect_token(struct kc_realm realm, struct kc_client client,
                          const char *bearer_token,
                          struct kc_token_info **info_out)
{
    if (!realm.base_uri || !realm.realm || !client.client_id ||
        !client.client_secret || !bearer_token || !info_out) {
        log_module(token_log, LOG_DEBUG, "keycloak_introspect_token: Invalid arguments");
        return KC_ERROR;
    }

    *info_out = NULL;
    int result = KC_ERROR;
    char *uri = NULL;
    char *post_fields = NULL;
    char *escaped_token = NULL;
    struct memory chunk = {0};

    /* Build URI using endpoint builder */
    uri = kc_build_introspect_endpoint(realm);
    if (!uri) {
        log_module(token_log, LOG_DEBUG, "keycloak_introspect_token: Failed to allocate uri");
        goto cleanup;
    }

    /* URL-encode token */
    escaped_token = curl_easy_escape(NULL, bearer_token, 0);
    if (!escaped_token) {
        log_module(token_log, LOG_DEBUG, "keycloak_introspect_token: Failed to escape token");
        goto cleanup;
    }

    /* Build POST body */
    static const char post_tmpl[] = "token=%s&token_type_hint=access_token";
    int post_len = snprintf(NULL, 0, post_tmpl, escaped_token) + 1;
    post_fields = malloc(post_len);
    if (!post_fields) {
        log_module(token_log, LOG_DEBUG, "keycloak_introspect_token: Failed to allocate post_fields");
        goto cleanup;
    }
    snprintf(post_fields, post_len, post_tmpl, escaped_token);

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_POST;
    opts.post_fields = post_fields;
    opts.auth_user = client.client_id;
    opts.auth_passwd = client.client_secret;
    opts.max_retries = 1;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 200 && chunk.response) {
        result = json_read_token_info(chunk.response, info_out);
        if (result == KC_SUCCESS) {
            log_module(token_log, LOG_DEBUG, "keycloak_introspect_token: Token is valid, user: %s",
                (*info_out)->username ? (*info_out)->username : "unknown");
        } else if (result == KC_FORBIDDEN) {
            log_module(token_log, LOG_DEBUG, "keycloak_introspect_token: Token is inactive/invalid");
        }
    } else {
        log_module(token_log, LOG_DEBUG, "keycloak_introspect_token: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (post_fields) {
        memset(post_fields, 0, strlen(post_fields));
        free(post_fields);
    }
    if (escaped_token) {
        curl_free(escaped_token);
    }
    if (uri) {
        free(uri);
    }

    return result;
}

/* -------------------------------------------------------------------------
 * Token Manager Lifecycle
 * ---------------------------------------------------------------------- */

void
keycloak_token_manager_init(struct kc_realm realm, struct kc_client client)
{
    if (kc_token_mgr.initialized) {
        keycloak_token_manager_shutdown();
    }

    memset(&kc_token_mgr, 0, sizeof(kc_token_mgr));

    /* Copy realm config - note: strings are borrowed, not owned */
    kc_token_mgr.realm.base_uri = realm.base_uri;
    kc_token_mgr.realm.realm = realm.realm;

    /* Copy client config - note: strings are borrowed, not owned */
    kc_token_mgr.client.client_id = client.client_id;
    kc_token_mgr.client.client_secret = client.client_secret;
    kc_token_mgr.client.access_token = NULL;

    kc_token_mgr.available = 1;
    kc_token_mgr.initialized = 1;

    log_module(token_log, LOG_DEBUG, "Token manager initialized for realm %s", realm.realm);
}

void
keycloak_token_manager_shutdown(void)
{
    struct kc_token_waiter *waiter, *next;

    if (!kc_token_mgr.initialized)
        return;

    /* Free cached token (with lock for worker thread safety) */
#ifdef HAVE_PTHREAD_H
    pthread_mutex_lock(&kc_token_lock);
#endif
    if (kc_token_mgr.token) {
        keycloak_free_access_token(kc_token_mgr.token);
        kc_token_mgr.token = NULL;
    }
#ifdef HAVE_PTHREAD_H
    pthread_mutex_unlock(&kc_token_lock);
#endif

    /* Free pending waiters */
    for (waiter = kc_token_waiters; waiter; waiter = next) {
        next = waiter->next;
        /* Notify with error */
        if (waiter->callback) {
            waiter->callback(waiter->context, KC_ERROR, NULL);
        }
        free(waiter);
    }
    kc_token_waiters = NULL;
    kc_token_waiter_count = 0;

    kc_token_mgr.initialized = 0;
    log_module(token_log, LOG_DEBUG, "Token manager shutdown");
}

/* -------------------------------------------------------------------------
 * Token Ensure (sync & async)
 * ---------------------------------------------------------------------- */

int
keycloak_ensure_token(void)
{
    time_t now_time = time(NULL);

    if (!kc_token_mgr.initialized) {
        log_module(token_log, LOG_ERROR, "keycloak_ensure_token: Token manager not initialized");
        return KC_ERROR;
    }

    /* Check if token is still valid (with 60s margin) */
    if (kc_token_mgr.token && kc_token_mgr.token_expires > (now_time + 60)) {
        kc_token_mgr.client.access_token = kc_token_mgr.token;
        return KC_SUCCESS;
    }

    /* Free old token if exists (with lock for worker thread safety) */
#ifdef HAVE_PTHREAD_H
    pthread_mutex_lock(&kc_token_lock);
#endif
    if (kc_token_mgr.token) {
        keycloak_free_access_token(kc_token_mgr.token);
        kc_token_mgr.token = NULL;
        kc_token_mgr.client.access_token = NULL;
    }
#ifdef HAVE_PTHREAD_H
    pthread_mutex_unlock(&kc_token_lock);
#endif

    /* Get new token synchronously */
    struct access_token *new_token = NULL;
    int rc = keycloak_get_client_token(kc_token_mgr.realm, kc_token_mgr.client,
                                        &new_token);
    if (rc != KC_SUCCESS) {
        kc_token_mgr.available = 0;
        return rc;
    }

    /* Update with lock */
#ifdef HAVE_PTHREAD_H
    pthread_mutex_lock(&kc_token_lock);
#endif
    kc_token_mgr.token = new_token;
    kc_token_mgr.available = 1;
    kc_token_mgr.client.access_token = kc_token_mgr.token;
    kc_token_mgr.token_expires = now_time + kc_token_mgr.token->expires_in;
#ifdef HAVE_PTHREAD_H
    pthread_mutex_unlock(&kc_token_lock);
#endif
    return KC_SUCCESS;
}

/* Callback from async token refresh */
static int
kc_token_refresh_cb(void *session, int result, struct access_token *token)
{
    (void)session;

    if (result == KC_SUCCESS && token) {
        /* Update cached token (with lock for worker thread safety) */
#ifdef HAVE_PTHREAD_H
        pthread_mutex_lock(&kc_token_lock);
#endif
        if (kc_token_mgr.token) {
            keycloak_free_access_token(kc_token_mgr.token);
        }
        kc_token_mgr.token = token;
        kc_token_mgr.client.access_token = token;
        kc_token_mgr.token_expires = time(NULL) + token->expires_in;
        kc_token_mgr.available = 1;
#ifdef HAVE_PTHREAD_H
        pthread_mutex_unlock(&kc_token_lock);
#endif
        token_stats.token_refreshes++;  /* Track successful token refreshes */
        log_module(token_log, LOG_DEBUG, "Async token refresh successful (expires in %ld sec)",
                   token->expires_in);
    } else {
        kc_token_mgr.available = 0;
        log_module(token_log, LOG_WARNING, "Async token refresh failed: %d", result);
    }

    /* Notify all waiters */
    kc_notify_waiters(result, result == KC_SUCCESS ? kc_token_mgr.token : NULL);
    return 0;
}

int
keycloak_ensure_token_async(kc_token_callback callback, void *ctx)
{
    time_t now_time = time(NULL);
    struct kc_token_waiter *waiter;

    if (!kc_token_mgr.initialized) {
        log_module(token_log, LOG_ERROR, "keycloak_ensure_token_async: Token manager not initialized");
        return -1;
    }

    if (!callback) {
        log_module(token_log, LOG_ERROR, "keycloak_ensure_token_async: No callback");
        return -1;
    }

    /* Check if token is still valid (with 60s margin) */
    if (kc_token_mgr.token && kc_token_mgr.token_expires > (now_time + 60)) {
        kc_token_mgr.client.access_token = kc_token_mgr.token;
        /* Token valid - invoke callback immediately */
        callback(ctx, KC_SUCCESS, kc_token_mgr.token);
        return 1;
    }

    /* Backpressure: reject if waiter queue is full */
    if (kc_token_waiter_count >= KC_TOKEN_WAITER_LIMIT) {
        log_module(token_log, LOG_WARNING, "keycloak_ensure_token_async: Waiter queue full (%u/%u)",
                   kc_token_waiter_count, KC_TOKEN_WAITER_LIMIT);
        return -1;
    }

    /* Token needs refresh - add to waiter queue */
    waiter = calloc(1, sizeof(*waiter));
    if (!waiter) {
        log_module(token_log, LOG_ERROR, "keycloak_ensure_token_async: Out of memory");
        return -1;
    }
    waiter->callback = callback;
    waiter->context = ctx;
    waiter->next = kc_token_waiters;
    kc_token_waiters = waiter;
    kc_token_waiter_count++;

    /* If refresh not already in progress, start it */
    if (!kc_token_mgr.refresh_pending) {
        kc_token_mgr.refresh_pending = 1;

        /* Free old token before refresh (with lock for worker thread safety) */
#ifdef HAVE_PTHREAD_H
        pthread_mutex_lock(&kc_token_lock);
#endif
        if (kc_token_mgr.token) {
            keycloak_free_access_token(kc_token_mgr.token);
            kc_token_mgr.token = NULL;
            kc_token_mgr.client.access_token = NULL;
        }
#ifdef HAVE_PTHREAD_H
        pthread_mutex_unlock(&kc_token_lock);
#endif

        if (!async_acquire_fn) {
            log_module(token_log, LOG_ERROR, "keycloak_ensure_token_async: No async acquire function set");
            kc_token_waiters = waiter->next;
            kc_token_waiter_count--;
            free(waiter);
            kc_token_mgr.refresh_pending = 0;
            return -1;
        }

        /* Use function pointer to call keycloak_get_client_token_async
         * without a direct dependency on keycloak.c */
        if (async_acquire_fn(kc_token_mgr.realm, kc_token_mgr.client,
                              NULL, kc_token_refresh_cb) < 0) {
            log_module(token_log, LOG_ERROR, "keycloak_ensure_token_async: Failed to start refresh");
            /* Remove the waiter we just added and fail */
            kc_token_waiters = waiter->next;
            kc_token_waiter_count--;
            free(waiter);
            kc_token_mgr.refresh_pending = 0;
            return -1;
        }

        log_module(token_log, LOG_DEBUG, "keycloak_ensure_token_async: Started async refresh");
    } else {
        log_module(token_log, LOG_DEBUG, "keycloak_ensure_token_async: Refresh pending, queued waiter");
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Token Accessors
 * ---------------------------------------------------------------------- */

struct access_token *
keycloak_get_cached_token(void)
{
    return kc_token_mgr.token;
}

struct kc_client
keycloak_get_authed_client(void)
{
    struct kc_client client = kc_token_mgr.client;
    client.access_token = kc_token_mgr.token;
    return client;
}

struct kc_realm
keycloak_get_realm(void)
{
    return kc_token_mgr.realm;
}

void
keycloak_set_available(int available)
{
    kc_token_mgr.available = available;
}

int
keycloak_is_available(void)
{
    return kc_token_mgr.available;
}

/* -------------------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------------- */

void
kc_token_init(struct log_type *log)
{
    token_log = log;
}

void
kc_token_cleanup(void)
{
    keycloak_token_manager_shutdown();
}

#endif /* WITH_KEYCLOAK */
