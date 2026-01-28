#include "config.h"

#ifdef WITH_KEYCLOAK

#include <string.h>
#include <time.h>
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include "keycloak.h"       /* also includes kc_token.h */
#include "kc_async.h"
#include "kc/kc_cache.h"
#include "kc_sync.h"
#include "kc_http_internal.h"
#include "threadpool.h"
#include "common.h"
#include "log.h"
#include "ioset.h"
#include "timeq.h"
#include "x3_kc_bridge.h"
#include "base64.h"
#include "mempool.h"
#include <curl/multi.h>

struct log_type* KC_LOG;

/* Persistent CURL handle for connection reuse */
CURL* kc_curl_handle = NULL;

/*
 * =============================================================================
 * Performance Statistics
 * =============================================================================
 */

static struct kc_stats kc_stats = {0};

/* Update stats after an HTTP request */
void
kc_stats_record_request(unsigned long latency_ms, int is_error)
{
    kc_stats.http_requests++;
    kc_stats.total_latency_ms += latency_ms;
    kc_stats.last_request_time = time(NULL);

    if (latency_ms > kc_stats.max_latency_ms) {
        kc_stats.max_latency_ms = latency_ms;
    }
    if (kc_stats.min_latency_ms == 0 || latency_ms < kc_stats.min_latency_ms) {
        kc_stats.min_latency_ms = latency_ms;
    }

    if (is_error) {
        kc_stats.http_errors++;
    }
}

/* Public API: get stats snapshot */
void
keycloak_get_stats(struct kc_stats *stats_out)
{
    if (stats_out) {
        struct kc_cache_stats cstats;
        struct kc_jwt_stats jstats;
        struct kc_token_stats tstats;
        *stats_out = kc_stats;
        /* Merge in cache stats */
        kc_cache_stats_get(&cstats);
        stats_out->user_cache_hits = cstats.user_cache_hits;
        stats_out->user_cache_misses = cstats.user_cache_misses;
        /* Merge in JWT stats */
        kc_jwt_stats_get(&jstats);
        stats_out->jwks_cache_hits = jstats.jwks_cache_hits;
        stats_out->jwks_cache_misses = jstats.jwks_cache_misses;
        /* Merge in token stats */
        kc_token_stats_get(&tstats);
        stats_out->token_refreshes = tstats.token_refreshes;
    }
}

/* Public API: reset stats */
void
keycloak_reset_stats(void)
{
    memset(&kc_stats, 0, sizeof(kc_stats));
}

/* Public wrapper for cache invalidation */
void
keycloak_invalidate_user_cache(const char *username)
{
    kc_userid_cache_remove(username);
}


/* Forward declaration for exit handler */
static void keycloak_exit_handler(void *extra);

void
init_keycloak(void)
{
    KC_LOG = log_register_type("keycloak", "file:keycloak.log");

    /* Initialize cache subsystem */
    kc_cache_init();

    /* Initialize JWT subsystem */
    kc_jwt_init();

    /* Initialize token subsystem */
    kc_token_init(KC_LOG);
    kc_token_set_async_acquire(keycloak_get_client_token_async);

    /* Initialize sync API subsystem */
    kc_sync_init(KC_LOG);

    /* Initialize persistent CURL handle */
    kc_curl_handle = curl_easy_init();
    if (kc_curl_handle) {
        /* Set persistent options that survive curl_easy_reset() */
        curl_easy_setopt(kc_curl_handle, CURLOPT_TCP_NODELAY, 1L);
        curl_easy_setopt(kc_curl_handle, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(kc_curl_handle, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(kc_curl_handle, CURLOPT_TCP_KEEPIDLE, 60L);
        curl_easy_setopt(kc_curl_handle, CURLOPT_TCP_KEEPINTVL, 30L);
        log_module(KC_LOG, LOG_INFO, "Keycloak CURL handle initialized with connection pooling");
    }

    /* Register cleanup on exit */
    reg_exit_func(keycloak_exit_handler, NULL);
}

static void
keycloak_exit_handler(UNUSED_ARG(void *extra))
{
    cleanup_keycloak();
}

void
cleanup_keycloak(void)
{
    /* Cleanup async infrastructure (includes coalesced updates cleanup) */
    kc_async_cleanup();

    /* Cleanup token subsystem (token manager shutdown) */
    kc_token_cleanup();

    /* Cleanup JWT subsystem (JWKS cache + CURL handle) */
    kc_jwt_cleanup();

    /* Cleanup caches */
    kc_cache_cleanup();

    if (kc_curl_handle) {
        curl_easy_cleanup(kc_curl_handle);
        kc_curl_handle = NULL;
        log_module(KC_LOG, LOG_INFO, "Keycloak CURL handle cleaned up");
    }
}

/*
 * =============================================================================
 * Unified HTTP API (curl_opts pattern for sync and async)
 * =============================================================================
 */

/* Write callback (shared by sync and async) */
size_t
curl_write_cb(char *data, size_t size, size_t nmemb, void *clientp)
{
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *)clientp;

    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if (!ptr) return 0;  /* Out of memory */

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}
/* Apply curl_opts to a CURL handle (shared by sync and async) */
int
curl_apply_opts(CURL *curl, struct curl_opts opts, struct memory *chunk_out,
                struct curl_slist **header_list_out)
{
    struct curl_slist *header_list = NULL;

    if (!curl || !opts.uri) return -1;

    /* Performance optimizations */
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 60L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 30L);

    /* Timeouts */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    /* URL */
    curl_easy_setopt(curl, CURLOPT_URL, opts.uri);

    /* Setup write callback if output buffer provided */
    if (chunk_out && opts.write_callback) {
        if (!chunk_out->response) {
            chunk_out->response = malloc(1);
            if (!chunk_out->response) return -1;
            chunk_out->response[0] = 0;
            chunk_out->size = 0;
        }
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, opts.write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)chunk_out);
    }

    /* HTTP method */
    switch (opts.method) {
        case HTTP_PUT:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
            break;
        case HTTP_DELETE:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            break;
        case HTTP_POST:
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            break;
        case HTTP_GET:
        default:
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            break;
    }

    /* POST/PUT fields - binary data takes priority over string fields */
    if (opts.post_data && opts.post_data_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, opts.post_data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)opts.post_data_len);
    } else if (opts.post_fields) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, opts.post_fields);
    }

    /* Headers */
    if (opts.header_count > 0) {
        for (size_t i = 0; i < opts.header_count; i++) {
            header_list = curl_slist_append(header_list, opts.header_list[i]);
        }
        if (!header_list) return -1;
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
        if (header_list_out) *header_list_out = header_list;
    }

    /* Basic auth */
    if (opts.auth_user && opts.auth_passwd) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, opts.auth_user);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, opts.auth_passwd);
    }

    /* Bearer auth */
    if (opts.xoauth2_bearer) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, opts.xoauth2_bearer);
    }

    /* Response header capture (optional) */
    if (opts.header_callback) {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, opts.header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, opts.header_userdata);
    }

    return 0;
}

void keycloak_user_free_fields(struct kc_user* user)
{
    if (!user) {
        return;
    }

    if (user->id) {
        free(user->id);
        user->id = NULL;
    }
    if (user->username) {
        free(user->username);
        user->username = NULL;
    }
    if (user->email) {
        free(user->email);
        user->email = NULL;
    }
}

void keycloak_user_free(struct kc_user* user)
{
    if (!user) {
        return;
    }

    keycloak_user_free_fields(user);
    free(user);
}

/* Check if HTTP code or curl error is retryable */
int
is_retryable_error(CURLcode curl_res, long http_code)
{
    /* Retryable curl errors */
    if (curl_res == CURLE_COULDNT_CONNECT ||
        curl_res == CURLE_OPERATION_TIMEDOUT ||
        curl_res == CURLE_GOT_NOTHING ||
        curl_res == CURLE_RECV_ERROR ||
        curl_res == CURLE_SEND_ERROR) {
        return 1;
    }
    /* Retryable HTTP codes (server errors, rate limiting) */
    if (http_code >= 500 || http_code == 429) {
        return 1;
    }
    return 0;
}

long curl_perform(struct curl_opts opts, struct memory* chunk_out)
{
    CURL* curl = NULL;
    int own_handle = 0;
    CURLcode res = CURLE_FAILED_INIT;
    long result = KC_ERROR;
    long http_code = 0;
    struct curl_slist* header_list = NULL;
    int attempt = 0;
    int max_attempts = opts.max_retries + 1;
    int delay_ms = opts.retry_delay_ms > 0 ? opts.retry_delay_ms : 100;
    const char *req_id = opts.request_id ? opts.request_id : "-";

    if (!opts.uri) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] curl_perform: Invalid arguments", req_id);
        return KC_ERROR;
    }

    /* Use persistent handle if available, otherwise create new one */
    if (kc_curl_handle) {
        curl = kc_curl_handle;
        curl_easy_reset(curl);  /* Reset all options for reuse */
        own_handle = 0;
    } else {
        curl = curl_easy_init();
        own_handle = 1;
        if (!curl) {
            log_module(KC_LOG, LOG_DEBUG, "[%s] curl_perform: Failed to init curl", req_id);
            return KC_ERROR;
        }
    }

    for (attempt = 0; attempt < max_attempts; attempt++) {
        /* Reset for retry */
        if (attempt > 0) {
            log_module(KC_LOG, LOG_DEBUG, "[%s] Retry %d/%d after %dms",
                       req_id, attempt, opts.max_retries, delay_ms * attempt);

            /* Exponential backoff */
            struct timespec ts = { .tv_sec = 0, .tv_nsec = delay_ms * attempt * 1000000L };
            nanosleep(&ts, NULL);

            /* Reset response buffer for retry */
            if (chunk_out && chunk_out->response) {
                free(chunk_out->response);
                chunk_out->response = NULL;
                chunk_out->size = 0;
            }

            /* Free previous headers */
            if (header_list) {
                curl_slist_free_all(header_list);
                header_list = NULL;
            }
        }

        /* Reset curl handle for each attempt */
        if (!own_handle) {
            curl_easy_reset(curl);
        }

        /* Apply unified options */
        if (curl_apply_opts(curl, opts, chunk_out, &header_list) < 0) {
            log_module(KC_LOG, LOG_DEBUG, "[%s] curl_perform: Failed to apply options", req_id);
            continue;  /* Try again if retries left */
        }

        /* Perform request (blocking) with timing */
        {
            struct timeval tv_start, tv_end;
            unsigned long latency_ms;
            int is_error;

            gettimeofday(&tv_start, NULL);
            res = curl_easy_perform(curl);
            gettimeofday(&tv_end, NULL);

            http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

            /* Calculate latency */
            latency_ms = (tv_end.tv_sec - tv_start.tv_sec) * 1000 +
                         (tv_end.tv_usec - tv_start.tv_usec) / 1000;
            is_error = (res != CURLE_OK || http_code >= 500);

            /* Record stats */
            kc_stats_record_request(latency_ms, is_error);

            /* Log slow requests */
            if (latency_ms > 1000) {
                log_module(KC_LOG, LOG_INFO, "[%s] Slow request: %lu ms (HTTP %ld)",
                           req_id, latency_ms, http_code);
            }
        }

        if (res == CURLE_OK && http_code > 0 && http_code < 500 && http_code != 429) {
            /* Success or non-retryable client error */
            result = http_code;
            break;
        }

        /* Check if error is retryable */
        if (!is_retryable_error(res, http_code) || attempt >= max_attempts - 1) {
            if (res != CURLE_OK) {
                log_module(KC_LOG, LOG_DEBUG, "[%s] curl_perform failed: %s",
                           req_id, curl_easy_strerror(res));
            } else {
                log_module(KC_LOG, LOG_DEBUG, "[%s] curl_perform: HTTP %ld (non-retryable)",
                           req_id, http_code);
                result = http_code;
            }
            break;
        }

        log_module(KC_LOG, LOG_DEBUG, "[%s] Retryable error: curl=%d http=%ld",
                   req_id, res, http_code);
    }

    if (header_list) {
        curl_slist_free_all(header_list);
    }

    if (result < 0 && chunk_out && chunk_out->response) {
        free(chunk_out->response);
        chunk_out->response = NULL;
        chunk_out->size = 0;
    }

    if (curl && own_handle) {
        curl_easy_cleanup(curl);
    }

    return result;
}


int json_read_object_string(json_t* object, const char* key,
    char** value_out, size_t* value_out_size)
{
    if (!object || !key || !value_out) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_object_string: Invalid arguments");
        return KC_ERROR;
    }

    // Extract and validate the string value
    json_t* value = json_object_get(object, key);
    if (!value || !json_is_string(value)) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_object_string: Missing or invalid '%s' field", key);
        return KC_ERROR;
    }

    const char* value_str = json_string_value(value);
    size_t value_len = strlen(value_str);

    // Allocate memory for the string (including null terminator)
    char* allocated_str = malloc(value_len + 1);
    if (!allocated_str) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_object_string: Failed to allocate memory for '%s'", key);
        return KC_ERROR;
    }

    strcpy(allocated_str, value_str);
    *value_out = allocated_str;

    if (value_out_size) {
        *value_out_size = value_len;
    }

    return KC_SUCCESS;
}

int json_read_object_boolean(json_t* object, const char* key, bool* value_out)
{
    // Extract and validate value
    json_t* value = json_object_get(object, key);
    if (!value || !json_is_boolean(value)) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_object_boolean: Missing or invalid '%s' field", key);
        return KC_ERROR;
    }

    *value_out = json_boolean_value(value);
    return KC_SUCCESS;
}

int json_read_kc_user(json_t* user_object, struct kc_user* user_out)
{
    if (!user_object || !user_out) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_user: Invalid arguments");
        return KC_ERROR;
    }

    memset(user_out, 0, sizeof(*user_out));

    if (json_read_object_string(user_object, "id", &user_out->id, &user_out->id_size) != KC_SUCCESS) {
        return KC_ERROR;
    }

    if (json_read_object_string(user_object, "username", &user_out->username, &user_out->username_size) != KC_SUCCESS) {
        free(user_out->id);
        return KC_ERROR;
    }

    /* Email may be absent during user creation - make it optional */
    if (json_read_object_string(user_object, "email", &user_out->email, &user_out->email_size) != KC_SUCCESS) {
        user_out->email = NULL;
        user_out->email_size = 0;
    }

    /* emailVerified defaults to false if absent */
    if (json_read_object_boolean(user_object, "emailVerified", &user_out->emailVerified) != KC_SUCCESS) {
        user_out->emailVerified = 0;
    }

    return KC_SUCCESS;
}

char* json_build_user_representation(const char *username, const char *email, const char *passwd)
{
    // Input validation - username required, email optional (use ""), passwd optional (NULL = no credentials)
    if (!username) {
        log_module(KC_LOG, LOG_DEBUG, "json_build_user_representation: Invalid arguments");
        return NULL;
    }

    char* result = NULL;

    json_t* user_obj = json_object();

    // Build JSON using Jansson API
    json_object_set_new(user_obj, "username", json_string(username));
    json_object_set_new(user_obj, "email", json_string(email ? email : ""));
    json_object_set_new(user_obj, "enabled", json_true());

    // Only add credentials if password provided
    if (passwd && *passwd) {
        json_t* creds = json_array();
        json_t* cred = json_object();

        json_object_set_new(cred, "type", json_string("password"));
        json_object_set_new(cred, "value", json_string(passwd));
        json_object_set_new(cred, "temporary", json_false());
        json_array_append_new(creds, cred);
        json_object_set_new(user_obj, "credentials", creds);
    }

    result = json_dumps(user_obj, JSON_COMPACT);

    if (!result) {
        log_module(KC_LOG, LOG_DEBUG, "json_build_user_representation: json_dumps failed");
    }

    json_decref(user_obj);

    return result;
}

/**
 * Build user JSON representation with pre-hashed password for credential import.
 * Uses Keycloak's credential import format instead of plaintext password.
 *
 * @param username    Username for the new user
 * @param email       Email address (can be empty string)
 * @param cred_data   JSON string for credentialData (algorithm, iterations)
 * @param secret_data JSON string for secretData (hash value, salt)
 * @return Allocated JSON string or NULL on failure
 */
char* json_build_user_with_hash(const char *username, const char *email,
                                const char *cred_data, const char *secret_data)
{
    /* For user creation: username, email, cred_data, and secret_data all required
     * For user updates: username can be NULL, and either email or credentials can be set
     * If cred_data is set, secret_data must also be set */
    if (cred_data && !secret_data) {
        log_module(KC_LOG, LOG_DEBUG, "json_build_user_with_hash: cred_data requires secret_data");
        return NULL;
    }

    /* Must have at least something to update/create (check for non-empty) */
    int has_username = username && username[0];
    int has_email = email && email[0];
    if (!has_username && !has_email && !cred_data) {
        log_module(KC_LOG, LOG_DEBUG, "json_build_user_with_hash: Nothing to include in JSON body");
        return NULL;
    }

    char* result = NULL;

    json_t* user_obj = json_object();

    /* Build user object - only include fields that are set and non-empty */
    if (username && username[0]) {
        json_object_set_new(user_obj, "username", json_string(username));
    }
    if (email && email[0]) {
        json_object_set_new(user_obj, "email", json_string(email));
    }
    json_object_set_new(user_obj, "enabled", json_true());

    /* Build credential with pre-hashed password if provided */
    if (cred_data && secret_data) {
        json_t* creds = json_array();
        json_t* cred = json_object();

        json_object_set_new(cred, "type", json_string("password"));

        /* credentialData and secretData must be JSON strings containing JSON */
        json_object_set_new(cred, "credentialData", json_string(cred_data));
        json_object_set_new(cred, "secretData", json_string(secret_data));
        json_object_set_new(cred, "temporary", json_false());

        json_array_append_new(creds, cred);
        json_object_set_new(user_obj, "credentials", creds);
    }

    result = json_dumps(user_obj, JSON_COMPACT);

    if (!result) {
        log_module(KC_LOG, LOG_DEBUG, "json_build_user_with_hash: json_dumps failed");
    }

    json_decref(user_obj);

    return result;
}


#endif /* WITH_KEYCLOAK */
