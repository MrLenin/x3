#include "config.h"

#ifdef WITH_KEYCLOAK

#include <string.h>
#include <time.h>
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include "keycloak.h"
#include "threadpool.h"
#include "common.h"
#include "log.h"
#include "ioset.h"
#include "timeq.h"
#include "x3_kc_bridge.h"
#include "base64.h"
#include "mempool.h"
#include <curl/multi.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif

static struct log_type* KC_LOG;

/* Persistent CURL handle for connection reuse */
static CURL* kc_curl_handle = NULL;

/*
 * =============================================================================
 * JWKS Cache for Local JWT Validation
 * =============================================================================
 */

#define JWKS_CACHE_TTL 3600  /* Cache keys for 1 hour */
#define JWKS_MAX_KEYS 4      /* Max number of keys to cache */

struct jwks_key {
    char *kid;           /* Key ID */
    EVP_PKEY *pkey;      /* Parsed public key */
};

/* JWKS (JSON Web Key Set) cache for JWT signature verification.
 *
 * Thread-safety note: This cache is accessed without locking because X3 uses
 * single-threaded event-driven I/O (ioset). All Keycloak HTTP operations
 * either block or use async callbacks that run in the main event loop.
 * The cache is refreshed synchronously via jwks_refresh() before any JWT
 * validation that finds a missing key.
 */
static struct {
    struct jwks_key keys[JWKS_MAX_KEYS];
    int key_count;
    time_t fetched;
    char *realm_url;     /* URL of the realm this cache is for */
} jwks_cache = {0};

/*
 * =============================================================================
 * User ID Cache for HTTP Round-trip Optimization
 * =============================================================================
 *
 * When creating a user, Keycloak returns the user ID in the Location header
 * of the HTTP 201 response. We cache this to avoid a GET lookup when we need
 * to update the user (e.g., syncing password hash after registration).
 *
 * Cache entries are short-lived (5 minutes) and used primarily during the
 * registration → activation flow where multiple operations target the same user.
 */

#define KC_USERID_CACHE_TTL 300  /* 5 minutes */
#define KC_USERID_CACHE_MAX 64   /* Max cached entries */

struct kc_userid_entry {
    char username[64];
    char user_id[64];
    time_t created;
};

static struct {
    struct kc_userid_entry entries[KC_USERID_CACHE_MAX];
    int count;
} kc_userid_cache = {0};

/*
 * =============================================================================
 * Performance Statistics
 * =============================================================================
 */

static struct kc_stats kc_stats = {0};

/* Update stats after an HTTP request */
static void
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
        *stats_out = kc_stats;
    }
}

/* Public API: reset stats */
void
keycloak_reset_stats(void)
{
    memset(&kc_stats, 0, sizeof(kc_stats));
}

/* Cache a user ID (called after successful create) */
static void
kc_userid_cache_put(const char *username, const char *user_id)
{
    if (!username || !user_id) return;

    /* Check if already cached (update timestamp) */
    for (int i = 0; i < kc_userid_cache.count; i++) {
        if (strcasecmp(kc_userid_cache.entries[i].username, username) == 0) {
            safestrncpy(kc_userid_cache.entries[i].user_id, user_id,
                        sizeof(kc_userid_cache.entries[i].user_id));
            kc_userid_cache.entries[i].created = time(NULL);
            log_module(KC_LOG, LOG_DEBUG, "userid_cache: Updated %s -> %s", username, user_id);
            return;
        }
    }

    /* Evict stale entries if full */
    if (kc_userid_cache.count >= KC_USERID_CACHE_MAX) {
        time_t now = time(NULL);
        int oldest_idx = 0;
        time_t oldest_time = kc_userid_cache.entries[0].created;

        for (int i = 0; i < kc_userid_cache.count; i++) {
            /* Prefer evicting expired entries */
            if (now - kc_userid_cache.entries[i].created > KC_USERID_CACHE_TTL) {
                oldest_idx = i;
                break;
            }
            /* Otherwise evict oldest */
            if (kc_userid_cache.entries[i].created < oldest_time) {
                oldest_time = kc_userid_cache.entries[i].created;
                oldest_idx = i;
            }
        }

        log_module(KC_LOG, LOG_DEBUG, "userid_cache: Evicting %s to make room",
                   kc_userid_cache.entries[oldest_idx].username);

        /* Shift remaining entries if not last */
        if (oldest_idx < kc_userid_cache.count - 1) {
            memmove(&kc_userid_cache.entries[oldest_idx],
                    &kc_userid_cache.entries[oldest_idx + 1],
                    (kc_userid_cache.count - oldest_idx - 1) * sizeof(struct kc_userid_entry));
        }
        kc_userid_cache.count--;
    }

    /* Add new entry */
    int idx = kc_userid_cache.count++;
    safestrncpy(kc_userid_cache.entries[idx].username, username,
                sizeof(kc_userid_cache.entries[idx].username));
    safestrncpy(kc_userid_cache.entries[idx].user_id, user_id,
                sizeof(kc_userid_cache.entries[idx].user_id));
    kc_userid_cache.entries[idx].created = time(NULL);

    log_module(KC_LOG, LOG_DEBUG, "userid_cache: Added %s -> %s (count=%d)",
               username, user_id, kc_userid_cache.count);
}

/* Get cached user ID (returns NULL if not found or expired) */
static const char *
kc_userid_cache_get(const char *username)
{
    if (!username) return NULL;

    time_t now = time(NULL);

    for (int i = 0; i < kc_userid_cache.count; i++) {
        if (strcasecmp(kc_userid_cache.entries[i].username, username) == 0) {
            if (now - kc_userid_cache.entries[i].created > KC_USERID_CACHE_TTL) {
                log_module(KC_LOG, LOG_DEBUG, "userid_cache: %s expired", username);
                kc_stats.user_cache_misses++;
                return NULL;
            }
            log_module(KC_LOG, LOG_DEBUG, "userid_cache: Hit %s -> %s",
                       username, kc_userid_cache.entries[i].user_id);
            kc_stats.user_cache_hits++;
            return kc_userid_cache.entries[i].user_id;
        }
    }

    kc_stats.user_cache_misses++;
    return NULL;
}

/* Remove a cached entry (called on user delete) */
static void
kc_userid_cache_remove(const char *username)
{
    if (!username) return;

    for (int i = 0; i < kc_userid_cache.count; i++) {
        if (strcasecmp(kc_userid_cache.entries[i].username, username) == 0) {
            if (i < kc_userid_cache.count - 1) {
                memmove(&kc_userid_cache.entries[i],
                        &kc_userid_cache.entries[i + 1],
                        (kc_userid_cache.count - i - 1) * sizeof(struct kc_userid_entry));
            }
            kc_userid_cache.count--;
            log_module(KC_LOG, LOG_DEBUG, "userid_cache: Removed %s", username);
            return;
        }
    }
}

/* Public wrapper for cache invalidation */
void
keycloak_invalidate_user_cache(const char *username)
{
    kc_userid_cache_remove(username);
}

/*
 * =============================================================================
 * User Representation Cache for Safe Attribute Updates
 * =============================================================================
 *
 * Keycloak's PUT /admin/realms/{realm}/users/{id} does FULL replacement of
 * the user object. This means sending {"attributes": {"foo": ["bar"]}} will
 * CLEAR the user's email, firstName, etc.
 *
 * This cache stores full user representations (from webhooks or GET) so that
 * when updating attributes we can merge the new attribute into the existing
 * representation and PUT the complete object.
 *
 * Cache population sources:
 * - Webhook USER UPDATE events (contain full representation in payload)
 * - Explicit GET when cache miss occurs during attribute update
 *
 * Cache invalidation:
 * - User deleted: remove from cache
 * - Webhook USER UPDATE: replace with new representation
 */

#define KC_USER_REPR_CACHE_MAX 128  /* Max cached user representations */

struct kc_user_repr_entry {
    char user_id[64];      /* Keycloak user UUID (key) */
    json_t *repr;          /* Full user JSON object (jansson) */
    time_t last_updated;   /* When this entry was last refreshed */
};

static struct {
    struct kc_user_repr_entry entries[KC_USER_REPR_CACHE_MAX];
    int count;
} kc_user_repr_cache = {0};

/* Store/update user representation in cache */
void
kc_user_repr_cache_put(const char *user_id, json_t *repr)
{
    if (!user_id || !repr) return;

    /* Create a sanitized copy - strip credentials to avoid duplicate password creation.
     * Keycloak GET returns credentials array, but including it in PUT adds new credentials
     * rather than replacing. Credentials should be managed via separate endpoint. */
    json_t *sanitized = json_deep_copy(repr);
    if (!sanitized) {
        log_module(KC_LOG, LOG_ERROR, "user_repr_cache: Failed to copy repr for %s", user_id);
        return;
    }
    json_object_del(sanitized, "credentials");

    /* Check if already cached (update in place) */
    for (int i = 0; i < kc_user_repr_cache.count; i++) {
        if (strcmp(kc_user_repr_cache.entries[i].user_id, user_id) == 0) {
            /* Replace existing representation */
            if (kc_user_repr_cache.entries[i].repr)
                json_decref(kc_user_repr_cache.entries[i].repr);
            kc_user_repr_cache.entries[i].repr = sanitized;  /* Takes ownership */
            kc_user_repr_cache.entries[i].last_updated = time(NULL);
            log_module(KC_LOG, LOG_DEBUG, "user_repr_cache: Updated %s (credentials stripped)", user_id);
            return;
        }
    }

    /* Evict oldest entry if full */
    if (kc_user_repr_cache.count >= KC_USER_REPR_CACHE_MAX) {
        int oldest_idx = 0;
        time_t oldest_time = kc_user_repr_cache.entries[0].last_updated;

        for (int i = 1; i < kc_user_repr_cache.count; i++) {
            if (kc_user_repr_cache.entries[i].last_updated < oldest_time) {
                oldest_time = kc_user_repr_cache.entries[i].last_updated;
                oldest_idx = i;
            }
        }

        log_module(KC_LOG, LOG_DEBUG, "user_repr_cache: Evicting %s to make room",
                   kc_user_repr_cache.entries[oldest_idx].user_id);

        /* Free the old representation */
        if (kc_user_repr_cache.entries[oldest_idx].repr)
            json_decref(kc_user_repr_cache.entries[oldest_idx].repr);

        /* Shift remaining entries if not last */
        if (oldest_idx < kc_user_repr_cache.count - 1) {
            memmove(&kc_user_repr_cache.entries[oldest_idx],
                    &kc_user_repr_cache.entries[oldest_idx + 1],
                    (kc_user_repr_cache.count - oldest_idx - 1) *
                    sizeof(struct kc_user_repr_entry));
        }
        kc_user_repr_cache.count--;
    }

    /* Add new entry */
    int idx = kc_user_repr_cache.count++;
    safestrncpy(kc_user_repr_cache.entries[idx].user_id, user_id,
                sizeof(kc_user_repr_cache.entries[idx].user_id));
    kc_user_repr_cache.entries[idx].repr = sanitized;  /* Takes ownership */
    kc_user_repr_cache.entries[idx].last_updated = time(NULL);

    log_module(KC_LOG, LOG_DEBUG, "user_repr_cache: Added %s (count=%d, credentials stripped)",
               user_id, kc_user_repr_cache.count);
}

/* Get cached representation (returns borrowed reference, NULL if not found) */
json_t *
kc_user_repr_cache_get(const char *user_id)
{
    if (!user_id) return NULL;

    for (int i = 0; i < kc_user_repr_cache.count; i++) {
        if (strcmp(kc_user_repr_cache.entries[i].user_id, user_id) == 0) {
            log_module(KC_LOG, LOG_DEBUG, "user_repr_cache: Hit for %s", user_id);
            return kc_user_repr_cache.entries[i].repr;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "user_repr_cache: Miss for %s", user_id);
    return NULL;
}

/* Remove user from cache */
void
kc_user_repr_cache_remove(const char *user_id)
{
    if (!user_id) return;

    for (int i = 0; i < kc_user_repr_cache.count; i++) {
        if (strcmp(kc_user_repr_cache.entries[i].user_id, user_id) == 0) {
            if (kc_user_repr_cache.entries[i].repr)
                json_decref(kc_user_repr_cache.entries[i].repr);

            if (i < kc_user_repr_cache.count - 1) {
                memmove(&kc_user_repr_cache.entries[i],
                        &kc_user_repr_cache.entries[i + 1],
                        (kc_user_repr_cache.count - i - 1) *
                        sizeof(struct kc_user_repr_entry));
            }
            kc_user_repr_cache.count--;
            log_module(KC_LOG, LOG_DEBUG, "user_repr_cache: Removed %s", user_id);
            return;
        }
    }
}

/* Cleanup entire cache (call from cleanup_keycloak) */
static void
kc_user_repr_cache_cleanup(void)
{
    for (int i = 0; i < kc_user_repr_cache.count; i++) {
        if (kc_user_repr_cache.entries[i].repr) {
            json_decref(kc_user_repr_cache.entries[i].repr);
            kc_user_repr_cache.entries[i].repr = NULL;
        }
    }
    kc_user_repr_cache.count = 0;
    log_module(KC_LOG, LOG_DEBUG, "user_repr_cache: Cleaned up");
}

/*
 * =============================================================================
 * Attribute Update Coalescing
 * =============================================================================
 *
 * When multiple attribute updates for the same user arrive rapidly (e.g., during
 * account setup or bulk operations), we batch them into a single Keycloak API call.
 *
 * Flow:
 * 1. First attr update for a user creates a pending entry and schedules flush
 * 2. Subsequent attrs for same user are added to pending entry
 * 3. After delay, flush callback merges all pending attrs and issues single PUT
 */

#define KC_COALESCE_DELAY_SEC 1       /* Flush after 1 second of no new updates */
#define KC_COALESCE_MAX_PENDING 64    /* Max pending attr changes per user */

/* Single pending attribute change */
struct kc_pending_attr {
    char *name;                       /* Attribute name (heap allocated) */
    char *value;                      /* Attribute value (NULL = delete attr) */
    kc_async_callback cb;             /* Callback for this attr's requester */
    void *session;                    /* Session for this attr's requester */
};

/* Pending updates for one user - owns all memory */
struct kc_pending_user_update {
    char user_id[64];                 /* Keycloak user UUID */
    struct kc_pending_attr attrs[KC_COALESCE_MAX_PENDING];
    int attr_count;
    time_t scheduled_flush;           /* When flush was scheduled */
    struct kc_pending_user_update *next;
};

static struct kc_pending_user_update *kc_pending_updates = NULL;

/* Forward declarations for coalescing functions */
static void kc_coalesce_flush_cb(void *data);
static void kc_pending_update_free(struct kc_pending_user_update *p);
static void kc_coalesce_cleanup(void);

/* Invoke all callbacks for a pending update with given result */
static void
kc_pending_invoke_all_callbacks(struct kc_pending_user_update *p, int result)
{
    if (!p) return;
    for (int i = 0; i < p->attr_count; i++) {
        if (p->attrs[i].cb) {
            p->attrs[i].cb(p->attrs[i].session, result);
        }
    }
}

/* Free a pending update structure and all its contents */
static void
kc_pending_update_free(struct kc_pending_user_update *p)
{
    if (!p) return;
    for (int i = 0; i < p->attr_count; i++) {
        free(p->attrs[i].name);
        free(p->attrs[i].value);
    }
    free(p);
}

/* Cleanup all pending updates (called on shutdown) */
static void
kc_coalesce_cleanup(void)
{
    struct kc_pending_user_update *p, *next;
    int count = 0;

    for (p = kc_pending_updates; p; p = next) {
        next = p->next;
        /* Cancel the scheduled timeq callback to prevent use-after-free */
        timeq_del(0, kc_coalesce_flush_cb, p, TIMEQ_IGNORE_WHEN);
        /* Invoke all callbacks with error - shutdown aborts pending operations */
        kc_pending_invoke_all_callbacks(p, KC_ERROR);
        kc_pending_update_free(p);
        count++;
    }
    kc_pending_updates = NULL;

    if (count > 0) {
        log_module(KC_LOG, LOG_DEBUG, "coalesce: Cleaned up %d pending updates", count);
    }
}

/* Find existing pending update for user, or create new one */
static struct kc_pending_user_update *
kc_coalesce_get_or_create(const char *user_id)
{
    struct kc_pending_user_update *p;

    /* Find existing */
    for (p = kc_pending_updates; p; p = p->next) {
        if (strcmp(p->user_id, user_id) == 0)
            return p;
    }

    /* Create new */
    p = calloc(1, sizeof(*p));
    if (!p) {
        log_module(KC_LOG, LOG_ERROR, "coalesce: Out of memory");
        return NULL;
    }

    safestrncpy(p->user_id, user_id, sizeof(p->user_id));
    p->scheduled_flush = now + KC_COALESCE_DELAY_SEC;
    p->next = kc_pending_updates;
    kc_pending_updates = p;

    /* Schedule flush callback */
    timeq_add(p->scheduled_flush, kc_coalesce_flush_cb, p);

    log_module(KC_LOG, LOG_DEBUG, "coalesce: Created pending update for %s, flush in %ds",
               user_id, KC_COALESCE_DELAY_SEC);
    return p;
}

/* Add an attribute to pending update */
static int
kc_coalesce_add_attr(struct kc_pending_user_update *p,
                     const char *attr_name, const char *attr_value,
                     kc_async_callback cb, void *session)
{
    /* Check if this attr already pending (update in place) */
    for (int i = 0; i < p->attr_count; i++) {
        if (strcmp(p->attrs[i].name, attr_name) == 0) {
            free(p->attrs[i].value);
            p->attrs[i].value = attr_value ? strdup(attr_value) : NULL;
            /* Store callback for this attr - each requester gets notified */
            p->attrs[i].cb = cb;
            p->attrs[i].session = session;
            log_module(KC_LOG, LOG_DEBUG, "coalesce: Updated pending attr %s for %s",
                       attr_name, p->user_id);
            return 0;
        }
    }

    /* Add new attr */
    if (p->attr_count >= KC_COALESCE_MAX_PENDING) {
        log_module(KC_LOG, LOG_WARNING, "coalesce: Too many pending attrs for %s",
                   p->user_id);
        return -1;
    }

    p->attrs[p->attr_count].name = strdup(attr_name);
    p->attrs[p->attr_count].value = attr_value ? strdup(attr_value) : NULL;
    p->attrs[p->attr_count].cb = cb;
    p->attrs[p->attr_count].session = session;
    if (!p->attrs[p->attr_count].name) {
        log_module(KC_LOG, LOG_ERROR, "coalesce: Out of memory for attr name");
        return -1;
    }
    p->attr_count++;

    log_module(KC_LOG, LOG_DEBUG, "coalesce: Added pending attr %s for %s (count=%d)",
               attr_name, p->user_id, p->attr_count);
    return 0;
}

/* Forward declarations for JWT functions */
static int jwks_refresh(struct kc_realm realm);
static void jwks_cleanup(void);
static EVP_PKEY *jwks_get_key(const char *kid);
static char *base64url_decode_alloc(const char *input, size_t *out_len);
static int jwt_verify_signature(const char *token, EVP_PKEY *pkey);
static int jwt_parse_claims(const char *payload_b64, struct kc_token_info *info);

/* Forward declaration for JSON helpers used by async functions */
static char* json_build_user_representation(const char *username, const char *email, const char *passwd);
static char* json_build_user_with_hash(const char *username, const char *email,
                                       const char *cred_data, const char *secret_data);
static int json_read_kc_access_token(const char* response, struct access_token** token_out);
static int json_read_kc_user(json_t* user_object, struct kc_user* user_out);

/* Forward declaration for exit handler */
static void keycloak_exit_handler(void *extra);

/*
 * Token Manager State (defined early for use by async functions)
 * The actual initialization and management functions are defined later.
 *
 * Thread-safety: The token can be read by worker threads (for HTTP auth).
 * kc_token_lock protects reads/writes to the token field.
 */
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

/*
 * Thread-safe helper to get a copy of the current bearer token.
 * Returns a newly allocated string that must be freed by the caller.
 * Returns NULL if no token is available.
 */
static char *
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

void
init_keycloak(void)
{
    KC_LOG = log_register_type("keycloak", "file:keycloak.log");

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

/* Forward declarations */
static void kc_async_cleanup(void);
static void kc_async_bridge_complete(long http_code, const char *body, size_t body_len,
                                      json_t *json, const char *error, void *req_data);

void
cleanup_keycloak(void)
{
    /* Cleanup pending coalesced updates first (cancels timeq callbacks) */
    kc_coalesce_cleanup();

    /* Cleanup async infrastructure */
    kc_async_cleanup();

    /* Cleanup JWKS cache */
    jwks_cleanup();

    /* Cleanup user representation cache */
    kc_user_repr_cache_cleanup();

    if (kc_curl_handle) {
        curl_easy_cleanup(kc_curl_handle);
        kc_curl_handle = NULL;
        log_module(KC_LOG, LOG_INFO, "Keycloak CURL handle cleaned up");
    }
}

/*
 * =============================================================================
 * Local JWT Validation (JWKS + OpenSSL)
 * =============================================================================
 */

/* Cleanup JWKS cache */
static void
jwks_cleanup(void)
{
    for (int i = 0; i < jwks_cache.key_count; i++) {
        if (jwks_cache.keys[i].kid) {
            free(jwks_cache.keys[i].kid);
            jwks_cache.keys[i].kid = NULL;
        }
        if (jwks_cache.keys[i].pkey) {
            EVP_PKEY_free(jwks_cache.keys[i].pkey);
            jwks_cache.keys[i].pkey = NULL;
        }
    }
    jwks_cache.key_count = 0;
    jwks_cache.fetched = 0;
    if (jwks_cache.realm_url) {
        free(jwks_cache.realm_url);
        jwks_cache.realm_url = NULL;
    }
}

/* Convert base64url to standard base64 and decode */
static char *
base64url_decode_alloc(const char *input, size_t *out_len)
{
    if (!input || !out_len) return NULL;

    size_t input_len = strlen(input);
    if (input_len == 0) return NULL;

    /* Calculate padded length */
    size_t padded_len = input_len;
    int padding = (4 - (input_len % 4)) % 4;
    padded_len += padding;

    /* Allocate buffer for standard base64 */
    char *std_b64 = malloc(padded_len + 1);
    if (!std_b64) return NULL;

    /* Convert base64url to standard base64 */
    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
        std_b64[i] = c;
    }
    /* Add padding */
    for (size_t i = input_len; i < padded_len; i++) {
        std_b64[i] = '=';
    }
    std_b64[padded_len] = '\0';

    /* Decode using existing base64 function */
    char *decoded = NULL;
    if (!base64_decode_alloc(std_b64, padded_len, &decoded, out_len)) {
        free(std_b64);
        return NULL;
    }
    free(std_b64);
    return decoded;
}

/* Parse RSA public key from JWKS 'n' and 'e' values */
static EVP_PKEY *
jwks_parse_rsa_key(const char *n_b64, const char *e_b64)
{
    EVP_PKEY *pkey = NULL;
    BIGNUM *n = NULL, *e = NULL;
    unsigned char *n_bin = NULL, *e_bin = NULL;
    size_t n_len = 0, e_len = 0;

    /* Decode modulus and exponent */
    n_bin = (unsigned char *)base64url_decode_alloc(n_b64, &n_len);
    e_bin = (unsigned char *)base64url_decode_alloc(e_b64, &e_len);
    if (!n_bin || !e_bin) {
        goto cleanup;
    }

    /* Create BIGNUMs */
    n = BN_bin2bn(n_bin, n_len, NULL);
    e = BN_bin2bn(e_bin, e_len, NULL);
    if (!n || !e) {
        goto cleanup;
    }

    /* Create EVP_PKEY with RSA parameters */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* OpenSSL 3.0+ uses EVP_PKEY_fromdata */
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) goto cleanup;

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
        OSSL_PARAM_BLD_free(bld);
        goto cleanup;
    }

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) goto cleanup;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (ctx) {
        if (EVP_PKEY_fromdata_init(ctx) > 0) {
            EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        }
        EVP_PKEY_CTX_free(ctx);
    }
    OSSL_PARAM_free(params);
#else
    /* OpenSSL 1.1.x uses RSA_set0_key */
    RSA *rsa = RSA_new();
    if (!rsa) goto cleanup;

    /* RSA_set0_key takes ownership of n and e on success */
    if (RSA_set0_key(rsa, n, e, NULL) != 1) {
        RSA_free(rsa);
        goto cleanup;
    }
    n = NULL; e = NULL;  /* Ownership transferred */

    pkey = EVP_PKEY_new();
    if (!pkey) {
        RSA_free(rsa);
        goto cleanup;
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto cleanup;
    }
#endif

cleanup:
    if (n_bin) free(n_bin);
    if (e_bin) free(e_bin);
    if (n) BN_free(n);
    if (e) BN_free(e);
    return pkey;
}

/* Forward declarations for JWKS fetch */
static size_t curl_write_cb(char* data, size_t size, size_t nmemb, void* clientp);
static char *kc_build_jwks_endpoint(struct kc_realm realm);

/* Refresh JWKS cache from Keycloak */
static int
jwks_refresh(struct kc_realm realm)
{
    if (!realm.base_uri || !realm.realm) {
        return KC_ERROR;
    }

    /* Build JWKS URL using endpoint builder */
    char *url = kc_build_jwks_endpoint(realm);
    if (!url) {
        return KC_ERROR;
    }

    /* Check if cache is still valid for this realm */
    if (jwks_cache.realm_url && strcmp(jwks_cache.realm_url, url) == 0) {
        if (now - jwks_cache.fetched < JWKS_CACHE_TTL && jwks_cache.key_count > 0) {
            log_module(KC_LOG, LOG_DEBUG, "JWKS cache still valid (%d keys)",
                       jwks_cache.key_count);
            free(url);
            return KC_SUCCESS;
        }
    }

    log_module(KC_LOG, LOG_INFO, "Refreshing JWKS from %s", url);

    /* Cleanup old cache */
    jwks_cleanup();

    /* Fetch JWKS - reuse persistent handle if available */
    struct {
        char *response;
        size_t size;
    } chunk = {0};

    CURL *curl;
    int own_handle = 0;
    if (kc_curl_handle) {
        curl = kc_curl_handle;
        curl_easy_reset(curl);
    } else {
        curl = curl_easy_init();
        own_handle = 1;
        if (!curl) {
            free(url);
            return KC_ERROR;
        }
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (own_handle) {
        curl_easy_cleanup(curl);
    }

    if (res != CURLE_OK || http_code != 200 || !chunk.response) {
        log_module(KC_LOG, LOG_WARNING, "Failed to fetch JWKS: %s (HTTP %ld)",
                   curl_easy_strerror(res), http_code);
        if (chunk.response) free(chunk.response);
        free(url);
        return KC_ERROR;
    }

    /* Parse JWKS JSON */
    json_error_t error;
    json_t *root = json_loads(chunk.response, 0, &error);
    free(chunk.response);

    if (!root) {
        log_module(KC_LOG, LOG_WARNING, "Failed to parse JWKS: %s", error.text);
        free(url);
        return KC_ERROR;
    }

    json_t *keys = json_object_get(root, "keys");
    if (!json_is_array(keys)) {
        json_decref(root);
        free(url);
        return KC_ERROR;
    }

    /* Parse each signing key */
    size_t index;
    json_t *key;
    json_array_foreach(keys, index, key) {
        if (jwks_cache.key_count >= JWKS_MAX_KEYS) break;

        const char *kty = json_string_value(json_object_get(key, "kty"));
        const char *use = json_string_value(json_object_get(key, "use"));
        const char *alg = json_string_value(json_object_get(key, "alg"));
        const char *kid = json_string_value(json_object_get(key, "kid"));
        const char *n = json_string_value(json_object_get(key, "n"));
        const char *e = json_string_value(json_object_get(key, "e"));

        /* Only cache RSA signing keys (RS256) */
        if (!kty || strcmp(kty, "RSA") != 0) continue;
        if (use && strcmp(use, "sig") != 0) continue;  /* Skip encryption keys */
        if (alg && strcmp(alg, "RS256") != 0) continue;
        if (!kid || !n || !e) continue;

        EVP_PKEY *pkey = jwks_parse_rsa_key(n, e);
        if (!pkey) {
            log_module(KC_LOG, LOG_WARNING, "Failed to parse RSA key kid=%s", kid);
            continue;
        }

        jwks_cache.keys[jwks_cache.key_count].kid = strdup(kid);
        jwks_cache.keys[jwks_cache.key_count].pkey = pkey;
        jwks_cache.key_count++;

        log_module(KC_LOG, LOG_DEBUG, "Cached JWKS key: kid=%s alg=%s", kid, alg ? alg : "RS256");
    }

    json_decref(root);

    if (jwks_cache.key_count == 0) {
        log_module(KC_LOG, LOG_WARNING, "No usable signing keys in JWKS");
        free(url);
        return KC_ERROR;
    }

    jwks_cache.fetched = now;
    jwks_cache.realm_url = url;  /* Transfer ownership */

    log_module(KC_LOG, LOG_INFO, "JWKS cache refreshed: %d keys", jwks_cache.key_count);
    return KC_SUCCESS;
}

/* Get cached key by kid */
static EVP_PKEY *
jwks_get_key(const char *kid)
{
    if (!kid) return NULL;

    for (int i = 0; i < jwks_cache.key_count; i++) {
        if (jwks_cache.keys[i].kid && strcmp(jwks_cache.keys[i].kid, kid) == 0) {
            return jwks_cache.keys[i].pkey;
        }
    }
    return NULL;
}

/* Verify JWT RS256 signature */
static int
jwt_verify_signature(const char *token, EVP_PKEY *pkey)
{
    if (!token || !pkey) return KC_ERROR;

    /* Find the two dots separating header.payload.signature */
    const char *dot1 = strchr(token, '.');
    if (!dot1) return KC_ERROR;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return KC_ERROR;

    /* The signed data is header.payload (everything before second dot) */
    size_t signed_len = dot2 - token;

    /* Decode signature */
    size_t sig_len = 0;
    unsigned char *sig = (unsigned char *)base64url_decode_alloc(dot2 + 1, &sig_len);
    if (!sig) return KC_ERROR;

    /* Verify RS256 signature */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(sig);
        return KC_ERROR;
    }

    int result = KC_ERROR;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1) {
        if (EVP_DigestVerifyUpdate(ctx, token, signed_len) == 1) {
            if (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) {
                result = KC_SUCCESS;
            }
        }
    }

    EVP_MD_CTX_free(ctx);
    free(sig);
    return result;
}

/* Parse JWT claims from payload */
static int
jwt_parse_claims(const char *payload_b64, struct kc_token_info *info)
{
    if (!payload_b64 || !info) return KC_ERROR;

    size_t payload_len = 0;
    char *payload = base64url_decode_alloc(payload_b64, &payload_len);
    if (!payload) return KC_ERROR;

    /* Null-terminate for JSON parsing */
    char *json_str = malloc(payload_len + 1);
    if (!json_str) {
        free(payload);
        return KC_ERROR;
    }
    memcpy(json_str, payload, payload_len);
    json_str[payload_len] = '\0';
    free(payload);

    json_error_t error;
    json_t *root = json_loads(json_str, 0, &error);
    free(json_str);

    if (!root) {
        log_module(KC_LOG, LOG_DEBUG, "Failed to parse JWT claims: %s", error.text);
        return KC_ERROR;
    }

    /* Extract standard claims */
    json_t *exp = json_object_get(root, "exp");
    json_t *iat = json_object_get(root, "iat");
    json_t *sub = json_object_get(root, "sub");
    json_t *preferred_username = json_object_get(root, "preferred_username");
    json_t *email = json_object_get(root, "email");

    /* Check expiration */
    if (json_is_integer(exp)) {
        info->exp = json_integer_value(exp);
        if (info->exp <= now) {
            log_module(KC_LOG, LOG_DEBUG, "JWT expired: exp=%ld now=%ld", info->exp, (long)now);
            json_decref(root);
            return KC_FORBIDDEN;  /* Token expired */
        }
    }

    if (json_is_integer(iat)) {
        info->iat = json_integer_value(iat);
    }

    if (json_is_string(sub)) {
        info->sub = strdup(json_string_value(sub));
        info->sub_size = strlen(info->sub);
    }

    if (json_is_string(preferred_username)) {
        info->username = strdup(json_string_value(preferred_username));
        info->username_size = strlen(info->username);
    }

    if (json_is_string(email)) {
        info->email = strdup(json_string_value(email));
        info->email_size = strlen(info->email);
    }

    /* Extract opserv level from custom claim if present */
    json_t *opserv_level = json_object_get(root, "x3_opserv_level");
    if (json_is_integer(opserv_level)) {
        info->opserv_level = json_integer_value(opserv_level);
    }

    info->active = true;
    json_decref(root);
    return KC_SUCCESS;
}

/**
 * Validate a JWT token locally using cached JWKS
 * Returns KC_SUCCESS if valid, KC_FORBIDDEN if expired/invalid, KC_ERROR if can't validate locally
 */
int
keycloak_validate_jwt_local(struct kc_realm realm, const char *token,
                            struct kc_token_info **info_out)
{
    if (!token || !info_out) return KC_ERROR;
    *info_out = NULL;

    /* Ensure JWKS is cached */
    if (jwks_refresh(realm) != KC_SUCCESS) {
        kc_stats.jwks_cache_misses++;  /* Need HTTP introspection */
        return KC_ERROR;  /* Can't validate locally, need fallback */
    }

    /* Parse JWT header to get kid */
    const char *dot1 = strchr(token, '.');
    if (!dot1) {
        log_module(KC_LOG, LOG_DEBUG, "Malformed JWT: no header separator");
        return KC_FORBIDDEN;  /* Not a valid JWT format - reject immediately */
    }

    size_t header_b64_len = dot1 - token;
    char *header_b64 = malloc(header_b64_len + 1);
    if (!header_b64) return KC_ERROR;
    memcpy(header_b64, token, header_b64_len);
    header_b64[header_b64_len] = '\0';

    size_t header_len = 0;
    char *header = base64url_decode_alloc(header_b64, &header_len);
    free(header_b64);
    if (!header) return KC_ERROR;

    /* Null-terminate for JSON parsing */
    char *header_json = malloc(header_len + 1);
    if (!header_json) {
        free(header);
        return KC_ERROR;
    }
    memcpy(header_json, header, header_len);
    header_json[header_len] = '\0';
    free(header);

    json_error_t error;
    json_t *hdr = json_loads(header_json, 0, &error);
    free(header_json);

    if (!hdr) {
        log_module(KC_LOG, LOG_DEBUG, "Malformed JWT header JSON: %s", error.text);
        return KC_FORBIDDEN;  /* Definitely not a valid JWT - reject immediately */
    }

    const char *alg = json_string_value(json_object_get(hdr, "alg"));
    const char *kid = json_string_value(json_object_get(hdr, "kid"));

    /* Only support RS256 */
    if (!alg || strcmp(alg, "RS256") != 0) {
        log_module(KC_LOG, LOG_DEBUG, "Unsupported JWT algorithm: %s", alg ? alg : "null");
        json_decref(hdr);
        kc_stats.jwks_cache_misses++;  /* Need HTTP introspection */
        return KC_ERROR;  /* Fall back to introspection */
    }

    if (!kid) {
        log_module(KC_LOG, LOG_DEBUG, "JWT missing kid");
        json_decref(hdr);
        kc_stats.jwks_cache_misses++;  /* Need HTTP introspection */
        return KC_ERROR;
    }

    /* Copy kid before freeing hdr - json_string_value returns pointer into JSON object */
    char *kid_copy = strdup(kid);
    json_decref(hdr);

    /* Get signing key */
    EVP_PKEY *pkey = jwks_get_key(kid_copy);
    if (!pkey) {
        log_module(KC_LOG, LOG_DEBUG, "Unknown kid in JWT: %s", kid_copy);
        free(kid_copy);
        kc_stats.jwks_cache_misses++;  /* Need HTTP introspection */
        return KC_ERROR;  /* Unknown key - might need JWKS refresh or fallback */
    }
    free(kid_copy);

    /* Verify signature */
    if (jwt_verify_signature(token, pkey) != KC_SUCCESS) {
        log_module(KC_LOG, LOG_DEBUG, "JWT signature verification failed");
        return KC_FORBIDDEN;  /* Invalid signature */
    }

    /* Parse and validate claims */
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return KC_ERROR;

    size_t payload_b64_len = dot2 - dot1 - 1;
    char *payload_b64 = malloc(payload_b64_len + 1);
    if (!payload_b64) return KC_ERROR;
    memcpy(payload_b64, dot1 + 1, payload_b64_len);
    payload_b64[payload_b64_len] = '\0';

    struct kc_token_info *info = calloc(1, sizeof(*info));
    if (!info) {
        free(payload_b64);
        return KC_ERROR;
    }

    int result = jwt_parse_claims(payload_b64, info);
    free(payload_b64);

    if (result == KC_SUCCESS) {
        *info_out = info;
        kc_stats.jwks_cache_hits++;  /* Validated locally, no HTTP needed */
        log_module(KC_LOG, LOG_DEBUG, "JWT validated locally: user=%s",
                   info->username ? info->username : "unknown");
    } else {
        keycloak_free_token_info(info);
    }

    return result;
}

/*
 * =============================================================================
 * Unified HTTP API (curl_opts pattern for sync and async)
 * =============================================================================
 */

/* Response buffer structure (shared by sync and async) */
struct memory {
    char* response;
    size_t size;
};

/* Write callback (shared by sync and async) */
static size_t
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

typedef size_t(*curl_write_cb_ptr)(char*, size_t, size_t, void*);

enum http_method {
    HTTP_GET = 0,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE
};

/* Header callback type - receives each header line */
typedef size_t (*curl_header_cb_ptr)(char *buffer, size_t size, size_t nitems, void *userdata);

struct curl_opts {
    const char* uri;
    const char* header_list[10];
    size_t header_count;
    const char* post_fields;
    const char* auth_user;
    const char* auth_passwd;
    const char* xoauth2_bearer;
    curl_write_cb_ptr write_callback;
    enum http_method method;
    /* Retry configuration */
    int max_retries;         /* 0 = no retry (default), 1-3 typical */
    int retry_delay_ms;      /* Base delay between retries (default 100ms) */
    /* Logging */
    const char* request_id;  /* Optional: for log correlation */
    /* Binary POST data (alternative to post_fields) */
    const void* post_data;   /* Binary data pointer */
    size_t post_data_len;    /* Binary data length */
    /* Response header capture (optional) */
    curl_header_cb_ptr header_callback;  /* Called for each response header */
    void* header_userdata;               /* Passed to header_callback */
};

/* Convenience initializer with sensible defaults */
#define CURL_OPTS_INIT { \
    .write_callback = curl_write_cb, \
    .method = HTTP_GET, \
    .header_count = 0, \
    .max_retries = 0, \
    .retry_delay_ms = 100, \
    .request_id = NULL \
}

/*
 * Auto-cleanup helpers for response buffers (GCC/Clang cleanup attribute)
 * Usage: AUTO_CLEANUP_RESPONSE struct memory chunk = {0};
 *        // chunk.response will be freed automatically when scope ends
 */
static void __attribute__((unused)) memory_struct_cleanup(struct memory *mem) {
    if (mem && mem->response) {
        free(mem->response);
        mem->response = NULL;
        mem->size = 0;
    }
}

/* For stack-allocated struct memory - most common case */
#define AUTO_CLEANUP_RESPONSE __attribute__((cleanup(memory_struct_cleanup)))

/* For sensitive data that should be zeroed before free */
static void __attribute__((unused)) memory_secure_cleanup(struct memory *mem) {
    if (mem && mem->response) {
        memset(mem->response, 0, mem->size);
        free(mem->response);
        mem->response = NULL;
        mem->size = 0;
    }
}

/* For responses containing tokens/secrets */
#define AUTO_CLEANUP_RESPONSE_SECURE __attribute__((cleanup(memory_secure_cleanup)))

/* Auto-cleanup for allocated strings (uri, json_body, etc.) */
static void __attribute__((unused)) string_cleanup(char **str) {
    if (str && *str) {
        free(*str);
        *str = NULL;
    }
}

#define AUTO_FREE_STRING __attribute__((cleanup(string_cleanup)))

/* For strings containing sensitive data */
static void __attribute__((unused)) string_secure_cleanup(char **str) {
    if (str && *str) {
        memset(*str, 0, strlen(*str));
        free(*str);
        *str = NULL;
    }
}

#define AUTO_FREE_STRING_SECURE __attribute__((cleanup(string_secure_cleanup)))

/*
 * =============================================================================
 * Keycloak Endpoint Builders
 * =============================================================================
 * These functions allocate and return endpoint URLs. Caller must free().
 */

/* Token endpoint: /realms/{realm}/protocol/openid-connect/token */
static char *
kc_build_token_endpoint(struct kc_realm realm)
{
    static const char tmpl[] = "%s/realms/%s/protocol/openid-connect/token";
    if (!realm.base_uri || !realm.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm);
    return uri;
}

/* Introspect endpoint: /realms/{realm}/protocol/openid-connect/token/introspect */
static char *
kc_build_introspect_endpoint(struct kc_realm realm)
{
    static const char tmpl[] = "%s/realms/%s/protocol/openid-connect/token/introspect";
    if (!realm.base_uri || !realm.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm);
    return uri;
}

/* Users admin endpoint: /admin/realms/{realm}/users */
static char *
kc_build_users_endpoint(struct kc_realm realm)
{
    static const char tmpl[] = "%s/admin/realms/%s/users";
    if (!realm.base_uri || !realm.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm);
    return uri;
}

/* User admin endpoint: /admin/realms/{realm}/users/{user_id} */
static char *
kc_build_user_endpoint(struct kc_realm realm, const char *user_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/%s";
    if (!realm.base_uri || !realm.realm || !user_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, user_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, user_id);
    return uri;
}

/* Groups admin endpoint: /admin/realms/{realm}/groups */
static char *
kc_build_groups_endpoint(struct kc_realm realm)
{
    static const char tmpl[] = "%s/admin/realms/%s/groups";
    if (!realm.base_uri || !realm.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm);
    return uri;
}

/* Group admin endpoint: /admin/realms/{realm}/groups/{group_id} */
static char *
kc_build_group_endpoint(struct kc_realm realm, const char *group_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/groups/%s";
    if (!realm.base_uri || !realm.realm || !group_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, group_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, group_id);
    return uri;
}

/* User's group membership endpoint: /admin/realms/{realm}/users/{user_id}/groups/{group_id} */
static char *
kc_build_user_group_endpoint(struct kc_realm realm, const char *user_id, const char *group_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/%s/groups/%s";
    if (!realm.base_uri || !realm.realm || !user_id || !group_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, user_id, group_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, user_id, group_id);
    return uri;
}

/* Group members endpoint: /admin/realms/{realm}/groups/{group_id}/members */
static char *
kc_build_group_members_endpoint(struct kc_realm realm, const char *group_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/groups/%s/members?max=1000";
    if (!realm.base_uri || !realm.realm || !group_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, group_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, group_id);
    return uri;
}

/* Group children (subgroups) endpoint: /admin/realms/{realm}/groups/{parent_id}/children */
static char *
kc_build_group_children_endpoint(struct kc_realm realm, const char *parent_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/groups/%s/children";
    if (!realm.base_uri || !realm.realm || !parent_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, parent_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, parent_id);
    return uri;
}

/* Group-by-path endpoint: /admin/realms/{realm}/group-by-path{path} (path includes leading /) */
static char *
kc_build_group_by_path_endpoint(struct kc_realm realm, const char *path)
{
    static const char tmpl[] = "%s/admin/realms/%s/group-by-path%s";
    if (!realm.base_uri || !realm.realm || !path) return NULL;

    /* URL-encode the path - especially important for # which is a URL fragment delimiter */
    char *encoded_path = curl_easy_escape(NULL, path, 0);
    if (!encoded_path) {
        log_module(KC_LOG, LOG_ERROR, "kc_build_group_by_path_endpoint: curl_easy_escape returned NULL for '%s'", path);
        return NULL;
    }

    log_module(KC_LOG, LOG_DEBUG, "kc_build_group_by_path_endpoint: BEFORE %%2F fix: raw='%s'", encoded_path);

    /* curl_easy_escape encodes / as %2F, but we need literal slashes in the path */
    /* Replace %2F back to / for path separators */
    char *p = encoded_path;
    char *w = encoded_path;
    while (*p) {
        if (p[0] == '%' && p[1] == '2' && (p[2] == 'F' || p[2] == 'f')) {
            *w++ = '/';
            p += 3;
        } else {
            *w++ = *p++;
        }
    }
    *w = '\0';

    log_module(KC_LOG, LOG_DEBUG, "kc_build_group_by_path_endpoint: AFTER %%2F fix: encoded='%s'", encoded_path);

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, encoded_path) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, encoded_path);

    log_module(KC_LOG, LOG_DEBUG, "kc_build_group_by_path_endpoint: FINAL uri='%s'", uri ? uri : "(null)");

    curl_free(encoded_path);
    return uri;
}

/* User search endpoint: /admin/realms/{realm}/users?{query} */
static __attribute__((unused)) char *
kc_build_user_search_endpoint(struct kc_realm realm, const char *query)
{
    static const char tmpl[] = "%s/admin/realms/%s/users?%s";
    if (!realm.base_uri || !realm.realm || !query) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, query) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, query);
    return uri;
}

/* Reset password endpoint: /admin/realms/{realm}/users/{user_id}/reset-password */
static char *
kc_build_reset_password_endpoint(struct kc_realm realm, const char *user_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/%s/reset-password";
    if (!realm.base_uri || !realm.realm || !user_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, user_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, user_id);
    return uri;
}

/* Credentials endpoint for hash import: /admin/realms/{realm}/users/{user_id}/credentials */
static __attribute__((unused)) char *
kc_build_credentials_endpoint(struct kc_realm realm, const char *user_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/%s/credentials";
    if (!realm.base_uri || !realm.realm || !user_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, user_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, user_id);
    return uri;
}

/* JWKS endpoint: /realms/{realm}/protocol/openid-connect/certs */
static char *
kc_build_jwks_endpoint(struct kc_realm realm)
{
    static const char tmpl[] = "%s/realms/%s/protocol/openid-connect/certs";
    if (!realm.base_uri || !realm.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm);
    return uri;
}

/* Fingerprint search endpoint: /admin/realms/{realm}/users?q=x509_fingerprints:{fp} */
static char *
kc_build_fingerprint_search_endpoint(struct kc_realm realm, const char *escaped_fingerprint)
{
    static const char tmpl[] = "%s/admin/realms/%s/users?q=x509_fingerprints:%s";
    if (!realm.base_uri || !realm.realm || !escaped_fingerprint) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, escaped_fingerprint) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, escaped_fingerprint);
    return uri;
}

/* User lookup by username: /admin/realms/{realm}/users/?username={user}&exact=true */
static char *
kc_build_user_by_username_endpoint(struct kc_realm realm, const char *escaped_username, int exact)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/?username=%s%s";
    static const char exact_suffix[] = "&exact=true";
    if (!realm.base_uri || !realm.realm || !escaped_username) return NULL;

    const char *suffix = exact ? exact_suffix : "";
    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, escaped_username, suffix) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, escaped_username, suffix);
    return uri;
}

/* Group search by name: /admin/realms/{realm}/groups?search={name}&exact=true */
static char *
kc_build_group_search_endpoint(struct kc_realm realm, const char *escaped_name)
{
    static const char tmpl[] = "%s/admin/realms/%s/groups?search=%s&exact=true";
    if (!realm.base_uri || !realm.realm || !escaped_name) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, escaped_name) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, escaped_name);
    return uri;
}

/* Apply curl_opts to a CURL handle (shared by sync and async) */
static int
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

/*
 * =============================================================================
 * Async HTTP Infrastructure (libkc bridge)
 * =============================================================================
 */

/* Async request types */
enum kc_async_type {
    KC_ASYNC_AUTH,          /* Password authentication */
    KC_ASYNC_FINGERPRINT,   /* Certificate fingerprint lookup */
    KC_ASYNC_INTROSPECT,    /* Token introspection */
    KC_ASYNC_SET_ATTR,      /* Set user attribute */
    KC_ASYNC_GROUP_ADD,     /* Add user to group */
    KC_ASYNC_GROUP_REMOVE,  /* Remove user from group */
    KC_ASYNC_CREATE_USER,   /* User creation */
    KC_ASYNC_GROUP_INFO,    /* Get group info (phase 1 of group members) */
    KC_ASYNC_GROUP_MEMBERS, /* Get group members (phase 2 or standalone) */
    KC_ASYNC_CLIENT_TOKEN,  /* Client credentials token acquisition */
    KC_ASYNC_GET_USER,      /* Get user by username (Phase 3) */
    KC_ASYNC_UPDATE_USER,   /* Update user representation (Phase 3) - PUT phase */
    KC_ASYNC_UPDATE_USER_GET, /* Update user representation (Phase 3) - GET phase (cache miss) */
    KC_ASYNC_GET_GROUP_PATH,/* Get group by path (Phase 4) */
    KC_ASYNC_CREATE_SUBGROUP,/* Create subgroup (Phase 4) */
    KC_ASYNC_SET_GROUP_ATTR, /* Set group attribute (Phase 4) - PUT phase */
    KC_ASYNC_SET_GROUP_ATTR_GET, /* Set group attribute (Phase 4) - GET phase */
    KC_ASYNC_GET_GROUP_NAME, /* Get group by name (Phase 5 sync cleanup) */
    KC_ASYNC_DELETE_GROUP,   /* Delete group (Phase 5 sync cleanup) */
    KC_ASYNC_DELETE_USER,    /* Delete user (Phase 5.10) */
    KC_ASYNC_LIST_ATTRS,     /* List user attributes (Phase 5.10) */
    KC_ASYNC_GET_ATTR,       /* Get user attribute (Phase 5.10) */
    KC_ASYNC_SET_USER_ATTR_GET, /* GET user before attribute update (cache miss case) */
    KC_ASYNC_COALESCE_GET    /* GET user before coalesced attribute update (cache miss) */
};

/* Async request tracking */
struct kc_async_request {
    void *session;                /* Opaque session pointer (SASLSession) */
    struct memory response;       /* Response buffer */
    char *uri;                    /* Allocated URL */
    char *post_fields;            /* Allocated POST data */
    char *request_id;             /* Optional: for log correlation (allocated copy) */
    struct curl_slist *header_list;  /* HTTP headers (must free on completion) */
    enum kc_async_type type;      /* Request type for result parsing */
    union {
        kc_async_callback auth;   /* Auth callback */
        kc_async_callback generic;/* Generic success/failure callback */
        kc_fingerprint_callback fingerprint;  /* Fingerprint callback */
        kc_introspect_callback introspect;    /* Introspect callback */
        kc_group_info_callback group_info;    /* Group info callback */
        kc_group_members_callback group_members; /* Group members callback */
        kc_client_token_callback client_token;   /* Client token callback */
        kc_get_user_callback get_user;           /* Get user callback (Phase 3) */
        kc_update_user_callback update_user;     /* Update user callback (Phase 3) */
        kc_get_group_path_callback get_group_path; /* Get group by path callback (Phase 4) */
        kc_create_subgroup_callback create_subgroup; /* Create subgroup callback (Phase 4) */
        kc_get_group_path_callback get_group_name; /* Get group by name callback (reuses same signature) */
        kc_async_callback delete_group; /* Delete group callback (simple result) */
        kc_async_callback delete_user;  /* Delete user callback (simple result) */
        kc_list_attrs_callback list_attrs; /* List attributes callback (Phase 5.10) */
        kc_get_attr_callback get_attr;     /* Get attribute callback (Phase 5.10) */
    } cb;
    /* WebPush-specific: copy of binary POST data for async request */
    void *post_data_copy;
    size_t post_data_len;
    /* Timeout tracking (Phase 5.3) */
    time_t started;               /* When request was initiated */
    /* User ID cache support (for KC_ASYNC_CREATE_USER) */
    char *create_username;        /* Username being created (for cache population) */
    char location_header[256];    /* Captured Location header from 201 response */
    /* Attribute operations (Phase 5.10) */
    char *attr_prefix;            /* For KC_ASYNC_LIST_ATTRS - prefix filter (allocated) */
    char *attr_name;              /* For KC_ASYNC_GET_ATTR - attribute name (allocated) */
    /* Group attribute operations (GET-then-PUT flow) */
    char *group_attr_value;       /* For KC_ASYNC_SET_GROUP_ATTR_GET - value to set (allocated) */
    char *group_id;               /* For KC_ASYNC_SET_GROUP_ATTR_GET - group ID (allocated) */
    /* User attribute operations (GET-then-PUT flow for cache miss) */
    char *user_attr_name;         /* For KC_ASYNC_SET_USER_ATTR_GET - attribute name (allocated) */
    char *user_attr_value;        /* For KC_ASYNC_SET_USER_ATTR_GET - attribute value (allocated, NULL=delete) */
    char *user_id_copy;           /* For KC_ASYNC_SET_USER_ATTR_GET - user ID for PUT phase (allocated) */
    struct kc_realm realm_copy;   /* For KC_ASYNC_SET_USER_ATTR_GET - realm config copy */
    struct kc_client client_copy; /* For KC_ASYNC_SET_USER_ATTR_GET - client config copy (access_token borrowed) */
    char *bearer_token_copy;      /* Owned copy of bearer token for async request lifetime */
    /* User representation update (GET-then-PUT flow for KC_ASYNC_UPDATE_USER_GET) */
    char *update_email;           /* Email to update (allocated, NULL = no change) */
    char *update_username;        /* Username for credential updates (allocated) */
    char *update_cred_data;       /* Credential data JSON (allocated, NULL = no change) */
    char *update_secret_data;     /* Secret data JSON (allocated, NULL = no change) */
    /* Retry logic for transient errors (5xx, 429, connection errors) */
    int retry_count;              /* Current retry attempt (0 = first try) */
    int max_retries;              /* Maximum retries for this request (default: 2) */
    /* Coalescing support - pointer to pending update (owned by coalesce subsystem) */
    struct kc_pending_user_update *coalesce_pending;
};

/* Forward declaration for curl_perform_async (used in dispatch handler) */
static int curl_perform_async(struct kc_async_request *req, struct curl_opts opts);

/* Header callback to capture Location header from HTTP 201 response */
static size_t
kc_header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
    size_t realsize = size * nitems;
    struct kc_async_request *req = (struct kc_async_request *)userdata;

    /* Look for "Location:" header */
    if (realsize > 10 && strncasecmp(buffer, "Location:", 9) == 0) {
        const char *value = buffer + 9;
        /* Skip leading whitespace */
        while (*value == ' ' || *value == '\t') value++;

        /* Copy value, stripping trailing \r\n */
        size_t len = realsize - (value - buffer);
        while (len > 0 && (value[len-1] == '\r' || value[len-1] == '\n'))
            len--;

        if (len > 0 && len < sizeof(req->location_header)) {
            memcpy(req->location_header, value, len);
            req->location_header[len] = '\0';
            log_module(KC_LOG, LOG_DEBUG, "kc_header_callback: Captured Location: %s",
                       req->location_header);
        }
    }

    return realsize;
}

/* Parse fingerprint lookup response and invoke callback */
static void
kc_async_complete_fingerprint(struct kc_async_request *req, long http_code)
{
    int result = KC_ERROR;
    char *username = NULL;
    const char *req_id = req->request_id ? req->request_id : "-";

    if (http_code != 200 || !req->response.response) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async fingerprint: HTTP %ld", req_id, http_code);
        req->cb.fingerprint(req->session, result, NULL);
        return;
    }

    /* Parse JSON array response */
    json_error_t error;
    json_t *root = json_loads(req->response.response, 0, &error);
    if (!root || !json_is_array(root)) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async fingerprint: Invalid JSON response", req_id);
        if (root) json_decref(root);
        req->cb.fingerprint(req->session, KC_ERROR, NULL);
        return;
    }

    size_t count = json_array_size(root);
    if (count == 0) {
        result = KC_NOT_FOUND;
        log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async fingerprint: Not found", req_id);
    } else if (count > 1) {
        result = KC_COLLISION;
        log_module(KC_LOG, LOG_ERROR, "[%s] SECURITY: Fingerprint collision - %zu users!", req_id, count);
    } else {
        /* Exactly one user - extract username */
        json_t *user = json_array_get(root, 0);
        const char *uname = json_string_value(json_object_get(user, "username"));
        if (uname) {
            username = strdup(uname);
            result = KC_SUCCESS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async fingerprint: Found '%s'", req_id, username);
        }
    }

    json_decref(root);
    req->cb.fingerprint(req->session, result, username);
}

/* Parse token introspection response and invoke callback */
static void
kc_async_complete_introspect(struct kc_async_request *req, long http_code)
{
    struct kc_token_info *token_info = NULL;
    const char *req_id = req->request_id ? req->request_id : "-";

    if (http_code != 200 || !req->response.response) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async introspect: HTTP %ld", req_id, http_code);
        req->cb.introspect(req->session, KC_ERROR, NULL);
        return;
    }

    /* Parse JSON response */
    json_error_t error;
    json_t *root = json_loads(req->response.response, 0, &error);
    if (!root) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async introspect: Invalid JSON", req_id);
        req->cb.introspect(req->session, KC_ERROR, NULL);
        return;
    }

    /* Allocate and populate token_info */
    token_info = calloc(1, sizeof(*token_info));
    if (!token_info) {
        json_decref(root);
        req->cb.introspect(req->session, KC_ERROR, NULL);
        return;
    }

    token_info->active = json_is_true(json_object_get(root, "active"));

    const char *val;
    if ((val = json_string_value(json_object_get(root, "username"))))
        token_info->username = strdup(val);
    if ((val = json_string_value(json_object_get(root, "sub"))))
        token_info->sub = strdup(val);

    json_decref(root);

    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async introspect: active=%d, username=%s",
               req_id, token_info->active, token_info->username ? token_info->username : "(null)");

    req->cb.introspect(req->session, KC_SUCCESS, token_info);
}

/* Async retry configuration */
#define KC_ASYNC_MAX_RETRIES 2
#define KC_ASYNC_RETRY_BASE_DELAY_SEC 1

/* Forward declarations for retry logic */
static void kc_async_retry_cb(void *data);
static void kc_async_request_cleanup(struct kc_async_request *req);

/* Schedule a retry for an async request using timeq */
static int
kc_async_schedule_retry(struct kc_async_request *req)
{
    const char *req_id = req->request_id ? req->request_id : "-";

    /* Use default max_retries if not explicitly set */
    int max_retries = req->max_retries > 0 ? req->max_retries : KC_ASYNC_MAX_RETRIES;

    if (req->retry_count >= max_retries) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async: Max retries (%d) exceeded",
                   req_id, max_retries);
        return 0;  /* Max retries exceeded */
    }

    req->retry_count++;

    /* Exponential backoff: 1s, 2s, 4s... */
    int delay_sec = KC_ASYNC_RETRY_BASE_DELAY_SEC * (1 << (req->retry_count - 1));
    time_t retry_time = now + delay_sec;

    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async: Scheduling retry %d/%d in %ds",
               req_id, req->retry_count, req->max_retries, delay_sec);

    timeq_add(retry_time, kc_async_retry_cb, req);
    return 1;  /* Retry scheduled */
}

/* Callback fired by timeq to retry an async request */
static void
kc_async_retry_cb(void *data)
{
    struct kc_async_request *req = data;
    const char *req_id = req->request_id ? req->request_id : "-";

    if (!x3_kc_bridge_is_ready()) {
        log_module(KC_LOG, LOG_ERROR, "[%s] kc_async retry: bridge not initialized", req_id);
        if (req->cb.generic)
            req->cb.generic(req->session, KC_ERROR);
        kc_async_request_cleanup(req);
        return;
    }

    /* Reset response buffer for retry */
    if (req->response.response) {
        free(req->response.response);
        req->response.response = NULL;
        req->response.size = 0;
    }

    /* Reset timing */
    req->started = time(NULL);

    int max_retries = req->max_retries > 0 ? req->max_retries : KC_ASYNC_MAX_RETRIES;
    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async: Executing retry %d/%d",
               req_id, req->retry_count, max_retries);

    /* Re-submit through bridge using stored URI and fields */
    int rc = x3_kc_bridge_submit(
        req->uri, NULL /* bridge will default to GET */,
        req->post_fields, req->post_fields ? strlen(req->post_fields) : 0,
        req->header_list,
        req->bearer_token_copy,
        NULL, NULL,
        kc_async_bridge_complete, req);

    if (rc != 0) {
        log_module(KC_LOG, LOG_ERROR, "[%s] kc_async retry: bridge submit failed", req_id);
        if (req->cb.generic)
            req->cb.generic(req->session, KC_ERROR);
        kc_async_request_cleanup(req);
    }
}

/* Cleanup an async request - frees all allocated resources */
static void
kc_async_request_cleanup(struct kc_async_request *req)
{
    if (!req) return;

    /* No curl handle to manage — bridge owns the HTTP lifecycle */

    /* Free response buffer (securely zero first) */
    if (req->response.response) {
        memset(req->response.response, 0, req->response.size);
        free(req->response.response);
    }

    /* Free allocated strings - use pool_strfree for strings that may be pooled */
    if (req->uri) free(req->uri);  /* URIs are typically long, not pooled */
    if (req->post_fields) {
        memset(req->post_fields, 0, strlen(req->post_fields));  /* Zero sensitive data */
        free(req->post_fields);
    }
    if (req->post_data_copy) free(req->post_data_copy);  /* Binary data, not pooled */
    if (req->header_list) curl_slist_free_all(req->header_list);
    pool_strfree(req->request_id);
    pool_strfree(req->create_username);
    pool_strfree(req->attr_prefix);
    pool_strfree(req->attr_name);
    pool_strfree(req->user_attr_name);
    pool_strfree(req->user_attr_value);
    pool_strfree(req->user_id_copy);
    if (req->bearer_token_copy) free(req->bearer_token_copy);  /* JWT tokens are long */
    pool_strfree(req->group_attr_value);
    pool_strfree(req->group_id);
    /* User representation update fields */
    pool_strfree(req->update_email);
    pool_strfree(req->update_username);
    if (req->update_cred_data) {
        memset(req->update_cred_data, 0, strlen(req->update_cred_data));
        free(req->update_cred_data);
    }
    if (req->update_secret_data) {
        memset(req->update_secret_data, 0, strlen(req->update_secret_data));
        free(req->update_secret_data);
    }

    free(req);
}

/*
 * Handle the result of an async HTTP request.
 * Called from the libkc bridge completion path (kc_async_bridge_complete).
 *
 * This contains the stats recording, retry logic, type dispatch switch,
 * and cleanup.
 */
static void
kc_async_handle_result(struct kc_async_request *req, long http_code,
                        int curl_failed, unsigned long latency_ms)
{
    const char *req_id = req->request_id ? req->request_id : "-";

    /* Check elapsed time */
    if (req->started > 0) {
        time_t elapsed = time(NULL) - req->started;
        if (elapsed >= 5) {
            log_module(KC_LOG, LOG_WARNING, "[%s] kc_async: Request took %ld seconds (type=%d)",
                       req_id, (long)elapsed, req->type);
        }
    }

    /* Record async request stats */
    int is_error = (curl_failed || http_code >= 500);
    kc_stats_record_request(latency_ms, is_error);

    /* Log slow async requests */
    if (latency_ms > 1000) {
        log_module(KC_LOG, LOG_INFO, "[%s] Async request slow: %lu ms (HTTP %ld, type=%d)",
                   req_id, latency_ms, http_code, req->type);
    }

    /* Check for retryable errors */
    if (curl_failed || http_code >= 500 || http_code == 429) {
        /* Only retry certain operation types */
        int should_retry = 0;
        switch (req->type) {
        case KC_ASYNC_SET_ATTR:
        case KC_ASYNC_GROUP_ADD:
        case KC_ASYNC_GROUP_REMOVE:
        case KC_ASYNC_CREATE_USER:
        case KC_ASYNC_DELETE_USER:
        case KC_ASYNC_UPDATE_USER:
        case KC_ASYNC_UPDATE_USER_GET:
        case KC_ASYNC_GET_USER:
        case KC_ASYNC_SET_USER_ATTR_GET:
        case KC_ASYNC_SET_GROUP_ATTR:
        case KC_ASYNC_SET_GROUP_ATTR_GET:
        case KC_ASYNC_GET_GROUP_PATH:
        case KC_ASYNC_GET_GROUP_NAME:
        case KC_ASYNC_CREATE_SUBGROUP:
        case KC_ASYNC_DELETE_GROUP:
        case KC_ASYNC_LIST_ATTRS:
        case KC_ASYNC_GET_ATTR:
        case KC_ASYNC_GROUP_INFO:
        case KC_ASYNC_GROUP_MEMBERS:
        case KC_ASYNC_COALESCE_GET:
            should_retry = 1;
            break;
        default:
            break;
        }

        if (should_retry && kc_async_schedule_retry(req))
            return;  /* Retry scheduled, don't dispatch yet */
    }

    /* === DISPATCH BY TYPE === */
    switch (req->type) {
    case KC_ASYNC_AUTH: {
        int result = KC_ERROR;
        if (http_code == 200) {
            result = KC_SUCCESS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async auth: Success (HTTP 200)", req_id);
        } else if (http_code == 401) {
            result = KC_FORBIDDEN;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async auth: Failed (HTTP 401)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async auth: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.auth) {
            req->cb.auth(req->session, result);
        }
        break;
    }
    case KC_ASYNC_FINGERPRINT:
        kc_async_complete_fingerprint(req, http_code);
        break;
    case KC_ASYNC_INTROSPECT:
        kc_async_complete_introspect(req, http_code);
        break;
    case KC_ASYNC_SET_ATTR: {
        int result = KC_ERROR;
        if (http_code == 204 || http_code == 200) {
            result = KC_SUCCESS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async set_attr: Success (HTTP %ld)", req_id, http_code);
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async set_attr: Not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async set_attr: Error (HTTP %ld)", req_id, http_code);
        }
        /* If this came from coalescing, invoke all pending callbacks */
        if (req->coalesce_pending) {
            kc_pending_invoke_all_callbacks(req->coalesce_pending, result);
            kc_pending_update_free(req->coalesce_pending);
            req->coalesce_pending = NULL;
        } else if (req->cb.generic) {
            req->cb.generic(req->session, result);
        }
        break;
    }
    case KC_ASYNC_GROUP_ADD:
    case KC_ASYNC_GROUP_REMOVE: {
        int result = KC_ERROR;
        if (http_code == 204 || http_code == 200) {
            result = KC_SUCCESS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group: Success (HTTP %ld)", req_id, http_code);
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group: Not found (HTTP 404)", req_id);
        } else if (http_code == 409) {
            /* Conflict - user already in/not in group */
            result = KC_SUCCESS;  /* Treat as success for idempotency */
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group: Conflict (HTTP 409), treating as success", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.generic) {
            req->cb.generic(req->session, result);
        }
        break;
    }
    case KC_ASYNC_CREATE_USER: {
        int result = KC_ERROR;
        if (http_code == 201) {
            result = KC_SUCCESS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_user: User created (HTTP 201)", req_id);

            /* Cache user ID from Location header for subsequent operations */
            if (req->create_username && req->location_header[0]) {
                /* Location format: .../users/{user-id} - extract last path segment */
                const char *user_id = strrchr(req->location_header, '/');
                if (user_id && user_id[1]) {
                    user_id++;  /* Skip the '/' */
                    kc_userid_cache_put(req->create_username, user_id);
                }
            }
        } else if (http_code == 409) {
            result = KC_USER_EXISTS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_user: User exists (HTTP 409)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_user: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.generic) {
            req->cb.generic(req->session, result);
        }
        break;
    }
    case KC_ASYNC_GROUP_INFO: {
        int result = KC_ERROR;
        struct kc_group_info *info = NULL;

        if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group_info: Not found (HTTP 404)", req_id);
        } else if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *root = json_loads(req->response.response, 0, &error);
            if (root && json_is_object(root)) {
                info = calloc(1, sizeof(*info));
                if (info) {
                    json_t *jid = json_object_get(root, "id");
                    json_t *jname = json_object_get(root, "name");
                    json_t *jpath = json_object_get(root, "path");
                    json_t *jattrs = json_object_get(root, "attributes");

                    if (jid && json_is_string(jid))
                        info->id = strdup(json_string_value(jid));
                    if (jname && json_is_string(jname))
                        info->name = strdup(json_string_value(jname));
                    if (jpath && json_is_string(jpath))
                        info->path = strdup(json_string_value(jpath));

                    /* Parse x3_access_level attribute */
                    if (jattrs && json_is_object(jattrs)) {
                        json_t *level_arr = json_object_get(jattrs, "x3_access_level");
                        if (level_arr && json_is_array(level_arr) && json_array_size(level_arr) > 0) {
                            json_t *level_val = json_array_get(level_arr, 0);
                            if (level_val && json_is_string(level_val)) {
                                info->access_level = (unsigned short)atoi(json_string_value(level_val));
                            }
                        }
                    }
                    result = KC_SUCCESS;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group_info: Success (level=%d)",
                               req_id, info->access_level);
                }
                json_decref(root);
            } else {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group_info: JSON parse error", req_id);
            }
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group_info: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.group_info) {
            req->cb.group_info(req->session, result, info);
        }
        break;
    }
    case KC_ASYNC_GROUP_MEMBERS: {
        int result = KC_ERROR;
        struct kc_group_member *members = NULL;
        int member_count = 0;

        if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group_members: Not found (HTTP 404)", req_id);
        } else if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *root = json_loads(req->response.response, 0, &error);
            if (root && json_is_array(root)) {
                struct kc_group_member *tail = NULL;
                size_t array_size = json_array_size(root);

                for (size_t i = 0; i < array_size; i++) {
                    json_t *user_obj = json_array_get(root, i);
                    json_t *jid = json_object_get(user_obj, "id");
                    json_t *jusername = json_object_get(user_obj, "username");

                    if (jid && json_is_string(jid) &&
                        jusername && json_is_string(jusername)) {
                        struct kc_group_member *member = calloc(1, sizeof(*member));
                        if (member) {
                            member->user_id = strdup(json_string_value(jid));
                            member->username = strdup(json_string_value(jusername));
                            member->next = NULL;

                            if (!member->user_id || !member->username) {
                                if (member->user_id) free(member->user_id);
                                if (member->username) free(member->username);
                                free(member);
                                continue;
                            }

                            if (!members) {
                                members = member;
                                tail = member;
                            } else {
                                tail->next = member;
                                tail = member;
                            }
                            member_count++;
                        }
                    }
                }
                result = member_count;
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group_members: Found %d members",
                           req_id, member_count);
                json_decref(root);
            } else {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group_members: JSON parse error", req_id);
            }
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async group_members: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.group_members) {
            req->cb.group_members(req->session, result, members);
        }
        break;
    }
    case KC_ASYNC_CLIENT_TOKEN: {
        int result = KC_TOKEN_ERROR;
        struct access_token *token = NULL;

        if (http_code == 200 && req->response.response) {
            if (json_read_kc_access_token(req->response.response, &token) == KC_SUCCESS) {
                result = KC_SUCCESS;
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async client_token: Success (HTTP 200)", req_id);
            } else {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async client_token: JSON parse error", req_id);
            }
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async client_token: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.client_token) {
            req->cb.client_token(req->session, result, token);
            /* Note: token ownership transferred to callback */
        } else if (token) {
            keycloak_free_access_token(token);
        }
        break;
    }
    case KC_ASYNC_GET_USER: {
        int result = KC_ERROR;
        struct kc_user user = {0};

        if (http_code == 200 && req->response.response) {
            /* Parse JSON array response (same format as keycloak_get_users) */
            json_error_t error;
            json_t *root = json_loads(req->response.response, 0, &error);
            if (root && json_is_array(root)) {
                size_t count = json_array_size(root);
                if (count == 0) {
                    result = KC_NOT_FOUND;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_user: Not found", req_id);
                } else if (count == 1) {
                    json_t *user_obj = json_array_get(root, 0);
                    if (json_read_kc_user(user_obj, &user) == KC_SUCCESS) {
                        result = KC_SUCCESS;
                        /* Cache user ID for future lookups */
                        if (user.username && user.id) {
                            kc_userid_cache_put(user.username, user.id);
                        }
                        log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_user: Found user %s", req_id, user.username);
                    }
                } else {
                    log_module(KC_LOG, LOG_WARNING, "[%s] kc_async get_user: Multiple users found (%zu)", req_id, count);
                    result = KC_ERROR;
                }
                json_decref(root);
            } else {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_user: Invalid JSON", req_id);
                if (root) json_decref(root);
            }
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_user: Not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_user: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.get_user) {
            req->cb.get_user(req->session, result, result == KC_SUCCESS ? &user : NULL);
        }
        /* Free user fields if callback didn't take ownership or there was an error */
        if (result != KC_SUCCESS) {
            keycloak_user_free_fields(&user);
        }
        break;
    }
    case KC_ASYNC_UPDATE_USER: {
        int result = KC_ERROR;
        if (http_code == 204 || http_code == 200) {
            result = KC_SUCCESS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async update_user: Success (HTTP %ld)", req_id, http_code);
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async update_user: Not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async update_user: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.update_user) {
            req->cb.update_user(req->session, result);
        }
        break;
    }
    case KC_ASYNC_UPDATE_USER_GET: {
        /* GET phase completed for user representation update.
         * Merge updates into full representation and issue PUT. */
        int result = KC_ERROR;

        if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *repr = json_loads(req->response.response, 0, &error);
            if (repr) {
                /* Strip credentials from GET response - they should not be in PUT
                 * as Keycloak treats credentials in PUT as "add" not "replace" */
                json_object_del(repr, "credentials");

                /* Merge email if provided */
                if (req->update_email) {
                    json_object_set_new(repr, "email", json_string(req->update_email));
                }

                /* Cache the merged representation AFTER merging email.
                 * This ensures subsequent operations have the email.
                 * kc_user_repr_cache_put already strips credentials. */
                json_t *id_json = json_object_get(repr, "id");
                if (id_json && json_is_string(id_json)) {
                    kc_user_repr_cache_put(json_string_value(id_json), repr);
                }

                /* Add credentials if provided - only for PUT, not for cache */
                if (req->update_cred_data && req->update_secret_data) {
                    json_t *cred = json_object();
                    json_object_set_new(cred, "type", json_string("password"));
                    json_object_set_new(cred, "credentialData", json_string(req->update_cred_data));
                    json_object_set_new(cred, "secretData", json_string(req->update_secret_data));
                    json_object_set_new(cred, "temporary", json_false());

                    json_t *creds = json_array();
                    json_array_append_new(creds, cred);
                    json_object_set_new(repr, "credentials", creds);
                }

                /* Serialize merged representation for PUT */
                char *json_body = json_dumps(repr, JSON_COMPACT);
                json_decref(repr);

                if (json_body) {
                    /* Build PUT request */
                    struct kc_async_request *put_req = calloc(1, sizeof(*put_req));
                    if (put_req) {
                        put_req->session = req->session;
                        put_req->type = KC_ASYNC_UPDATE_USER;
                        put_req->cb.update_user = req->cb.update_user;
                        put_req->uri = strdup(req->uri);  /* Same URI for PUT */
                        put_req->post_fields = json_body;

                        /* Get fresh bearer token for PUT */
                        if (kc_token_mgr.token && kc_token_mgr.token->access_token) {
                            put_req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
                        }

                        if (put_req->uri && put_req->bearer_token_copy) {
                            struct curl_opts opts = CURL_OPTS_INIT;
                            opts.uri = put_req->uri;
                            opts.method = HTTP_PUT;
                            opts.post_fields = put_req->post_fields;
                            opts.xoauth2_bearer = put_req->bearer_token_copy;
                            opts.header_list[0] = "Content-Type: application/json";
                            opts.header_count = 1;

                            if (curl_perform_async(put_req, opts) == 0) {
                                log_module(KC_LOG, LOG_DEBUG,
                                           "[%s] kc_async update_user_get: GET succeeded, issued PUT with merged repr",
                                           req_id);
                                result = KC_SUCCESS;
                                /* Clear callback in original req - PUT will call it */
                                req->cb.update_user = NULL;
                            } else {
                                log_module(KC_LOG, LOG_ERROR,
                                           "[%s] kc_async update_user_get: Failed to start PUT", req_id);
                                free(put_req->uri);
                                free(put_req->bearer_token_copy);
                                free(json_body);
                                free(put_req);
                            }
                        } else {
                            log_module(KC_LOG, LOG_ERROR,
                                       "[%s] kc_async update_user_get: Failed to prepare PUT request", req_id);
                            if (put_req->uri) free(put_req->uri);
                            if (put_req->bearer_token_copy) free(put_req->bearer_token_copy);
                            free(json_body);
                            free(put_req);
                        }
                    } else {
                        free(json_body);
                    }
                }
            } else {
                log_module(KC_LOG, LOG_ERROR,
                           "[%s] kc_async update_user_get: Invalid JSON: %s", req_id, error.text);
            }
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG,
                       "[%s] kc_async update_user_get: User not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_ERROR,
                       "[%s] kc_async update_user_get: GET failed (HTTP %ld)", req_id, http_code);
        }

        /* On error, call callback. On success, PUT will call callback. */
        if (result != KC_SUCCESS && req->cb.update_user) {
            req->cb.update_user(req->session, result);
        }
        break;
    }
    case KC_ASYNC_GET_GROUP_PATH: {
        int result = KC_ERROR;
        char *group_id = NULL;

        if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_group_path: Not found (HTTP 404)", req_id);
        } else if (http_code == 200 && req->response.response) {
            /* Parse JSON response to get group ID */
            json_error_t error;
            json_t *root = json_loads(req->response.response, 0, &error);
            if (root) {
                const char *id = json_string_value(json_object_get(root, "id"));
                if (id) {
                    group_id = pool_strdup(id);
                    result = KC_SUCCESS;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_group_path: Found group %s", req_id, group_id);
                }
                json_decref(root);
            }
            if (result != KC_SUCCESS) {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_group_path: Failed to parse response", req_id);
            }
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_group_path: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.get_group_path) {
            req->cb.get_group_path(req->session, result, group_id);
            /* Note: group_id ownership transferred to callback */
        } else if (group_id) {
            pool_strfree(group_id);
        }
        break;
    }
    case KC_ASYNC_CREATE_SUBGROUP: {
        int result = KC_ERROR;
        char *group_id = NULL;

        if (http_code == 201) {
            /* Extract group ID from Location header */
            if (req->location_header[0]) {
                /* Location header format: .../groups/{id} */
                const char *last_slash = strrchr(req->location_header, '/');
                if (last_slash && last_slash[1]) {
                    group_id = pool_strdup(last_slash + 1);
                    result = KC_SUCCESS;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_subgroup: Created group %s", req_id, group_id);
                }
            }
            if (!group_id) {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_subgroup: Created but no Location header", req_id);
                result = KC_SUCCESS;  /* Still success, just no ID */
            }
        } else if (http_code == 409) {
            result = KC_USER_EXISTS;  /* Group already exists */
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_subgroup: Group already exists", req_id);
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;  /* Parent not found */
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_subgroup: Parent not found", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_subgroup: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.create_subgroup) {
            req->cb.create_subgroup(req->session, result, group_id);
            /* Note: group_id ownership transferred to callback */
        } else if (group_id) {
            pool_strfree(group_id);
        }
        break;
    }
    case KC_ASYNC_SET_GROUP_ATTR: {
        int result = KC_ERROR;
        if (http_code == 204 || http_code == 200) {
            result = KC_SUCCESS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async set_group_attr: Success (HTTP %ld)", req_id, http_code);
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async set_group_attr: Not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async set_group_attr: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.generic) {
            req->cb.generic(req->session, result);
        }
        break;
    }
    case KC_ASYNC_SET_GROUP_ATTR_GET: {
        /* GET phase completed for group attribute update.
         * Merge the attribute and issue PUT with full representation. */
        int result = KC_ERROR;

        if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *repr = json_loads(req->response.response, 0, &error);
            if (repr) {
                /* Get or create attributes object */
                json_t *attrs = json_object_get(repr, "attributes");
                if (!attrs) {
                    attrs = json_object();
                    json_object_set_new(repr, "attributes", attrs);
                }

                /* Set the attribute */
                if (req->group_attr_value) {
                    json_t *attr_array = json_array();
                    json_array_append_new(attr_array, json_string(req->group_attr_value));
                    json_object_set_new(attrs, req->user_attr_name, attr_array);
                }

                /* Issue PUT with full representation */
                char *json_body = json_dumps(repr, JSON_COMPACT);
                json_decref(repr);

                if (json_body) {
                    char *put_uri = kc_build_group_endpoint(req->realm_copy, req->group_id);
                    if (put_uri) {
                        struct kc_async_request *put_req = calloc(1, sizeof(*put_req));
                        if (put_req) {
                            put_req->session = req->session;
                            put_req->type = KC_ASYNC_SET_GROUP_ATTR;
                            put_req->cb.generic = req->cb.generic;
                            put_req->uri = put_uri;
                            put_req->post_fields = json_body;

                            put_req->bearer_token_copy = strdup(req->bearer_token_copy);
                            if (!put_req->bearer_token_copy) {
                                log_module(KC_LOG, LOG_ERROR,
                                           "[%s] kc_async set_group_attr_get: Failed to copy bearer token",
                                           req_id);
                                free(put_uri);
                                free(json_body);
                                free(put_req);
                            } else {
                                struct curl_opts opts = CURL_OPTS_INIT;
                                opts.uri = put_req->uri;
                                opts.method = HTTP_PUT;
                                opts.post_fields = put_req->post_fields;
                                opts.xoauth2_bearer = put_req->bearer_token_copy;
                                opts.header_list[0] = "Content-Type: application/json";
                                opts.header_count = 1;

                                if (curl_perform_async(put_req, opts) == 0) {
                                    log_module(KC_LOG, LOG_DEBUG,
                                               "[%s] kc_async set_group_attr_get: GET succeeded, "
                                               "issued PUT with merged attributes for group %s",
                                               req_id, req->group_id);
                                    result = KC_SUCCESS;
                                } else {
                                    log_module(KC_LOG, LOG_ERROR,
                                               "[%s] kc_async set_group_attr_get: PUT submit failed",
                                               req_id);
                                    free(put_req->bearer_token_copy);
                                    free(put_uri);
                                    free(json_body);
                                    free(put_req);
                                }
                            }
                        } else {
                            free(put_uri);
                            free(json_body);
                        }
                    } else {
                        free(json_body);
                    }
                }
            } else {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async set_group_attr_get: JSON parse error", req_id);
            }
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async set_group_attr_get: Not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async set_group_attr_get: Error (HTTP %ld)", req_id, http_code);
        }

        /* Only invoke callback on error - success means PUT is in flight */
        if (result != KC_SUCCESS && req->cb.generic) {
            req->cb.generic(req->session, result);
        }
        break;
    }
    case KC_ASYNC_GET_GROUP_NAME: {
        /* Parse group search results - returns array of groups */
        int result = KC_ERROR;
        char *group_id = NULL;

        if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *root = json_loads(req->response.response, 0, &error);
            if (root) {
                if (json_is_array(root) && json_array_size(root) > 0) {
                    json_t *first_group = json_array_get(root, 0);
                    json_t *id_val = json_object_get(first_group, "id");
                    if (id_val && json_is_string(id_val)) {
                        group_id = pool_strdup(json_string_value(id_val));
                        if (group_id) {
                            result = KC_SUCCESS;
                            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_group_name: Found group ID %s", req_id, group_id);
                        }
                    }
                } else {
                    result = KC_NOT_FOUND;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_group_name: Group not found", req_id);
                }
                json_decref(root);
            } else {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_group_name: JSON parse error: %s", req_id, error.text);
            }
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_group_name: Not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_group_name: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.get_group_name) {
            req->cb.get_group_name(req->session, result, group_id);
            /* Note: group_id ownership transferred to callback */
        } else if (group_id) {
            pool_strfree(group_id);
        }
        break;
    }
    case KC_ASYNC_DELETE_GROUP: {
        int result = KC_ERROR;
        if (http_code == 204 || http_code == 200) {
            result = KC_SUCCESS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async delete_group: Success (HTTP %ld)", req_id, http_code);
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async delete_group: Not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async delete_group: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.delete_group) {
            req->cb.delete_group(req->session, result);
        }
        break;
    }
    case KC_ASYNC_DELETE_USER: {
        int result = KC_ERROR;
        if (http_code == 204 || http_code == 200) {
            result = KC_SUCCESS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async delete_user: Success (HTTP %ld)", req_id, http_code);
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async delete_user: Not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async delete_user: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.delete_user) {
            req->cb.delete_user(req->session, result);
        }
        break;
    }
    case KC_ASYNC_LIST_ATTRS: {
        int result = KC_ERROR;
        struct kc_metadata_entry *entries = NULL;

        if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *root = json_loads(req->response.response, 0, &error);
            if (root) {
                json_t *attrs = json_object_get(root, "attributes");
                if (attrs && json_is_object(attrs)) {
                    const char *key;
                    json_t *value;
                    struct kc_metadata_entry *head = NULL;
                    struct kc_metadata_entry *tail = NULL;
                    size_t prefix_len = req->attr_prefix ? strlen(req->attr_prefix) : 0;

                    json_object_foreach(attrs, key, value) {
                        /* Skip if prefix specified and doesn't match */
                        if (req->attr_prefix && prefix_len > 0) {
                            if (strncmp(key, req->attr_prefix, prefix_len) != 0)
                                continue;
                        }

                        /* Get first value from array */
                        if (!json_is_array(value) || json_array_size(value) == 0)
                            continue;

                        json_t *first_val = json_array_get(value, 0);
                        if (!first_val || !json_is_string(first_val))
                            continue;

                        const char *val_str = json_string_value(first_val);
                        if (!val_str || !*val_str)
                            continue;

                        /* Create entry */
                        struct kc_metadata_entry *entry = malloc(sizeof(*entry));
                        if (!entry)
                            continue;

                        entry->key = strdup(key);
                        entry->value = strdup(val_str);
                        entry->next = NULL;

                        if (!entry->key || !entry->value) {
                            if (entry->key) free(entry->key);
                            if (entry->value) free(entry->value);
                            free(entry);
                            continue;
                        }

                        /* Add to list */
                        if (!head) {
                            head = tail = entry;
                        } else {
                            tail->next = entry;
                            tail = entry;
                        }
                    }

                    entries = head;
                    result = KC_SUCCESS;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async list_attrs: Success", req_id);
                } else {
                    /* No attributes object is valid - empty list */
                    result = KC_SUCCESS;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async list_attrs: No attributes on user", req_id);
                }
                json_decref(root);
            } else {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async list_attrs: Invalid JSON: %s", req_id, error.text);
            }
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async list_attrs: Not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async list_attrs: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.list_attrs) {
            req->cb.list_attrs(req->session, result, entries);
        }
        /* Note: callback owns entries on success, must free on error */
        if (result != KC_SUCCESS && entries) {
            keycloak_free_metadata_entries(entries);
        }
        break;
    }
    case KC_ASYNC_GET_ATTR: {
        int result = KC_ERROR;
        char *attr_value = NULL;

        if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *root = json_loads(req->response.response, 0, &error);
            if (root) {
                json_t *attrs = json_object_get(root, "attributes");
                if (attrs && json_is_object(attrs) && req->attr_name) {
                    json_t *attr_arr = json_object_get(attrs, req->attr_name);
                    if (attr_arr && json_is_array(attr_arr) && json_array_size(attr_arr) > 0) {
                        json_t *first_val = json_array_get(attr_arr, 0);
                        if (first_val && json_is_string(first_val)) {
                            const char *val_str = json_string_value(first_val);
                            if (val_str && *val_str) {
                                attr_value = strdup(val_str);
                                if (attr_value) {
                                    result = KC_SUCCESS;
                                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_attr: Found %s", req_id, req->attr_name);
                                }
                            }
                        }
                    }
                    if (result != KC_SUCCESS) {
                        result = KC_NOT_FOUND;
                        log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_attr: Attribute %s not found", req_id, req->attr_name);
                    }
                } else if (!attrs || !json_is_object(attrs)) {
                    result = KC_NOT_FOUND;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_attr: No attributes on user", req_id);
                }
                json_decref(root);
            } else {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_attr: Invalid JSON: %s", req_id, error.text);
            }
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_attr: User not found (HTTP 404)", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async get_attr: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.get_attr) {
            req->cb.get_attr(req->session, result, attr_value);
        }
        /* Note: callback owns attr_value on success, must free on error */
        if (result != KC_SUCCESS && attr_value) {
            free(attr_value);
        }
        break;
    }
    case KC_ASYNC_SET_USER_ATTR_GET: {
        /* GET phase completed for user attribute update (cache miss case).
         * Now merge the attribute and issue PUT with full representation. */
        int result = KC_ERROR;

        if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *repr = json_loads(req->response.response, 0, &error);
            if (repr) {
                /* Strip credentials from GET response - they should not be in PUT
                 * as Keycloak treats credentials in PUT as "add" not "replace" */
                json_object_del(repr, "credentials");

                /* Get or create attributes object */
                json_t *attrs = json_object_get(repr, "attributes");
                if (!attrs) {
                    attrs = json_object();
                    json_object_set_new(repr, "attributes", attrs);
                }

                /* Set the attribute (or remove if value is NULL) */
                if (req->user_attr_value) {
                    json_t *attr_array = json_array();
                    json_array_append_new(attr_array, json_string(req->user_attr_value));
                    json_object_set_new(attrs, req->user_attr_name, attr_array);
                } else {
                    /* NULL value = delete attribute by setting to empty array */
                    json_t *empty_array = json_array();
                    json_object_set_new(attrs, req->user_attr_name, empty_array);
                }

                /* Cache the merged representation AFTER merging attribute.
                 * kc_user_repr_cache_put already strips credentials. */
                json_t *id_json = json_object_get(repr, "id");
                if (id_json && json_is_string(id_json)) {
                    kc_user_repr_cache_put(json_string_value(id_json), repr);
                }

                /* Now issue the PUT with full representation */
                char *json_body = json_dumps(repr, JSON_COMPACT);
                json_decref(repr);

                if (json_body) {
                    /* Build PUT request */
                    char *put_uri = kc_build_user_endpoint(req->realm_copy, req->user_id_copy);
                    if (put_uri) {
                        struct kc_async_request *put_req = calloc(1, sizeof(*put_req));
                        if (put_req) {
                            put_req->session = req->session;
                            put_req->type = KC_ASYNC_SET_ATTR;
                            put_req->cb.generic = req->cb.generic;
                            put_req->uri = put_uri;
                            put_req->post_fields = json_body;

                            /* Copy bearer token for PUT request lifetime (original req will be freed) */
                            put_req->bearer_token_copy = strdup(req->bearer_token_copy);
                            if (!put_req->bearer_token_copy) {
                                log_module(KC_LOG, LOG_ERROR,
                                           "[%s] kc_async set_user_attr_get: Failed to copy bearer token",
                                           req_id);
                                free(put_uri);
                                free(json_body);
                                free(put_req);
                            } else {
                                struct curl_opts opts = CURL_OPTS_INIT;
                                opts.uri = put_req->uri;
                                opts.method = HTTP_PUT;
                                opts.post_fields = put_req->post_fields;
                                opts.xoauth2_bearer = put_req->bearer_token_copy;
                                opts.header_list[0] = "Content-Type: application/json";
                                opts.header_count = 1;

                                if (curl_perform_async(put_req, opts) == 0) {
                                    log_module(KC_LOG, LOG_DEBUG,
                                               "[%s] kc_async set_user_attr_get: GET succeeded, "
                                               "issued PUT with merged attributes for %s.%s",
                                               req_id, req->user_id_copy, req->user_attr_name);
                                    /* PUT request is now in flight, will call callback when done.
                                     * Don't call callback here - the PUT completion will do it. */
                                    result = KC_SUCCESS;
                                } else {
                                    log_module(KC_LOG, LOG_ERROR,
                                               "[%s] kc_async set_user_attr_get: Failed to start PUT",
                                               req_id);
                                    free(put_req->bearer_token_copy);
                                    free(put_uri);
                                    free(json_body);
                                    free(put_req);
                                }
                            }
                        } else {
                            free(put_uri);
                            free(json_body);
                        }
                    } else {
                        free(json_body);
                    }
                }
            } else {
                log_module(KC_LOG, LOG_ERROR,
                           "[%s] kc_async set_user_attr_get: Invalid JSON: %s",
                           req_id, error.text);
            }
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG,
                       "[%s] kc_async set_user_attr_get: User not found (HTTP 404)",
                       req_id);
        } else {
            log_module(KC_LOG, LOG_ERROR,
                       "[%s] kc_async set_user_attr_get: GET failed (HTTP %ld)",
                       req_id, http_code);
        }

        /* Only call callback on error - success continues to PUT phase */
        if (result != KC_SUCCESS && req->cb.generic) {
            req->cb.generic(req->session, result);
        }
        break;
    }
    case KC_ASYNC_COALESCE_GET: {
        /* GET phase completed for coalesced attribute update (cache miss case).
         * Merge all pending attributes and issue single PUT. */
        struct kc_pending_user_update *pending = req->coalesce_pending;
        int result = KC_ERROR;

        if (!pending) {
            log_module(KC_LOG, LOG_ERROR,
                       "[%s] kc_async coalesce_get: No pending update context",
                       req_id);
            break;
        }

        if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *repr = json_loads(req->response.response, 0, &error);
            if (repr) {
                /* Strip credentials from GET response - they should not be in PUT
                 * as Keycloak treats credentials in PUT as "add" not "replace" */
                json_object_del(repr, "credentials");

                /* Get or create attributes object */
                json_t *attrs = json_object_get(repr, "attributes");
                if (!attrs) {
                    attrs = json_object();
                    json_object_set_new(repr, "attributes", attrs);
                }

                /* Merge ALL pending attributes */
                for (int i = 0; i < pending->attr_count; i++) {
                    if (pending->attrs[i].value) {
                        json_t *attr_array = json_array();
                        json_array_append_new(attr_array, json_string(pending->attrs[i].value));
                        json_object_set_new(attrs, pending->attrs[i].name, attr_array);
                    } else {
                        /* NULL value = delete attribute by setting to empty array */
                        json_t *empty_array = json_array();
                        json_object_set_new(attrs, pending->attrs[i].name, empty_array);
                    }
                }

                /* Cache the merged representation AFTER merging attributes.
                 * kc_user_repr_cache_put already strips credentials. */
                json_t *id_json = json_object_get(repr, "id");
                if (id_json && json_is_string(id_json)) {
                    kc_user_repr_cache_put(json_string_value(id_json), repr);
                }

                /* Now issue PUT with full representation */
                char *json_body = json_dumps(repr, JSON_COMPACT);
                json_decref(repr);

                if (json_body) {
                    char *put_uri = kc_build_user_endpoint(req->realm_copy, pending->user_id);
                    if (put_uri) {
                        struct kc_async_request *put_req = calloc(1, sizeof(*put_req));
                        if (put_req) {
                            put_req->type = KC_ASYNC_SET_ATTR;
                            put_req->coalesce_pending = pending;  /* Transfer ownership */
                            put_req->uri = put_uri;
                            put_req->post_fields = json_body;

                            /* Get fresh token for PUT request */
                            if (kc_token_mgr.token && kc_token_mgr.token->access_token) {
                                put_req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
                            }

                            if (!put_req->bearer_token_copy) {
                                log_module(KC_LOG, LOG_ERROR,
                                           "[%s] kc_async coalesce_get: Failed to get bearer token for PUT",
                                           req_id);
                                put_req->coalesce_pending = NULL;  /* Return ownership */
                                free(put_uri);
                                free(json_body);
                                free(put_req);
                            } else {
                                struct curl_opts opts = CURL_OPTS_INIT;
                                opts.uri = put_req->uri;
                                opts.method = HTTP_PUT;
                                opts.post_fields = put_req->post_fields;
                                opts.xoauth2_bearer = put_req->bearer_token_copy;
                                opts.header_list[0] = "Content-Type: application/json";
                                opts.header_count = 1;

                                if (curl_perform_async(put_req, opts) == 0) {
                                    log_module(KC_LOG, LOG_DEBUG,
                                               "[%s] kc_async coalesce_get: GET succeeded, "
                                               "issued PUT with %d merged attrs for %s",
                                               req_id, pending->attr_count, pending->user_id);
                                    result = KC_SUCCESS;
                                    /* Ownership transferred to put_req - don't free pending */
                                    req->coalesce_pending = NULL;
                                } else {
                                    log_module(KC_LOG, LOG_ERROR,
                                               "[%s] kc_async coalesce_get: Failed to start PUT",
                                               req_id);
                                    put_req->coalesce_pending = NULL;  /* Return ownership */
                                    free(put_req->bearer_token_copy);
                                    free(put_uri);
                                    free(json_body);
                                    free(put_req);
                                }
                            }
                        } else {
                            free(put_uri);
                            free(json_body);
                        }
                    } else {
                        free(json_body);
                    }
                }
            } else {
                log_module(KC_LOG, LOG_ERROR,
                           "[%s] kc_async coalesce_get: Invalid JSON: %s",
                           req_id, error.text);
            }
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG,
                       "[%s] kc_async coalesce_get: User not found (HTTP 404)",
                       req_id);
        } else {
            log_module(KC_LOG, LOG_ERROR,
                       "[%s] kc_async coalesce_get: GET failed (HTTP %ld)",
                       req_id, http_code);
        }

        /* On error, invoke all callbacks. On success, PUT will handle callbacks. */
        if (result != KC_SUCCESS) {
            kc_pending_invoke_all_callbacks(pending, result);
            kc_pending_update_free(pending);
            req->coalesce_pending = NULL;  /* Don't double-free in cleanup */
        }
        break;
    }
    }

    /* Cleanup request */
    kc_async_request_cleanup(req);
}

/*
 * Bridge completion callback — called by x3_kc_bridge when a request completes.
 * Copies response data into kc_async_request and dispatches via the standard
 * result handler.
 */
static void
kc_async_bridge_complete(long http_code, const char *body, size_t body_len,
                          json_t *json, const char *error, void *req_data)
{
    struct kc_async_request *req = (struct kc_async_request *)req_data;
    (void)json;  /* Response is already in req->response from bridge copy */

    /* Copy response body into req->response for existing parsing code */
    if (body && body_len > 0) {
        req->response.response = malloc(body_len + 1);
        if (req->response.response) {
            memcpy(req->response.response, body, body_len);
            req->response.response[body_len] = '\0';
            req->response.size = body_len;
        }
    }

    /* Calculate latency from req->started */
    unsigned long latency_ms = 0;
    if (req->started > 0) {
        time_t elapsed = time(NULL) - req->started;
        latency_ms = (unsigned long)(elapsed * 1000);
    }

    int curl_failed = (http_code == 0 && error != NULL);
    kc_async_handle_result(req, http_code, curl_failed, latency_ms);
}

/* Initialize async HTTP infrastructure via libkc bridge */
static void
kc_async_init(void)
{
    if (x3_kc_bridge_is_ready()) return;  /* Already initialized */

    if (x3_kc_bridge_init() != 0) {
        log_module(KC_LOG, LOG_ERROR, "Failed to initialize libkc bridge");
        return;
    }
    log_module(KC_LOG, LOG_INFO, "Keycloak async HTTP initialized (libkc bridge)");
}

/* Cleanup async HTTP infrastructure */
static void
kc_async_cleanup(void)
{
    x3_kc_bridge_shutdown();
    log_module(KC_LOG, LOG_INFO, "Keycloak async HTTP cleaned up (libkc bridge)");
}

/*
 * Async version of curl_perform - submits HTTP request through libkc bridge.
 * The request struct must have uri, post_fields (if needed), session, type, and callback set.
 * Returns 0 on success (request started), -1 on error
 */
static int
curl_perform_async(struct kc_async_request *req, struct curl_opts opts)
{
    const char *req_id = opts.request_id ? opts.request_id : "-";

    if (!req || !opts.uri) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] curl_perform_async: Invalid arguments", req_id);
        return -1;
    }

    /* Initialize bridge if needed */
    if (!x3_kc_bridge_is_ready()) {
        kc_async_init();
        if (!x3_kc_bridge_is_ready()) {
            log_module(KC_LOG, LOG_ERROR, "[%s] curl_perform_async: Failed to init bridge", req_id);
            return -1;
        }
    }

    /* Store request_id for completion logging */
    if (opts.request_id) {
        req->request_id = pool_strdup(opts.request_id);
    }

    /* Record start time for timeout tracking */
    req->started = time(NULL);

    /* Store max retries from opts */
    if (opts.max_retries > 0)
        req->max_retries = opts.max_retries;

    /* Determine method string */
    const char *method = "GET";
    switch (opts.method) {
    case HTTP_POST:   method = "POST";   break;
    case HTTP_PUT:    method = "PUT";    break;
    case HTTP_DELETE: method = "DELETE"; break;
    default:          method = "GET";    break;
    }

    /* Determine body */
    const char *body = NULL;
    size_t body_len = 0;
    if (opts.post_data && opts.post_data_len > 0) {
        body = (const char *)opts.post_data;
        body_len = opts.post_data_len;
    } else if (opts.post_fields) {
        body = opts.post_fields;
        body_len = strlen(opts.post_fields);
    }

    /* Build headers list from curl_opts array */
    struct curl_slist *headers = NULL;
    for (size_t i = 0; i < opts.header_count && i < 10; i++) {
        if (opts.header_list[i])
            headers = curl_slist_append(headers, opts.header_list[i]);
    }
    req->header_list = headers;  /* Track for cleanup */

    /* Submit through bridge */
    int rc = x3_kc_bridge_submit(
        opts.uri, method, body, body_len,
        headers, opts.xoauth2_bearer,
        opts.auth_user, opts.auth_passwd,
        kc_async_bridge_complete, req);

    if (rc != 0) {
        log_module(KC_LOG, LOG_ERROR, "[%s] curl_perform_async: Bridge submit failed", req_id);
        if (headers) curl_slist_free_all(headers);
        req->header_list = NULL;
        return -1;
    }

    log_module(KC_LOG, LOG_DEBUG, "[%s] curl_perform_async: Request started via bridge", req_id);
    return 0;
}

/*
 * Start async authentication check against Keycloak
 * Returns 0 on success (request started), -1 on error
 */
int
kc_check_auth_async(struct kc_realm realm, struct kc_client client,
                    const char *handle, const char *password,
                    void *session, kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *user_enc = NULL;
    char *passwd_enc = NULL;
    static const char query_params_tmpl[] = "grant_type=password&username=%s&password=%s";

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.client_id || !client.client_secret ||
        !handle || !password || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "kc_check_auth_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "kc_check_auth_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_AUTH;
    req->cb.auth = callback;

    /* URL-encode credentials */
    user_enc = curl_easy_escape(NULL, handle, 0);
    passwd_enc = curl_easy_escape(NULL, password, 0);
    if (!user_enc || !passwd_enc) {
        log_module(KC_LOG, LOG_DEBUG, "kc_check_auth_async: Failed to escape credentials");
        goto error;
    }

    /* Build URI using endpoint builder */
    req->uri = kc_build_token_endpoint(realm);
    if (!req->uri) goto error;

    /* Build POST data */
    int post_len = snprintf(NULL, 0, query_params_tmpl, user_enc, passwd_enc) + 1;
    req->post_fields = malloc(post_len);
    if (!req->post_fields) goto error;
    snprintf(req->post_fields, post_len, query_params_tmpl, user_enc, passwd_enc);

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.post_fields = req->post_fields;
    opts.auth_user = client.client_id;
    opts.auth_passwd = client.client_secret;
    opts.method = HTTP_POST;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "kc_check_auth_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "kc_check_auth_async: Started async auth for %s", handle);

    /* Cleanup temporary strings */
    curl_free(user_enc);
    memset(passwd_enc, 0, strlen(passwd_enc));
    curl_free(passwd_enc);

    return 0;

error:
    if (user_enc) curl_free(user_enc);
    if (passwd_enc) {
        memset(passwd_enc, 0, strlen(passwd_enc));
        curl_free(passwd_enc);
    }
    if (req) {
        if (req->uri) free(req->uri);
        if (req->post_fields) {
            memset(req->post_fields, 0, strlen(req->post_fields));
            free(req->post_fields);
        }
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

/*
 * Start async client credentials token acquisition from Keycloak
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_get_client_token_async(struct kc_realm realm, struct kc_client client,
                                 void *session, kc_client_token_callback callback)
{
    struct kc_async_request *req = NULL;
    static const char query_params[] = "grant_type=client_credentials";

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.client_id ||
        !client.client_secret || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "keycloak_get_client_token_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_CLIENT_TOKEN;
    req->cb.client_token = callback;

    /* Build URI using endpoint builder */
    req->uri = kc_build_token_endpoint(realm);
    if (!req->uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token_async: Failed to build URI");
        goto error;
    }

    /* Copy POST data */
    req->post_fields = strdup(query_params);
    if (!req->post_fields) {
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.post_fields = req->post_fields;
    opts.auth_user = client.client_id;
    opts.auth_passwd = client.client_secret;
    opts.method = HTTP_POST;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "keycloak_get_client_token_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token_async: Started async token request");
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->post_fields) free(req->post_fields);
        free(req);
    }
    return -1;
}

/*
 * Start async fingerprint lookup against Keycloak
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_find_user_by_fingerprint_async(struct kc_realm realm, struct kc_client client,
                                         const char *fingerprint, void *session,
                                         kc_fingerprint_callback callback)
{
    struct kc_async_request *req = NULL;
    char *escaped_fp = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !fingerprint || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "fingerprint_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "fingerprint_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_FINGERPRINT;
    req->cb.fingerprint = callback;

    /* URL-encode fingerprint */
    escaped_fp = curl_easy_escape(NULL, fingerprint, 0);
    if (!escaped_fp) {
        log_module(KC_LOG, LOG_DEBUG, "fingerprint_async: Failed to escape fingerprint");
        goto error;
    }

    /* Build URI using endpoint builder */
    req->uri = kc_build_fingerprint_search_endpoint(realm, escaped_fp);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "fingerprint_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "fingerprint_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "fingerprint_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.xoauth2_bearer = req->bearer_token_copy;
    opts.method = HTTP_GET;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "fingerprint_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "fingerprint_async: Started lookup for %s", fingerprint);

    curl_free(escaped_fp);
    return 0;

error:
    if (escaped_fp) curl_free(escaped_fp);
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

/*
 * Start async token introspection against Keycloak
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_introspect_token_async(struct kc_realm realm, struct kc_client client,
                                 const char *token, void *session,
                                 kc_introspect_callback callback)
{
    struct kc_async_request *req = NULL;
    char *token_enc = NULL;
    static const char post_tmpl[] = "token=%s";

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.client_id || !client.client_secret ||
        !token || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "introspect_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "introspect_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_INTROSPECT;
    req->cb.introspect = callback;

    /* URL-encode token */
    token_enc = curl_easy_escape(NULL, token, 0);
    if (!token_enc) {
        log_module(KC_LOG, LOG_DEBUG, "introspect_async: Failed to escape token");
        goto error;
    }

    /* Build URI using endpoint builder */
    req->uri = kc_build_introspect_endpoint(realm);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "introspect_async: Failed to build URI");
        goto error;
    }

    /* Build POST fields */
    int post_len = snprintf(NULL, 0, post_tmpl, token_enc) + 1;
    req->post_fields = malloc(post_len);
    if (!req->post_fields) {
        log_module(KC_LOG, LOG_ERROR, "introspect_async: Failed to allocate POST data");
        goto error;
    }
    snprintf(req->post_fields, post_len, post_tmpl, token_enc);

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.post_fields = req->post_fields;
    opts.auth_user = client.client_id;
    opts.auth_passwd = client.client_secret;
    opts.method = HTTP_POST;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "introspect_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "introspect_async: Started token introspection");

    curl_free(token_enc);
    return 0;

error:
    if (token_enc) curl_free(token_enc);
    if (req) {
        if (req->uri) free(req->uri);
        if (req->post_fields) {
            memset(req->post_fields, 0, strlen(req->post_fields));
            free(req->post_fields);
        }
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

/**
 * Set a user attribute asynchronously with coalescing.
 *
 * Multiple attribute updates for the same user within KC_COALESCE_DELAY_SEC
 * are batched into a single Keycloak API call. This reduces API load when
 * multiple attributes are set in quick succession (e.g., during account setup).
 *
 * Flow:
 * 1. Find or create pending update entry for this user
 * 2. Add attribute to pending list (overwrites if same attr already pending)
 * 3. On first attr for user, schedule flush callback after delay
 * 4. Flush merges all pending attrs and issues single PUT
 */
int
keycloak_set_user_attribute_async(struct kc_realm realm, struct kc_client client,
                                   const char *user_id, const char *attr_name,
                                   const char *attr_value, void *session,
                                   kc_async_callback callback)
{
    (void)realm;   /* Realm taken from global token manager at flush time */
    (void)client;  /* Client token taken from global token manager at flush time */

    /* Validate inputs */
    if (!user_id || !attr_name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "set_attr_async: Invalid arguments");
        return -1;
    }

    /* Find or create pending update for this user */
    struct kc_pending_user_update *p = kc_coalesce_get_or_create(user_id);
    if (!p) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_async: Failed to create pending update");
        return -1;
    }

    /* Add attribute to pending list */
    if (kc_coalesce_add_attr(p, attr_name, attr_value, callback, session) < 0) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_async: Failed to add attr to pending");
        return -1;
    }

    return 0;
}

/**
 * Flush callback for coalesced attribute updates.
 * Called by timeq after the coalesce delay expires.
 */
static void
kc_coalesce_flush_cb(void *data)
{
    struct kc_pending_user_update *p = data;
    struct kc_pending_user_update **pp;

    /* Unlink from pending list */
    for (pp = &kc_pending_updates; *pp; pp = &(*pp)->next) {
        if (*pp == p) {
            *pp = p->next;
            break;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "coalesce: Flushing %d attrs for user %s",
               p->attr_count, p->user_id);

    if (p->attr_count == 0) {
        /* Nothing to flush */
        kc_pending_update_free(p);
        return;
    }

    /* Check if we have a valid token */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "coalesce: No valid token for flush");
        kc_pending_invoke_all_callbacks(p, KC_ERROR);
        kc_pending_update_free(p);
        return;
    }

    /* Check user representation cache */
    json_t *cached_repr = kc_user_repr_cache_get(p->user_id);

    if (cached_repr) {
        /* Cache hit - merge all pending attrs and issue PUT directly */
        log_module(KC_LOG, LOG_DEBUG, "coalesce: Cache hit for %s, merging %d attrs",
                   p->user_id, p->attr_count);

        /* Deep copy the representation so we can modify it */
        json_t *repr = json_deep_copy(cached_repr);
        if (!repr) {
            log_module(KC_LOG, LOG_ERROR, "coalesce: Failed to copy cached repr");
            kc_pending_invoke_all_callbacks(p, KC_ERROR);
            kc_pending_update_free(p);
            return;
        }

        /* Strip any existing credentials - Keycloak treats credentials in PUT as "add"
         * not "replace". kc_user_repr_cache_put already strips them, but be defensive. */
        json_object_del(repr, "credentials");

        /* Get or create attributes object */
        json_t *attrs = json_object_get(repr, "attributes");
        if (!attrs) {
            attrs = json_object();
            json_object_set_new(repr, "attributes", attrs);
        }

        /* Merge all pending attribute changes */
        for (int i = 0; i < p->attr_count; i++) {
            if (p->attrs[i].value) {
                json_t *attr_array = json_array();
                json_array_append_new(attr_array, json_string(p->attrs[i].value));
                json_object_set_new(attrs, p->attrs[i].name, attr_array);
            } else {
                /* NULL value = delete attribute by setting to empty array
                 * NOTE: json_object_del doesn't work - Keycloak interprets missing
                 * attributes as "don't change" not "delete". Must explicitly set
                 * to empty array [] to delete. */
                json_t *empty_array = json_array();
                json_object_set_new(attrs, p->attrs[i].name, empty_array);
            }
        }

        /* Serialize for PUT */
        char *json_body = json_dumps(repr, JSON_COMPACT);
        json_decref(repr);

        if (!json_body) {
            log_module(KC_LOG, LOG_ERROR, "coalesce: Failed to serialize JSON");
            kc_pending_invoke_all_callbacks(p, KC_ERROR);
            kc_pending_update_free(p);
            return;
        }

        /* Build PUT request */
        struct kc_async_request *req = calloc(1, sizeof(*req));
        if (!req) {
            log_module(KC_LOG, LOG_ERROR, "coalesce: Out of memory for request");
            free(json_body);
            kc_pending_invoke_all_callbacks(p, KC_ERROR);
            kc_pending_update_free(p);
            return;
        }

        req->type = KC_ASYNC_SET_ATTR;
        req->coalesce_pending = p;  /* Transfer ownership - callbacks invoked on completion */
        req->uri = kc_build_user_endpoint(kc_token_mgr.realm, p->user_id);
        req->post_fields = json_body;
        req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);

        if (!req->uri || !req->bearer_token_copy) {
            log_module(KC_LOG, LOG_ERROR, "coalesce: Failed to build request");
            if (req->uri) free(req->uri);
            if (req->bearer_token_copy) free(req->bearer_token_copy);
            free(json_body);
            free(req);
            kc_pending_invoke_all_callbacks(p, KC_ERROR);
            kc_pending_update_free(p);
            return;
        }

        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_PUT;
        opts.post_fields = req->post_fields;
        opts.xoauth2_bearer = req->bearer_token_copy;
        opts.header_list[0] = "Content-Type: application/json";
        opts.header_count = 1;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "coalesce: curl_perform_async failed");
            free(req->uri);
            free(req->bearer_token_copy);
            free(req->post_fields);
            free(req);
            kc_pending_invoke_all_callbacks(p, KC_ERROR);
            kc_pending_update_free(p);
            return;
        }

        log_module(KC_LOG, LOG_DEBUG, "coalesce: Started PUT with %d merged attrs for %s",
                   p->attr_count, p->user_id);
        /* Ownership of p transferred to req->coalesce_pending - don't free here */
        return;
    }

    /* Cache miss - need to GET user first, then merge and PUT */
    log_module(KC_LOG, LOG_DEBUG, "coalesce: Cache miss for %s, doing GET first", p->user_id);

    struct kc_async_request *req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "coalesce: Out of memory for GET request");
        kc_pending_invoke_all_callbacks(p, KC_ERROR);
        kc_pending_update_free(p);
        return;
    }

    req->type = KC_ASYNC_COALESCE_GET;
    req->coalesce_pending = p;  /* Transfer ownership to request */
    req->realm_copy = kc_token_mgr.realm;

    req->uri = kc_build_user_endpoint(kc_token_mgr.realm, p->user_id);
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);

    if (!req->uri || !req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "coalesce: Failed to build GET request");
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
        kc_pending_invoke_all_callbacks(p, KC_ERROR);
        kc_pending_update_free(p);
        return;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "coalesce: curl_perform_async failed for GET");
        free(req->uri);
        free(req->bearer_token_copy);
        free(req);
        kc_pending_invoke_all_callbacks(p, KC_ERROR);
        kc_pending_update_free(p);
        return;
    }

    log_module(KC_LOG, LOG_DEBUG, "coalesce: Started GET for %s before merging %d attrs",
               p->user_id, p->attr_count);
    /* Ownership of p transferred to req->coalesce_pending - don't free here */
}

/**
 * Set a multi-valued user attribute asynchronously.
 * Used for attributes like x509_fingerprints that have multiple values.
 *
 * Uses the user representation cache when available to safely merge the
 * attribute without clobbering other fields.
 */
int
keycloak_set_user_attribute_array_async(struct kc_realm realm, struct kc_client client,
                                         const char *user_id, const char *attr_name,
                                         const char **values, size_t value_count,
                                         void *session, kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !attr_name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "set_attr_array_async: Invalid arguments");
        return -1;
    }

    /* Check user representation cache */
    json_t *cached_repr = kc_user_repr_cache_get(user_id);

    if (cached_repr) {
        /* Cache hit - merge attribute into cached representation and PUT */
        log_module(KC_LOG, LOG_DEBUG, "set_attr_array_async: Cache hit for %s, merging attribute %s",
                   user_id, attr_name);

        /* Deep copy the representation so we can modify it */
        json_t *repr = json_deep_copy(cached_repr);
        if (!repr) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to copy cached repr");
            return -1;
        }

        /* Get or create attributes object */
        json_t *attrs = json_object_get(repr, "attributes");
        if (!attrs) {
            attrs = json_object();
            json_object_set_new(repr, "attributes", attrs);
        }

        /* Build attribute array */
        json_t *attr_array = json_array();
        for (size_t i = 0; i < value_count; i++) {
            if (values && values[i]) {
                json_array_append_new(attr_array, json_string(values[i]));
            }
        }
        json_object_set_new(attrs, attr_name, attr_array);

        /* Serialize for PUT */
        json_body = json_dumps(repr, JSON_COMPACT);
        json_decref(repr);

        if (!json_body) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to build JSON from cache");
            return -1;
        }

        /* Allocate request structure for PUT */
        req = calloc(1, sizeof(*req));
        if (!req) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Out of memory");
            free(json_body);
            return -1;
        }
        req->session = session;
        req->type = KC_ASYNC_SET_ATTR;
        req->cb.generic = callback;

        /* Build URI */
        req->uri = kc_build_user_endpoint(realm, user_id);
        if (!req->uri) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to build URI");
            free(json_body);
            free(req);
            return -1;
        }

        req->post_fields = json_body;

        /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
        if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: No valid token available (token refresh in progress?)");
            free(req->uri);
            free(req->post_fields);
            free(req);
            return -1;
        }
        req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
        if (!req->bearer_token_copy) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to copy bearer token");
            free(req->uri);
            free(req->post_fields);
            free(req);
            return -1;
        }

        /* Issue PUT */
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_PUT;
        opts.post_fields = req->post_fields;
        opts.xoauth2_bearer = req->bearer_token_copy;
        opts.header_list[0] = "Content-Type: application/json";
        opts.header_count = 1;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: curl_perform_async failed");
            free(req->uri);
            free(req->bearer_token_copy);
            free(req->post_fields);
            free(req);
            return -1;
        }

        log_module(KC_LOG, LOG_DEBUG, "set_attr_array_async: Started PUT with merged repr for %s.%s (%zu values)",
                   user_id, attr_name, value_count);
        return 0;
    }

    /* Cache miss - fall back to partial update
     * Note: This may clear other user fields, but for arrays (like x509_fingerprints)
     * we typically use this function after user registration when cache isn't populated yet.
     * Future: could add GET-then-PUT flow like keycloak_set_user_attribute_async. */
    log_module(KC_LOG, LOG_DEBUG, "set_attr_array_async: Cache miss for %s, using partial update", user_id);

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_SET_ATTR;
    req->cb.generic = callback;

    /* Build URI */
    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to build URI");
        goto error;
    }

    /* Build JSON body - { "attributes": { "attr_name": ["val1", "val2", ...] } } */
    json_t *attrs = json_object();
    json_t *attr_array = json_array();

    for (size_t i = 0; i < value_count; i++) {
        if (values && values[i]) {
            json_array_append_new(attr_array, json_string(values[i]));
        }
    }
    json_object_set_new(attrs, attr_name, attr_array);

    json_t *user_obj = json_object();
    json_object_set_new(user_obj, "attributes", attrs);
    json_body = json_dumps(user_obj, JSON_COMPACT);
    json_decref(user_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to build JSON");
        goto error;
    }

    /* Store post fields in request for cleanup */
    req->post_fields = json_body;
    json_body = NULL;  /* Transferred ownership */

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_PUT;
    opts.post_fields = req->post_fields;
    opts.xoauth2_bearer = req->bearer_token_copy;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "set_attr_array_async: Started attribute array update for %s.%s (%zu values)",
               user_id, attr_name, value_count);
    return 0;

error:
    if (json_body) free(json_body);
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->post_fields) {
            memset(req->post_fields, 0, strlen(req->post_fields));
            free(req->post_fields);
        }
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

/**
 * Set emailVerified flag on a Keycloak user asynchronously.
 * Used to sync X3's cookie-based email verification to Keycloak.
 */
int
keycloak_set_email_verified_async(struct kc_realm realm, struct kc_client client,
                                   const char *user_id, int verified,
                                   void *session, kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "set_email_verified_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_SET_ATTR;  /* Reuse generic attr type */
    req->cb.generic = callback;

    /* Build URI */
    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: Failed to build URI");
        goto error;
    }

    /* Build JSON body - update emailVerified boolean */
    json_t *user_obj = json_object();
    json_object_set_new(user_obj, "emailVerified", verified ? json_true() : json_false());
    json_body = json_dumps(user_obj, JSON_COMPACT);
    json_decref(user_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: Failed to build JSON");
        goto error;
    }

    /* Store post fields in request for cleanup */
    req->post_fields = json_body;
    json_body = NULL;  /* Transferred ownership */

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_PUT;
    opts.post_fields = req->post_fields;
    opts.xoauth2_bearer = req->bearer_token_copy;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "set_email_verified_async: Started for user %s (verified=%d)",
               user_id, verified);
    return 0;

error:
    if (json_body) free(json_body);
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->post_fields) {
            memset(req->post_fields, 0, strlen(req->post_fields));
            free(req->post_fields);
        }
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

/**
 * Add a user to a group asynchronously.
 * Useful for non-blocking channel access sync.
 */
int
keycloak_add_user_to_group_async(struct kc_realm realm, struct kc_client client,
                                  const char *user_id, const char *group_id,
                                  void *session, kc_async_callback callback)
{
    struct kc_async_request *req = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !group_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "add_group_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "add_group_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GROUP_ADD;
    req->cb.generic = callback;

    /* Build URI using endpoint builder */
    req->uri = kc_build_user_group_endpoint(realm, user_id, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "add_group_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "add_group_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "add_group_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API - PUT with no body */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_PUT;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "add_group_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "add_group_async: Started adding user %s to group %s",
               user_id, group_id);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

/**
 * Remove a user from a group asynchronously.
 * Useful for non-blocking channel access sync.
 */
int
keycloak_remove_user_from_group_async(struct kc_realm realm, struct kc_client client,
                                       const char *user_id, const char *group_id,
                                       void *session, kc_async_callback callback)
{
    struct kc_async_request *req = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !group_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "remove_group_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "remove_group_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GROUP_REMOVE;
    req->cb.generic = callback;

    /* Build URI using endpoint builder */
    req->uri = kc_build_user_group_endpoint(realm, user_id, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "remove_group_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "remove_group_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "remove_group_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API - DELETE with no body */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_DELETE;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "remove_group_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "remove_group_async: Started removing user %s from group %s",
               user_id, group_id);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

/**
 * Create a user in Keycloak asynchronously.
 * Uses the async curl_multi infrastructure for non-blocking HTTP.
 *
 * @param realm     Keycloak realm configuration
 * @param client    Client with admin access token
 * @param username  New user's username
 * @param email     New user's email (or empty string)
 * @param password  New user's password
 * @param session   Opaque session pointer (passed to callback)
 * @param callback  Function to call when request completes
 * @return 0 on success (request started), -1 on error
 */
int
keycloak_create_user_async(struct kc_realm realm, struct kc_client client,
                           const char *username, const char *email,
                           const char *password, void *session,
                           kc_create_user_callback callback)
{
    struct kc_async_request *req = NULL;
    char *user_repr = NULL;

    /* Validate inputs - password can be NULL (user created without credentials) */
    if (!realm.base_uri || !realm.realm || !client.access_token || !username || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "create_user_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_CREATE_USER;
    req->cb.generic = callback;

    /* Store username for user ID caching */
    req->create_username = pool_strdup(username);
    if (!req->create_username) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: Failed to copy username");
        free(req);
        return -1;
    }

    /* Build users endpoint URI */
    req->uri = kc_build_users_endpoint(realm);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: Failed to build URI");
        goto error;
    }

    /* Build user JSON representation */
    user_repr = json_build_user_representation(username, email ? email : "", password);
    if (!user_repr) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: Failed to build user JSON");
        goto error;
    }

    /* Copy POST data */
    req->post_fields = user_repr;
    user_repr = NULL;  /* Transfer ownership to req */

    /* Initialize location header buffer for user ID capture */
    req->location_header[0] = '\0';

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: Failed to copy bearer token");
        goto error;
    }

    /* Build curl options with header callback for Location capture */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_POST;
    opts.xoauth2_bearer = req->bearer_token_copy;
    opts.post_fields = req->post_fields;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;
    opts.header_callback = kc_header_callback;
    opts.header_userdata = req;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "create_user_async: Started user creation for %s", username);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->post_fields) {
            memset(req->post_fields, 0, strlen(req->post_fields));
            free(req->post_fields);
        }
        if (req->create_username) free(req->create_username);
        if (req->attr_prefix) free(req->attr_prefix);
        if (req->attr_name) free(req->attr_name);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    if (user_repr) {
        memset(user_repr, 0, strlen(user_repr));
        free(user_repr);
    }
    return -1;
}

/**
 * Create a user in Keycloak with a pre-hashed password asynchronously.
 * Uses the async curl_multi infrastructure for non-blocking HTTP.
 */
int
keycloak_create_user_with_hash_async(struct kc_realm realm, struct kc_client client,
                                      const char *username, const char *email,
                                      const char *cred_data, const char *secret_data,
                                      void *session, kc_create_user_callback callback)
{
    struct kc_async_request *req = NULL;
    char *user_repr = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !username || !cred_data || !secret_data || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "create_user_with_hash_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_CREATE_USER;
    req->cb.generic = callback;

    /* Store username for user ID caching */
    req->create_username = pool_strdup(username);
    if (!req->create_username) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: Failed to copy username");
        free(req);
        return -1;
    }

    /* Build users endpoint URI */
    req->uri = kc_build_users_endpoint(realm);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: Failed to build URI");
        goto error;
    }

    /* Build user JSON representation with pre-hashed password */
    user_repr = json_build_user_with_hash(username, email ? email : "", cred_data, secret_data);
    if (!user_repr) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: Failed to build user JSON");
        goto error;
    }

    /* Copy POST data */
    req->post_fields = user_repr;
    user_repr = NULL;  /* Transfer ownership to req */

    /* Initialize location header buffer for user ID capture */
    req->location_header[0] = '\0';

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: Failed to copy bearer token");
        goto error;
    }

    /* Build curl options with header callback for Location capture */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_POST;
    opts.xoauth2_bearer = req->bearer_token_copy;
    opts.post_fields = req->post_fields;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;
    opts.header_callback = kc_header_callback;
    opts.header_userdata = req;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "create_user_with_hash_async: Started user creation for %s",
               username);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->post_fields) {
            memset(req->post_fields, 0, strlen(req->post_fields));
            free(req->post_fields);
        }
        if (req->create_username) free(req->create_username);
        if (req->attr_prefix) free(req->attr_prefix);
        if (req->attr_name) free(req->attr_name);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    if (user_repr) {
        memset(user_repr, 0, strlen(user_repr));
        free(user_repr);
    }
    return -1;
}

/**
 * List user attributes asynchronously, optionally filtered by prefix.
 * Uses the async curl_multi infrastructure for non-blocking HTTP.
 *
 * @param realm     Keycloak realm configuration
 * @param client    Client with valid access token
 * @param user_id   Keycloak user ID (UUID)
 * @param prefix    Optional prefix filter (NULL for all attributes)
 * @param session   Opaque session pointer passed to callback
 * @param callback  Callback invoked on completion
 * @return 0 on success (request started), -1 on error
 */
int
keycloak_list_user_attributes_async(struct kc_realm realm, struct kc_client client,
                                     const char *user_id, const char *prefix,
                                     void *session, kc_list_attrs_callback callback)
{
    struct kc_async_request *req = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "list_user_attrs_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_LIST_ATTRS;
    req->cb.list_attrs = callback;

    /* Store prefix for completion handler */
    if (prefix) {
        req->attr_prefix = pool_strdup(prefix);
        if (!req->attr_prefix) {
            log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: Failed to copy prefix");
            goto error;
        }
    }

    /* Build URI: /admin/realms/{realm}/users/{user_id} */
    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "list_user_attrs_async: Started for user %s (prefix: %s)",
               user_id, prefix ? prefix : "(none)");
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->attr_prefix) free(req->attr_prefix);
        free(req);
    }
    return -1;
}

/**
 * Get a single user attribute asynchronously.
 * Uses the async curl_multi infrastructure for non-blocking HTTP.
 *
 * @param realm      Keycloak realm configuration
 * @param client     Client with valid access token
 * @param user_id    Keycloak user ID (UUID)
 * @param attr_name  Attribute name to retrieve
 * @param session    Opaque session pointer passed to callback
 * @param callback   Callback invoked on completion
 * @return 0 on success (request started), -1 on error
 */
int
keycloak_get_user_attribute_async(struct kc_realm realm, struct kc_client client,
                                   const char *user_id, const char *attr_name,
                                   void *session, kc_get_attr_callback callback)
{
    struct kc_async_request *req = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !attr_name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "get_user_attr_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GET_ATTR;
    req->cb.get_attr = callback;

    /* Store attribute name for completion handler */
    req->attr_name = pool_strdup(attr_name);
    if (!req->attr_name) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: Failed to copy attr_name");
        goto error;
    }

    /* Build URI: /admin/realms/{realm}/users/{user_id} */
    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "get_user_attr_async: Started for user %s, attr %s",
               user_id, attr_name);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->attr_name) free(req->attr_name);
        free(req);
    }
    return -1;
}

/* =============================================================================
 * End of Async HTTP Infrastructure
 * ============================================================================= */

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
static int
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

static long curl_perform(struct curl_opts opts, struct memory* chunk_out)
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

/*
 * Convenience wrapper for JSON API calls
 * Automatically sets Content-Type header and uses standard defaults
 */
static long
curl_perform_json(const char *uri, enum http_method method,
                  const char *json_body, const char *bearer_token,
                  struct memory *response)
{
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = method;
    opts.post_fields = json_body;
    opts.xoauth2_bearer = bearer_token;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;
    opts.max_retries = 1;  /* Retry once for transient failures */

    return curl_perform(opts, response);
}

/*
 * =============================================================================
 * Async HTTP Worker Infrastructure
 *
 * For offloading blocking sync HTTP calls to the threadpool.
 * Worker functions run in background threads; callbacks run in main thread.
 * =============================================================================
 */

/* Work structure for async HTTP operations */
struct kc_http_work {
    /* Input (copied by caller, owned by worker) */
    char *uri;
    char *post_data;
    char *bearer_token;
    enum http_method method;
    int max_retries;

    /* Output (written by worker) */
    struct memory response;
    long http_code;
    int result;  /* KC_SUCCESS, KC_ERROR, etc. */

    /* Callback (runs in main thread) */
    void (*callback)(struct kc_http_work *work, void *ctx);
    void *callback_ctx;
};

/* Worker function - runs in threadpool thread */
static void *
kc_http_worker(void *arg)
{
    struct kc_http_work *work = arg;
    CURL *curl;
    struct curl_slist *headers = NULL;
    CURLcode res;

    curl = curl_easy_init();
    if (!curl) {
        work->result = KC_ERROR;
        work->http_code = 0;
        return NULL;
    }

    /* Initialize response */
    work->response.response = NULL;
    work->response.size = 0;

    /* Set up curl options */
    curl_easy_setopt(curl, CURLOPT_URL, work->uri);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &work->response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);

    /* Set HTTP method */
    switch (work->method) {
    case HTTP_GET:
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        break;
    case HTTP_POST:
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (work->post_data)
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, work->post_data);
        break;
    case HTTP_PUT:
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        if (work->post_data)
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, work->post_data);
        break;
    case HTTP_DELETE:
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
        break;
    }

    /* Set headers */
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (work->bearer_token) {
        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", work->bearer_token);
        headers = curl_slist_append(headers, auth_header);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Perform blocking HTTP */
    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &work->http_code);
        work->result = KC_SUCCESS;
    } else {
        work->http_code = 0;
        work->result = KC_ERROR;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return NULL;
}

/* Callback wrapper - runs in main thread via threadpool notification */
static void
kc_http_done(void *result, void *user_data, tp_state_t state)
{
    struct kc_http_work *work = user_data;
    (void)result;

    if (state != TP_STATE_COMPLETED) {
        work->result = KC_ERROR;
    }

    /* Call user callback */
    if (work->callback) {
        work->callback(work, work->callback_ctx);
    }

    /* Cleanup work struct */
    free(work->uri);
    if (work->post_data) {
        memset(work->post_data, 0, strlen(work->post_data));  /* Zero sensitive data */
        free(work->post_data);
    }
    free(work->bearer_token);
    /* Note: response is owned by callback, not freed here */
    free(work);
}

/*
 * Submit an async HTTP request to the threadpool.
 * Returns 0 on successful submission, -1 on error.
 * The callback will be invoked in the main thread when complete.
 */
static int __attribute__((unused))
kc_http_async(const char *uri, enum http_method method, const char *post_data,
              void (*callback)(struct kc_http_work *, void *), void *ctx)
{
    struct kc_http_work *work;
    char *token;

    if (!threadpool_is_initialized()) {
        log_module(KC_LOG, LOG_DEBUG, "kc_http_async: Threadpool not available");
        return -1;
    }

    work = calloc(1, sizeof(*work));
    if (!work)
        return -1;

    work->uri = strdup(uri);
    work->method = method;
    work->post_data = post_data ? strdup(post_data) : NULL;
    work->max_retries = 1;
    work->callback = callback;
    work->callback_ctx = ctx;

    /* Get token copy (thread-safe) */
    token = kc_get_token_copy();
    work->bearer_token = token;  /* Takes ownership */

    if (!work->uri || (post_data && !work->post_data)) {
        free(work->uri);
        free(work->post_data);
        free(work->bearer_token);
        free(work);
        return -1;
    }

    /* Submit to threadpool */
    if (!threadpool_submit(kc_http_worker, work, kc_http_done, work, TP_PRIORITY_NORMAL)) {
        log_module(KC_LOG, LOG_DEBUG, "kc_http_async: Failed to submit to threadpool");
        free(work->uri);
        free(work->post_data);
        free(work->bearer_token);
        free(work);
        return -1;
    }

    return 0;
}

static int json_read_object_string(json_t* object, const char* key,
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

static int json_read_object_boolean(json_t* object, const char* key, bool* value_out)
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

static int json_read_kc_access_token(const char* response, struct access_token** token_out)
{
    if (!response || !token_out) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_access_token: Invalid arguments");
        return KC_ERROR;
    }

    *token_out = NULL;

    json_t* root = NULL;
    json_error_t error;

    root = json_loads(response, 0, &error);

    if (!root) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_access_token: Failed to parse JSON: %s", error.text);
        return KC_ERROR;
    }

    int result = KC_ERROR;

    if (!json_is_object(root)) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_access_token: Response is not an object");
        goto cleanup;
    }

    // Allocate the token struct
    struct access_token* token = malloc(sizeof(struct access_token));
    if (!token) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_access_token: Failed to allocate token struct");
        goto cleanup;
    }
    memset(token, 0, sizeof(*token));

    // Required field: access_token
    if (json_read_object_string(root, "access_token", &token->access_token, &token->access_token_size) != KC_SUCCESS) {
        free(token);
        goto cleanup;
    }

    // Optional string fields - read but don't fail if missing
    json_read_object_string(root, "refresh_token", &token->refresh_token, &token->refresh_token_size);
    json_read_object_string(root, "token_type", &token->token_type, &token->token_type_size);
    json_read_object_string(root, "session_state", &token->session_state, &token->session_state_size);
    json_read_object_string(root, "scope", &token->scope, &token->scope_size);

    // Optional integer fields
    json_t* expires_in = json_object_get(root, "expires_in");
    if (expires_in && json_is_integer(expires_in)) {
        token->expires_in = json_integer_value(expires_in);
    }

    json_t* not_before_policy = json_object_get(root, "not-before-policy");
    if (not_before_policy && json_is_integer(not_before_policy)) {
        token->not_before_policy = json_integer_value(not_before_policy);
    }

    json_t* refresh_expires_in = json_object_get(root, "refresh_expires_in");
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

static int json_read_kc_user(json_t* user_object, struct kc_user* user_out)
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

static int json_read_kc_users(const char* json_users_array,
    struct kc_user** kc_users_out)
{
    if (!json_users_array) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_users: Invalid arguments");
        return KC_ERROR;
    }

    *kc_users_out = NULL;

    log_module(KC_LOG, LOG_DEBUG, "json_read_kc_users: json_users_array: %s",
        json_users_array);

    json_error_t error;
    json_t* root = json_loads(json_users_array, 0, &error);
    if (!root) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_users: Failed to parse JSON: %s",
            error.text);
        return KC_ERROR;
    }

    if (!json_is_array(root)) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_users: Response is not a JSON array");
        json_decref(root);
        return KC_ERROR;
    }

    const size_t array_size = json_array_size(root);
    if (array_size == 0) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_users: Array is empty");
        json_decref(root);
        return KC_SUCCESS;
    }

    struct kc_user* users = (struct kc_user*)malloc(array_size * sizeof(struct kc_user));
    if (!users) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_users: Failed to allocate memory");
        json_decref(root);
        return KC_ERROR;
    }

    size_t success_count = 0;

    // Parse users, collecting successful ones
    for (size_t i = 0; i < array_size; i++) {
        json_t* user_object = json_array_get(root, i);
        if (!user_object || !json_is_object(user_object)) {
            log_module(KC_LOG, LOG_DEBUG,
                "json_read_kc_users: Skipping element %zu (not an object)", i);
            continue;
        }

        if (json_read_kc_user(user_object, &users[success_count]) == KC_SUCCESS) {
            success_count++;
        } else {
            log_module(KC_LOG, LOG_DEBUG,
                "json_read_kc_users: Skipping user at index %zu (parse failed)", i);
        }
    }

    if (success_count == 0) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_kc_users: No users parsed successfully");
        free(users);
        json_decref(root);
        return KC_NOT_FOUND;
    }

    // Shrink allocation if we skipped some users
    if (success_count < array_size) {
        struct kc_user* resized = (struct kc_user*)realloc(users,
            success_count * sizeof(struct kc_user));
        if (resized) {
            users = resized;
        }
        // If realloc fails, original allocation is still valid
    }

    *kc_users_out = users;
    json_decref(root);
    return (int)success_count;
}

static char* json_build_user_representation(const char *username, const char *email, const char *passwd)
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
static char* json_build_user_with_hash(const char *username, const char *email,
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


/* Still needed: called by keycloak_ensure_token() */
int keycloak_get_client_token(struct kc_realm realm, struct kc_client client, struct access_token** access_token)
{
    /* Input validation */
    if (!realm.base_uri || !realm.realm || !client.client_id || !client.client_secret || !access_token) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    struct memory chunk = {0};
    static const char query_params[] = "grant_type=client_credentials";

    /* Build URI using endpoint builder */
    char *uri = kc_build_token_endpoint(realm);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token: Failed to build uri");
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
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
        goto cleanup;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token: Token retrieved successfully (HTTP 200)");
        result = json_read_kc_access_token(chunk.response, access_token);
    }

cleanup:
    if (chunk.response) {
        // Use chunk.size instead of strlen to avoid potential issues
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }

    if (uri) {
        free(uri);
    }

    return result;
}

int keycloak_get_user_token(struct kc_realm realm, struct kc_client client, const char* user, const char* passwd, struct access_token** user_access_token)
{
    /* Input validation */
    if (!realm.base_uri || !realm.realm || !user || !passwd || !user_access_token) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Invalid arguments");
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
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Failed to escape user");
        goto cleanup;
    }

    passwd_enc = curl_easy_escape(NULL, passwd, 0);
    if (!passwd_enc) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Failed to escape passwd");
        goto cleanup;
    }

    static const char query_params_tmpl[] = "grant_type=password&username=%s&password=%s";

    /* Build URI using endpoint builder */
    uri = kc_build_token_endpoint(realm);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Failed to build uri");
        goto cleanup;
    }

    /* Build query parameters safely */
    int query_params_len = snprintf(NULL, 0, query_params_tmpl, user_enc, passwd_enc) + 1;
    query_params = malloc(query_params_len);
    if (!query_params) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Failed to build query_params");
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
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Token retrieved successfully (HTTP 200)");
        result = json_read_kc_access_token(chunk.response, user_access_token);
    } else if (http_code == 401) {
        /* 401 Unauthorized = invalid credentials */
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Invalid credentials (HTTP 401)");
        result = KC_FORBIDDEN;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
        /* result stays KC_ERROR */
    }

cleanup:
    if (chunk.response) {
        // Use chunk.size instead of strlen to avoid potential issues
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

/* Still needed: called by keycloak_get_user() */
int keycloak_get_users(struct kc_realm realm, struct kc_client client, const char* user, const char* filter, bool exact, struct kc_user** user_out)
{
    (void)filter; /* TODO: implement additional filtering */

    if (!realm.base_uri || !realm.realm || !client.access_token || !user || !user_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_users: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char* uri = NULL;
    char* escaped_user = NULL;
    struct memory chunk = { 0 };

    /* URL-encode username */
    escaped_user = curl_easy_escape(NULL, user, 0);
    if (!escaped_user) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_users: Failed to escape user");
        goto cleanup;
    }

    /* Build URI using endpoint builder */
    uri = kc_build_user_by_username_endpoint(realm, escaped_user, exact);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_users: Failed to build uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.method = HTTP_GET;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 200) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_users: User returned successfully (HTTP 200)");
        result = json_read_kc_users(chunk.response, user_out);
    } else if (http_code == 403) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_users: Forbidden to retrieve users (HTTP 403)");
        result = KC_FORBIDDEN;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_users: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (escaped_user) {
        curl_free(escaped_user);
    }
    if (uri) {
        free(uri);
    }

    return result;
}

/* DISABLED: Use keycloak_create_user_async instead */
#if 0
int keycloak_create_user(struct kc_realm realm, struct kc_client client, const char* username, const char* email, const char* passwd)
{
    /* Only require realm config, token, and username. Email and passwd can be NULL. */
    if (!realm.base_uri || !realm.realm || !client.access_token || !username) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = kc_build_users_endpoint(realm);
    char *user_repr = NULL;
    struct memory chunk = {0};

    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user: Failed to build uri");
        goto cleanup;
    }

    user_repr = json_build_user_representation(username, email, passwd);
    if (!user_repr) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user: Failed to build user representation");
        goto cleanup;
    }

    long http_code = curl_perform_json(uri, HTTP_POST, user_repr,
                                        client.access_token->access_token, &chunk);

    if (http_code == 201) {
        result = KC_SUCCESS;
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user: User created successfully (HTTP 201)");
    } else if (http_code == 409) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user: User already exists (HTTP 409)");
        result = KC_USER_EXISTS;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (user_repr) {
        memset(user_repr, 0, strlen(user_repr));
        free(user_repr);
    }
    free(uri);

    return result;
}
#endif /* keycloak_create_user - DISABLED */

/**
 * Create a user in Keycloak with a pre-hashed PBKDF2 password.
 * Uses Keycloak's credential import format to avoid sending plaintext.
 *
 * @param realm       Keycloak realm configuration
 * @param client      Client with admin access token
 * @param username    New user's username
 * @param email       New user's email (can be empty string)
 * @param cred_data   credentialData JSON string from pw_export_keycloak()
 * @param secret_data secretData JSON string from pw_export_keycloak()
 * @return KC_SUCCESS, KC_USER_EXISTS, or KC_ERROR
 */
/* DISABLED: Use keycloak_create_user_with_hash_async instead */
#if 0
int keycloak_create_user_with_hash(struct kc_realm realm, struct kc_client client,
                                   const char* username, const char* email,
                                   const char* cred_data, const char* secret_data)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !username || !email || !cred_data || !secret_data) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user_with_hash: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = kc_build_users_endpoint(realm);
    char *user_repr = NULL;
    struct memory chunk = {0};

    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user_with_hash: Failed to build uri");
        goto cleanup;
    }

    user_repr = json_build_user_with_hash(username, email, cred_data, secret_data);
    if (!user_repr) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user_with_hash: Failed to build user representation");
        goto cleanup;
    }

    log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user_with_hash: Creating user %s with pre-hashed password",
               username);

    long http_code = curl_perform_json(uri, HTTP_POST, user_repr,
                                        client.access_token->access_token, &chunk);

    if (http_code == 201) {
        result = KC_SUCCESS;
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user_with_hash: User created successfully (HTTP 201)");
    } else if (http_code == 409) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user_with_hash: User already exists (HTTP 409)");
        result = KC_USER_EXISTS;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user_with_hash: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (user_repr) {
        memset(user_repr, 0, strlen(user_repr));
        free(user_repr);
    }
    free(uri);

    return result;
}
#endif /* keycloak_create_user_with_hash - DISABLED */

int keycloak_get_user(struct kc_realm realm, struct kc_client client,
                             const char *user, struct kc_user *kc_user_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !user || !kc_user_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user: Invalid arguments");
        return KC_ERROR;
    }

    /* Check user ID cache first (populated after user creation) */
    const char *cached_id = kc_userid_cache_get(user);
    if (cached_id) {
        /* Cache hit - return minimal user struct with just the ID */
        memset(kc_user_out, 0, sizeof(*kc_user_out));
        kc_user_out->id = strdup(cached_id);
        if (!kc_user_out->id) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user: Failed to copy cached ID");
            return KC_ERROR;
        }
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user: Cache hit for %s -> %s", user, cached_id);
        return KC_SUCCESS;
    }

    /* Cache miss - do full HTTP GET */
    struct kc_user* kc_users = NULL;
    int result = keycloak_get_users(realm, client, user, NULL, true, &kc_users);

    if (result >= 1) {
        /* User found - cache the ID for future lookups */
        if (kc_users[0].id) {
            kc_userid_cache_put(user, kc_users[0].id);
        }
        *kc_user_out = kc_users[0];
        free(kc_users);
        return KC_SUCCESS;
    } else if (result == KC_SUCCESS) {
        /* Empty array - user not found */
        return KC_NOT_FOUND;
    }

    /* Error (KC_ERROR, KC_FORBIDDEN, etc.) */
    return result;
}

void keycloak_free_users(struct kc_user* users, size_t count)
{
    if (!users) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        keycloak_user_free_fields(&users[i]);
    }

    free(users);
}

void keycloak_free_access_token(struct access_token* token)
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

/* DISABLED: Use keycloak_update_user_async instead */
#if 0
int keycloak_update_user(struct kc_realm realm, struct kc_client client,
                         const char* user_id, const char* new_password,
                         const char* new_email)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !user_id) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Invalid arguments");
        return KC_ERROR;
    }

    if (!new_password && !new_email) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Nothing to update");
        return KC_SUCCESS;
    }

    int result = KC_ERROR;
    char* uri = NULL;
    char* json_body = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    /* Update email if provided (requires PUT to user endpoint) */
    if (new_email) {
        uri = kc_build_user_endpoint(realm, user_id);
        if (!uri) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Failed to allocate uri");
            goto cleanup;
        }

        json_t* user_obj = json_object();
        json_object_set_new(user_obj, "email", json_string(new_email));
        json_body = json_dumps(user_obj, JSON_COMPACT);
        json_decref(user_obj);

        if (!json_body) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Failed to build JSON");
            goto cleanup;
        }

        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = uri;
        opts.method = HTTP_PUT;
        opts.post_fields = json_body;
        opts.xoauth2_bearer = client.access_token->access_token;
        opts.header_list[0] = "Content-Type: application/json";
        opts.header_count = 1;

        long http_code = curl_perform(opts, &chunk);

        if (http_code == 204) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Email updated (HTTP 204)");
            result = KC_SUCCESS;
        } else if (http_code == 404) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: User not found (HTTP 404)");
            result = KC_NOT_FOUND;
            goto cleanup;
        } else {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Failed with HTTP %ld: %s",
                http_code, chunk.response ? chunk.response : "no response");
            goto cleanup;
        }

        free(json_body);
        json_body = NULL;
        free(uri);
        uri = NULL;
        if (chunk.response) {
            free(chunk.response);
            chunk.response = NULL;
            chunk.size = 0;
        }
    }

    /* Update password if provided (requires PUT to reset-password endpoint) */
    if (new_password) {
        uri = kc_build_reset_password_endpoint(realm, user_id);
        if (!uri) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Failed to allocate uri");
            goto cleanup;
        }

        json_t* cred_obj = json_object();
        json_object_set_new(cred_obj, "type", json_string("password"));
        json_object_set_new(cred_obj, "value", json_string(new_password));
        json_object_set_new(cred_obj, "temporary", json_false());
        json_body = json_dumps(cred_obj, JSON_COMPACT);
        json_decref(cred_obj);

        if (!json_body) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Failed to build password JSON");
            goto cleanup;
        }

        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = uri;
        opts.method = HTTP_PUT;
        opts.post_fields = json_body;
        opts.xoauth2_bearer = client.access_token->access_token;
        opts.header_list[0] = "Content-Type: application/json";
        opts.header_count = 1;

        long http_code = curl_perform(opts, &chunk);

        if (http_code == 204) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Password updated (HTTP 204)");
            result = KC_SUCCESS;
        } else if (http_code == 404) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: User not found (HTTP 404)");
            result = KC_NOT_FOUND;
        } else {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Failed with HTTP %ld: %s",
                http_code, chunk.response ? chunk.response : "no response");
        }
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (json_body) {
        memset(json_body, 0, strlen(json_body));
        free(json_body);
    }
    if (uri) {
        free(uri);
    }

    return result;
}
#endif /* keycloak_update_user - DISABLED */

/* NOTE: keycloak_update_user_credentials() removed - was dead code (never called).
 * Use keycloak_update_user_representation() with kc_user_update.cred_data instead. */

/* DISABLED: Use keycloak_update_user_representation_async instead */
#if 0
int keycloak_update_user_representation(struct kc_realm realm, struct kc_client client,
                                        const char* user_id,
                                        const struct kc_user_update* update)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !user_id || !update) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_representation: Invalid arguments");
        return KC_ERROR;
    }

    /* Check if there's anything to update */
    if (!update->email && !update->cred_data) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_representation: Nothing to update");
        return KC_SUCCESS;
    }

    /* Credentials require both cred_data and secret_data */
    if (update->cred_data && !update->secret_data) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_representation: cred_data requires secret_data");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = kc_build_user_endpoint(realm, user_id);
    char *json_body = NULL;
    struct memory chunk = {0};

    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_representation: Failed to build uri");
        goto cleanup;
    }

    /* Build UserRepresentation JSON with requested fields */
    json_t* user_obj = json_object();

    if (update->email) {
        json_object_set_new(user_obj, "email", json_string(update->email));
    }

    if (update->cred_data && update->secret_data) {
        json_t* cred_obj = json_object();
        json_object_set_new(cred_obj, "type", json_string("password"));
        json_object_set_new(cred_obj, "credentialData", json_string(update->cred_data));
        json_object_set_new(cred_obj, "secretData", json_string(update->secret_data));

        json_t* creds_array = json_array();
        json_array_append_new(creds_array, cred_obj);
        json_object_set_new(user_obj, "credentials", creds_array);
    }

    json_body = json_dumps(user_obj, JSON_COMPACT);
    json_decref(user_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_representation: Failed to build JSON");
        goto cleanup;
    }

    log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_representation: Updating user %s (email=%s, creds=%s)",
               user_id, update->email ? "yes" : "no", update->cred_data ? "yes" : "no");

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_PUT;
    opts.post_fields = json_body;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 204) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_representation: Updated (HTTP 204)");
        result = KC_SUCCESS;
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_representation: User not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_representation: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (json_body) {
        memset(json_body, 0, strlen(json_body));
        free(json_body);
    }
    free(uri);

    return result;
}
#endif /* keycloak_update_user_representation - DISABLED */

/* DISABLED: Use keycloak_delete_user_async instead */
#if 0
int keycloak_delete_user(struct kc_realm realm, struct kc_client client,
                         const char* user_id)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !user_id) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_user: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = kc_build_user_endpoint(realm, user_id);
    struct memory chunk = {0};

    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_user: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_DELETE;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 204) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_user: User deleted (HTTP 204)");
        result = KC_SUCCESS;
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_user: User not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_user: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    free(uri);

    return result;
}
#endif /* keycloak_delete_user - DISABLED */

/**
 * Set a user attribute synchronously.
 *
 * Uses the user representation cache when available to safely merge the
 * attribute without clobbering other fields (email, firstName, etc.).
 * If cache miss, performs GET first to fetch the full representation.
 */
/* DISABLED: Use keycloak_set_user_attribute_async instead */
#if 0
int keycloak_set_user_attribute(struct kc_realm realm, struct kc_client client,
                                const char* user_id, const char* attr_name,
                                const char* attr_value)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !attr_name) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = NULL;
    char *json_body = NULL;
    struct memory chunk = {0};
    json_t *repr = NULL;

    uri = kc_build_user_endpoint(realm, user_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Failed to allocate uri");
        goto cleanup;
    }

    /* Check user representation cache */
    json_t *cached_repr = kc_user_repr_cache_get(user_id);

    if (cached_repr) {
        /* Cache hit - use cached representation */
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Cache hit for %s", user_id);
        repr = json_deep_copy(cached_repr);
    } else {
        /* Cache miss - fetch user first */
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Cache miss for %s, fetching", user_id);

        struct curl_opts get_opts = CURL_OPTS_INIT;
        get_opts.uri = uri;
        get_opts.method = HTTP_GET;
        get_opts.xoauth2_bearer = client.access_token->access_token;

        long http_code = curl_perform(get_opts, &chunk);

        if (http_code == 200 && chunk.response) {
            json_error_t error;
            repr = json_loads(chunk.response, 0, &error);
            if (repr) {
                /* Cache the fetched representation */
                json_t *id_json = json_object_get(repr, "id");
                if (id_json && json_is_string(id_json)) {
                    kc_user_repr_cache_put(json_string_value(id_json), repr);
                }
            } else {
                log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Failed to parse GET response: %s", error.text);
            }
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: User not found (HTTP 404)");
            goto cleanup;
        } else {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: GET failed with HTTP %ld", http_code);
            goto cleanup;
        }

        /* Clear GET response before PUT */
        if (chunk.response) {
            memset(chunk.response, 0, chunk.size);
            free(chunk.response);
            chunk.response = NULL;
            chunk.size = 0;
        }
    }

    if (!repr) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: No representation available");
        goto cleanup;
    }

    /* Get or create attributes object */
    json_t *attrs = json_object_get(repr, "attributes");
    if (!attrs) {
        attrs = json_object();
        json_object_set_new(repr, "attributes", attrs);
    }

    /* Set or delete the attribute */
    if (attr_value) {
        json_t* values = json_array();
        json_array_append_new(values, json_string(attr_value));
        json_object_set_new(attrs, attr_name, values);
    } else {
        /* NULL value = delete attribute */
        json_object_del(attrs, attr_name);
    }

    /* Serialize for PUT */
    json_body = json_dumps(repr, JSON_COMPACT);
    if (!json_body) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Failed to build JSON");
        goto cleanup;
    }

    /* Issue PUT with full representation */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_PUT;
    opts.post_fields = json_body;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 204) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Attribute set (HTTP 204)");
        result = KC_SUCCESS;
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: User not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (repr) {
        json_decref(repr);
    }
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (json_body) {
        free(json_body);
    }
    if (uri) {
        free(uri);
    }

    return result;
}
#endif /* keycloak_set_user_attribute - DISABLED */

/* DISABLED: Use keycloak_set_user_attribute_array_async instead */
#if 0
int keycloak_set_user_attribute_array(struct kc_realm realm, struct kc_client client,
                                      const char* user_id, const char* attr_name,
                                      const char** values, size_t value_count)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !attr_name) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute_array: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = NULL;
    char *json_body = NULL;
    struct memory chunk = {0};

    uri = kc_build_user_endpoint(realm, user_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute_array: Failed to allocate uri");
        goto cleanup;
    }

    /* Build JSON: { "attributes": { "attr_name": ["val1", "val2", ...] } } */
    json_t* user_obj = json_object();
    json_t* attrs = json_object();
    json_t* values_arr = json_array();

    for (size_t i = 0; i < value_count; i++) {
        if (values[i]) {
            json_array_append_new(values_arr, json_string(values[i]));
        }
    }

    json_object_set_new(attrs, attr_name, values_arr);
    json_object_set_new(user_obj, "attributes", attrs);
    json_body = json_dumps(user_obj, JSON_COMPACT);
    json_decref(user_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute_array: Failed to build JSON");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_PUT;
    opts.post_fields = json_body;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 204) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute_array: Attribute set (HTTP 204)");
        result = KC_SUCCESS;
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute_array: User not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute_array: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (json_body) {
        free(json_body);
    }
    if (uri) {
        free(uri);
    }

    return result;
}
#endif /* keycloak_set_user_attribute_array - DISABLED */

/* DISABLED: Use keycloak_get_user_attribute_async instead */
#if 0
int keycloak_get_user_attribute(struct kc_realm realm, struct kc_client client,
                                const char* user_id, const char* attr_name,
                                char** value_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !attr_name || !value_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_attribute: Invalid arguments");
        return KC_ERROR;
    }

    *value_out = NULL;
    int result = KC_ERROR;
    char *uri = NULL;
    struct memory chunk = {0};

    uri = kc_build_user_endpoint(realm, user_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_attribute: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 200 && chunk.response) {
        json_error_t error;
        json_t* root = json_loads(chunk.response, 0, &error);
        if (!root) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_attribute: Failed to parse JSON: %s", error.text);
            goto cleanup;
        }

        json_t* attrs = json_object_get(root, "attributes");
        if (attrs && json_is_object(attrs)) {
            json_t* attr_values = json_object_get(attrs, attr_name);
            if (attr_values && json_is_array(attr_values) && json_array_size(attr_values) > 0) {
                json_t* first_val = json_array_get(attr_values, 0);
                if (first_val && json_is_string(first_val)) {
                    const char* val_str = json_string_value(first_val);
                    *value_out = strdup(val_str);
                    if (*value_out) {
                        result = KC_SUCCESS;
                    }
                }
            } else {
                log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_attribute: Attribute '%s' not found", attr_name);
                result = KC_NOT_FOUND;
            }
        } else {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_attribute: No attributes on user");
            result = KC_NOT_FOUND;
        }

        json_decref(root);
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_attribute: User not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_attribute: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
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
#endif /* keycloak_get_user_attribute - DISABLED */

void keycloak_free_metadata_entries(struct kc_metadata_entry* entries)
{
    struct kc_metadata_entry* curr;
    struct kc_metadata_entry* next;

    for (curr = entries; curr; curr = next) {
        next = curr->next;
        if (curr->key)
            free(curr->key);
        if (curr->value)
            free(curr->value);
        free(curr);
    }
}

int keycloak_list_user_attributes(struct kc_realm realm, struct kc_client client,
                                  const char* user_id, const char* prefix,
                                  struct kc_metadata_entry** entries_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !entries_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: Invalid arguments");
        return KC_ERROR;
    }

    *entries_out = NULL;
    int result = KC_ERROR;
    char *uri = NULL;
    struct memory chunk = {0};
    size_t prefix_len = prefix ? strlen(prefix) : 0;

    uri = kc_build_user_endpoint(realm, user_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 200 && chunk.response) {
        json_error_t error;
        json_t* root = json_loads(chunk.response, 0, &error);
        if (!root) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: Failed to parse JSON: %s", error.text);
            goto cleanup;
        }

        json_t* attrs = json_object_get(root, "attributes");
        if (attrs && json_is_object(attrs)) {
            const char* key;
            json_t* value;
            struct kc_metadata_entry* head = NULL;
            struct kc_metadata_entry* tail = NULL;

            json_object_foreach(attrs, key, value) {
                /* Skip if prefix specified and doesn't match */
                if (prefix && prefix_len > 0) {
                    if (strncmp(key, prefix, prefix_len) != 0)
                        continue;
                }

                /* Get first value from array */
                if (!json_is_array(value) || json_array_size(value) == 0)
                    continue;

                json_t* first_val = json_array_get(value, 0);
                if (!first_val || !json_is_string(first_val))
                    continue;

                const char* val_str = json_string_value(first_val);
                if (!val_str || !*val_str)
                    continue;

                /* Create entry */
                struct kc_metadata_entry* entry = malloc(sizeof(*entry));
                if (!entry)
                    continue;

                entry->key = strdup(key);
                entry->value = strdup(val_str);
                entry->next = NULL;

                if (!entry->key || !entry->value) {
                    if (entry->key) free(entry->key);
                    if (entry->value) free(entry->value);
                    free(entry);
                    continue;
                }

                /* Add to list */
                if (!head) {
                    head = tail = entry;
                } else {
                    tail->next = entry;
                    tail = entry;
                }
            }

            *entries_out = head;
            result = KC_SUCCESS;
        } else {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: No attributes on user");
            result = KC_SUCCESS; /* Empty list is valid */
        }

        json_decref(root);
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: User not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
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

/* DISABLED: Use keycloak_add_user_to_group_async instead */
#if 0
int keycloak_add_user_to_group(struct kc_realm realm, struct kc_client client,
                               const char* user_id, const char* group_id)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !group_id) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_add_user_to_group: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    struct memory chunk = {0};

    /* Build URI using endpoint builder */
    char *uri = kc_build_user_group_endpoint(realm, user_id, group_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_add_user_to_group: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_PUT;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 204) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_add_user_to_group: User added to group (HTTP 204)");
        result = KC_SUCCESS;
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_add_user_to_group: User or group not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_add_user_to_group: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    free(uri);

    return result;
}
#endif /* keycloak_add_user_to_group - DISABLED */

/* DISABLED: Use keycloak_remove_user_from_group_async instead */
#if 0
int keycloak_remove_user_from_group(struct kc_realm realm, struct kc_client client,
                                    const char* user_id, const char* group_id)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !group_id) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_remove_user_from_group: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    struct memory chunk = {0};

    /* Build URI using endpoint builder */
    char *uri = kc_build_user_group_endpoint(realm, user_id, group_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_remove_user_from_group: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_DELETE;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 204) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_remove_user_from_group: User removed from group (HTTP 204)");
        result = KC_SUCCESS;
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_remove_user_from_group: User or group not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_remove_user_from_group: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
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
#endif /* keycloak_remove_user_from_group - DISABLED */

int keycloak_get_group_by_name(struct kc_realm realm, struct kc_client client,
                               const char* group_name, char** group_id_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_name || !group_id_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Invalid arguments");
        return KC_ERROR;
    }

    *group_id_out = NULL;
    int result = KC_ERROR;
    char *uri = NULL;
    char *escaped_name = NULL;
    struct memory chunk = {0};

    escaped_name = curl_easy_escape(NULL, group_name, 0);
    if (!escaped_name) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Failed to escape group name");
        goto cleanup;
    }

    /* Build URI using endpoint builder */
    uri = kc_build_group_search_endpoint(realm, escaped_name);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 200 && chunk.response) {
        json_error_t error;
        json_t* root = json_loads(chunk.response, 0, &error);
        if (!root) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Failed to parse JSON: %s", error.text);
            goto cleanup;
        }

        if (json_is_array(root) && json_array_size(root) > 0) {
            json_t* first_group = json_array_get(root, 0);
            json_t* id_val = json_object_get(first_group, "id");
            if (id_val && json_is_string(id_val)) {
                *group_id_out = pool_strdup(json_string_value(id_val));
                if (*group_id_out) {
                    result = KC_SUCCESS;
                    log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Found group '%s' with ID '%s'",
                        group_name, *group_id_out);
                }
            }
        } else {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Group '%s' not found", group_name);
            result = KC_NOT_FOUND;
        }

        json_decref(root);
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (escaped_name) {
        curl_free(escaped_name);
    }
    if (uri) {
        free(uri);
    }

    return result;
}

/* DISABLED: Use keycloak_get_group_by_path_async instead */
#if 0
int keycloak_get_group_by_path(struct kc_realm realm, struct kc_client client,
                               const char* group_path, char** group_id_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_path || !group_id_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_path: Invalid arguments");
        return KC_ERROR;
    }

    *group_id_out = NULL;
    int result = KC_ERROR;
    struct memory chunk = {0};

    /* Build URI using endpoint builder (path should start with /) */
    char *uri = kc_build_group_by_path_endpoint(realm, group_path);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_path: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_path: Path '%s' not found", group_path);
        result = KC_NOT_FOUND;
        goto cleanup;
    }

    if (http_code == 200 && chunk.response) {
        json_error_t error;
        json_t* root = json_loads(chunk.response, 0, &error);
        if (!root) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_path: Failed to parse JSON: %s", error.text);
            goto cleanup;
        }

        /* Response is a single group object with "id" field */
        if (json_is_object(root)) {
            json_t* id_val = json_object_get(root, "id");
            if (id_val && json_is_string(id_val)) {
                *group_id_out = pool_strdup(json_string_value(id_val));
                if (*group_id_out) {
                    result = KC_SUCCESS;
                    log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_path: Found group at '%s' with ID '%s'",
                        group_path, *group_id_out);
                }
            }
        }

        json_decref(root);
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_path: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    free(uri);

    return result;
}
#endif /* keycloak_get_group_by_path - DISABLED */

static int json_read_token_info(const char* response, struct kc_token_info** info_out)
{
    if (!response || !info_out) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_token_info: Invalid arguments");
        return KC_ERROR;
    }

    *info_out = NULL;
    json_error_t error;
    json_t* root = json_loads(response, 0, &error);
    if (!root) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_token_info: Failed to parse JSON: %s", error.text);
        return KC_ERROR;
    }

    int result = KC_ERROR;

    if (!json_is_object(root)) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_token_info: Response is not an object");
        goto cleanup;
    }

    struct kc_token_info* info = malloc(sizeof(struct kc_token_info));
    if (!info) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_token_info: Failed to allocate token info");
        goto cleanup;
    }
    memset(info, 0, sizeof(*info));

    // Check if token is active
    json_t* active = json_object_get(root, "active");
    info->active = active && json_is_boolean(active) && json_boolean_value(active);

    if (!info->active) {
        log_module(KC_LOG, LOG_DEBUG, "json_read_token_info: Token is not active");
        *info_out = info;
        result = KC_FORBIDDEN;
        goto cleanup;
    }

    // Extract optional fields
    json_read_object_string(root, "username", &info->username, &info->username_size);
    json_read_object_string(root, "email", &info->email, &info->email_size);
    json_read_object_string(root, "sub", &info->sub, &info->sub_size);

    // Extract timestamps
    json_t* exp = json_object_get(root, "exp");
    if (exp && json_is_integer(exp)) {
        info->exp = json_integer_value(exp);
    }

    json_t* iat = json_object_get(root, "iat");
    if (iat && json_is_integer(iat)) {
        info->iat = json_integer_value(iat);
    }

    // Try to extract opserv_level from token claims (custom claim)
    json_t* oslevel = json_object_get(root, "x3_opserv_level");
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

int keycloak_introspect_token(struct kc_realm realm, struct kc_client client,
                              const char* bearer_token,
                              struct kc_token_info** info_out)
{
    if (!realm.base_uri || !realm.realm || !client.client_id ||
        !client.client_secret || !bearer_token || !info_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_introspect_token: Invalid arguments");
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
        log_module(KC_LOG, LOG_DEBUG, "keycloak_introspect_token: Failed to allocate uri");
        goto cleanup;
    }

    /* URL-encode token */
    escaped_token = curl_easy_escape(NULL, bearer_token, 0);
    if (!escaped_token) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_introspect_token: Failed to escape token");
        goto cleanup;
    }

    /* Build POST body */
    static const char post_tmpl[] = "token=%s&token_type_hint=access_token";
    int post_len = snprintf(NULL, 0, post_tmpl, escaped_token) + 1;
    post_fields = malloc(post_len);
    if (!post_fields) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_introspect_token: Failed to allocate post_fields");
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
            log_module(KC_LOG, LOG_DEBUG, "keycloak_introspect_token: Token is valid, user: %s",
                (*info_out)->username ? (*info_out)->username : "unknown");
        } else if (result == KC_FORBIDDEN) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_introspect_token: Token is inactive/invalid");
        }
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_introspect_token: Failed with HTTP %ld: %s",
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

void keycloak_free_token_info(struct kc_token_info* info)
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

/* DISABLED: Use keycloak_get_group_members_async instead */
#if 0
int keycloak_get_group_members(struct kc_realm realm, struct kc_client client,
                               const char* group_id, struct kc_group_member** members_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !members_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_members: Invalid arguments");
        return KC_ERROR;
    }

    *members_out = NULL;
    int result = KC_ERROR;
    int member_count = 0;
    struct memory chunk = {0};

    /* Build URI using endpoint builder */
    char *uri = kc_build_group_members_endpoint(realm, group_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_members: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_members: Group '%s' not found", group_id);
        result = KC_NOT_FOUND;
        goto cleanup;
    }

    if (http_code == 200 && chunk.response) {
        json_error_t error;
        json_t* root = json_loads(chunk.response, 0, &error);
        if (!root) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_members: Failed to parse JSON: %s", error.text);
            goto cleanup;
        }

        if (json_is_array(root)) {
            size_t array_size = json_array_size(root);
            struct kc_group_member* head = NULL;
            struct kc_group_member* tail = NULL;

            for (size_t i = 0; i < array_size; i++) {
                json_t* user_obj = json_array_get(root, i);
                json_t* id_val = json_object_get(user_obj, "id");
                json_t* username_val = json_object_get(user_obj, "username");

                if (id_val && json_is_string(id_val) &&
                    username_val && json_is_string(username_val)) {
                    struct kc_group_member* member = malloc(sizeof(struct kc_group_member));
                    if (!member) {
                        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_members: Failed to allocate member");
                        continue;
                    }
                    memset(member, 0, sizeof(*member));

                    member->user_id = strdup(json_string_value(id_val));
                    member->username = strdup(json_string_value(username_val));
                    member->next = NULL;

                    if (!member->user_id || !member->username) {
                        if (member->user_id) free(member->user_id);
                        if (member->username) free(member->username);
                        free(member);
                        continue;
                    }

                    /* Append to linked list */
                    if (!head) {
                        head = member;
                        tail = member;
                    } else {
                        tail->next = member;
                        tail = member;
                    }
                    member_count++;
                }
            }

            *members_out = head;
            result = member_count;
            log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_members: Found %d members in group '%s'",
                member_count, group_id);
        }

        json_decref(root);
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_members: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
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
#endif /* keycloak_get_group_members - DISABLED */

void keycloak_free_group_members(struct kc_group_member* members)
{
    while (members) {
        struct kc_group_member* next = members->next;
        if (members->username) {
            free(members->username);
        }
        if (members->user_id) {
            free(members->user_id);
        }
        free(members);
        members = next;
    }
}

void keycloak_free_group_info(struct kc_group_info* info)
{
    if (!info)
        return;

    if (info->id)
        free(info->id);
    if (info->name)
        free(info->name);
    if (info->path)
        free(info->path);
    if (info->attributes)
        keycloak_free_metadata_entries(info->attributes);

    free(info);
}

/* DISABLED: Use keycloak_get_group_info_async instead */
#if 0
int keycloak_get_group_info(struct kc_realm realm, struct kc_client client,
                            const char* group_id, struct kc_group_info** info_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !info_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_info: Invalid arguments");
        return KC_ERROR;
    }

    *info_out = NULL;
    int result = KC_ERROR;
    char *uri = NULL;
    struct memory chunk = {0};

    /* Build URI using endpoint builder */
    uri = kc_build_group_endpoint(realm, group_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_info: Failed to allocate uri");
        return KC_ERROR;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 404) {
        result = KC_NOT_FOUND;
        goto cleanup;
    }

    if (http_code != 200 || !chunk.response) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_info: Failed with HTTP %ld", http_code);
        goto cleanup;
    }

    /* Parse JSON response */
    json_error_t error;
    json_t* root = json_loads(chunk.response, 0, &error);
    if (!root) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_info: Failed to parse JSON: %s", error.text);
        goto cleanup;
    }

    if (!json_is_object(root)) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_info: Response is not an object");
        json_decref(root);
        goto cleanup;
    }

    /* Allocate group info struct */
    struct kc_group_info* info = calloc(1, sizeof(struct kc_group_info));
    if (!info) {
        json_decref(root);
        goto cleanup;
    }

    /* Extract basic fields */
    const char* id_val = json_string_value(json_object_get(root, "id"));
    const char* name_val = json_string_value(json_object_get(root, "name"));
    const char* path_val = json_string_value(json_object_get(root, "path"));

    if (id_val) info->id = strdup(id_val);
    if (name_val) info->name = strdup(name_val);
    if (path_val) info->path = strdup(path_val);

    /* Parse attributes */
    json_t* attrs = json_object_get(root, "attributes");
    if (attrs && json_is_object(attrs)) {
        const char* key;
        json_t* value;
        struct kc_metadata_entry* head = NULL;
        struct kc_metadata_entry* tail = NULL;

        json_object_foreach(attrs, key, value) {
            /* Attributes are arrays, get first element */
            const char* val_str = NULL;
            if (json_is_array(value) && json_array_size(value) > 0) {
                val_str = json_string_value(json_array_get(value, 0));
            } else if (json_is_string(value)) {
                val_str = json_string_value(value);
            }

            if (key && val_str) {
                struct kc_metadata_entry* entry = calloc(1, sizeof(*entry));
                if (entry) {
                    entry->key = strdup(key);
                    entry->value = strdup(val_str);
                    entry->next = NULL;

                    if (!head) {
                        head = tail = entry;
                    } else {
                        tail->next = entry;
                        tail = entry;
                    }

                    /* Check for x3_access_level */
                    if (strcmp(key, "x3_access_level") == 0) {
                        info->access_level = (unsigned short)atoi(val_str);
                        log_module(KC_LOG, LOG_DEBUG,
                                   "keycloak_get_group_info: Found x3_access_level=%d",
                                   info->access_level);
                    }
                }
            }
        }
        info->attributes = head;
    }

    *info_out = info;
    result = KC_SUCCESS;
    json_decref(root);

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
#endif /* keycloak_get_group_info - DISABLED */

/* DISABLED: Use keycloak_get_group_attribute_async instead */
#if 0
int keycloak_get_group_attribute(struct kc_realm realm, struct kc_client client,
                                 const char* group_id, const char* attr_name,
                                 char** value_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !attr_name || !value_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_attribute: Invalid arguments");
        return KC_ERROR;
    }

    *value_out = NULL;

    /* Fetch full group info */
    struct kc_group_info* info = NULL;
    int rc = keycloak_get_group_info(realm, client, group_id, &info);
    if (rc != KC_SUCCESS) {
        return rc;
    }

    /* Search for the attribute */
    int result = KC_NOT_FOUND;
    for (struct kc_metadata_entry* e = info->attributes; e; e = e->next) {
        if (strcmp(e->key, attr_name) == 0) {
            *value_out = strdup(e->value);
            if (*value_out) {
                result = KC_SUCCESS;
            } else {
                result = KC_ERROR;
            }
            break;
        }
    }

    keycloak_free_group_info(info);
    return result;
}
#endif /* keycloak_get_group_attribute - DISABLED */

/* DISABLED: Use keycloak_get_group_members_with_level_async instead */
#if 0
int keycloak_get_group_members_with_level(struct kc_realm realm, struct kc_client client,
                                          const char* group_id, struct kc_group_member** members_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !members_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_members_with_level: Invalid arguments");
        return KC_ERROR;
    }

    *members_out = NULL;

    /* First, get the group info to get the access level */
    struct kc_group_info* info = NULL;
    int rc = keycloak_get_group_info(realm, client, group_id, &info);
    if (rc != KC_SUCCESS) {
        return rc;
    }

    unsigned short access_level = info->access_level;
    keycloak_free_group_info(info);

    /* Now get the group members */
    struct kc_group_member* members = NULL;
    rc = keycloak_get_group_members(realm, client, group_id, &members);
    if (rc < 0) {
        return rc;
    }

    /* Set access_level on all members */
    for (struct kc_group_member* m = members; m; m = m->next) {
        m->access_level = access_level;
    }

    *members_out = members;
    return rc; /* Returns count of members */
}
#endif /* keycloak_get_group_members_with_level - DISABLED */

int keycloak_find_user_by_fingerprint(struct kc_realm realm, struct kc_client client,
                                       const char* fingerprint, char** username_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !fingerprint || !username_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Invalid arguments");
        return KC_ERROR;
    }

    *username_out = NULL;
    int result = KC_ERROR;
    char *uri = NULL;
    char *escaped_fp = NULL;
    struct memory chunk = {0};

    /* URL-encode the fingerprint for the query parameter */
    escaped_fp = curl_easy_escape(NULL, fingerprint, 0);
    if (!escaped_fp) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Failed to escape fingerprint");
        goto cleanup;
    }

    /* Build the search URI using endpoint builder */
    uri = kc_build_fingerprint_search_endpoint(realm, escaped_fp);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code != 200 || !chunk.response) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Failed with HTTP %ld",
            http_code);
        goto cleanup;
    }

    /* Parse JSON array response */
    json_error_t error;
    json_t* root = json_loads(chunk.response, 0, &error);
    if (!root) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Failed to parse JSON: %s",
            error.text);
        goto cleanup;
    }

    if (!json_is_array(root)) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Response is not an array");
        json_decref(root);
        goto cleanup;
    }

    size_t count = json_array_size(root);

    if (count == 0) {
        /* Fingerprint not registered to any user */
        log_module(KC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Fingerprint not found");
        result = KC_NOT_FOUND;
        json_decref(root);
        goto cleanup;
    }

    if (count > 1) {
        /* Fingerprint collision! This should never happen if uniqueness is enforced */
        log_module(KC_LOG, LOG_ERROR,
                   "SECURITY: Fingerprint %s registered to %zu users!",
                   fingerprint, count);
        result = KC_COLLISION;
        json_decref(root);
        goto cleanup;
    }

    /* Exactly one user - extract username */
    json_t* user = json_array_get(root, 0);
    const char* username = json_string_value(json_object_get(user, "username"));

    if (username) {
        *username_out = strdup(username);
        if (*username_out) {
            result = KC_SUCCESS;
            log_module(KC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Found user '%s'",
                *username_out);
        }
    }

    json_decref(root);

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (escaped_fp) {
        curl_free(escaped_fp);
    }
    if (uri) {
        free(uri);
    }

    return result;
}

int keycloak_create_group(struct kc_realm realm, struct kc_client client,
                          const char* group_name, char** group_id_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !group_name) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_group: Invalid arguments");
        return KC_ERROR;
    }

    if (group_id_out)
        *group_id_out = NULL;

    int result = KC_ERROR;
    char *uri = NULL;
    char *json_body = NULL;
    struct memory chunk = {0};

    /* Build URI using endpoint builder */
    uri = kc_build_groups_endpoint(realm);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_group: Failed to allocate uri");
        goto cleanup;
    }

    /* Build JSON: { "name": "group_name" } */
    json_t* group_obj = json_object();
    json_object_set_new(group_obj, "name", json_string(group_name));
    json_body = json_dumps(group_obj, JSON_COMPACT);
    json_decref(group_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_group: Failed to build JSON");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_POST;
    opts.post_fields = json_body;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 201) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_group: Group '%s' created (HTTP 201)",
            group_name);
        result = KC_SUCCESS;

        /* Try to get the group ID - need to look it up since Keycloak doesn't return it */
        if (group_id_out) {
            keycloak_get_group_by_name(realm, client, group_name, group_id_out);
        }
    } else if (http_code == 409) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_group: Group '%s' already exists (HTTP 409)",
            group_name);
        result = KC_USER_EXISTS;

        /* Still get the ID if requested */
        if (group_id_out) {
            keycloak_get_group_by_name(realm, client, group_name, group_id_out);
        }
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_group: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (json_body) {
        free(json_body);
    }
    if (uri) {
        free(uri);
    }

    return result;
}

/* DISABLED: Use keycloak_create_subgroup_async instead */
#if 0
int keycloak_create_subgroup(struct kc_realm realm, struct kc_client client,
                             const char* parent_id, const char* group_name,
                             char** group_id_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !parent_id || !group_name) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_subgroup: Invalid arguments");
        return KC_ERROR;
    }

    if (group_id_out)
        *group_id_out = NULL;

    int result = KC_ERROR;
    char *json_body = NULL;
    struct memory chunk = {0};

    /* Build URI using endpoint builder */
    char *uri = kc_build_group_children_endpoint(realm, parent_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_subgroup: Failed to allocate uri");
        goto cleanup;
    }

    /* Build JSON: { "name": "group_name" } */
    json_t* group_obj = json_object();
    json_object_set_new(group_obj, "name", json_string(group_name));
    json_body = json_dumps(group_obj, JSON_COMPACT);
    json_decref(group_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_subgroup: Failed to build JSON");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_POST;
    opts.post_fields = json_body;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 201) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_subgroup: Subgroup '%s' created (HTTP 201)",
            group_name);
        result = KC_SUCCESS;

        /* Get the group ID by looking up by path */
        if (group_id_out) {
            /* We need to get parent info to build the path */
            struct kc_group_info* parent_info = NULL;
            if (keycloak_get_group_info(realm, client, parent_id, &parent_info) == KC_SUCCESS) {
                /* Build child path: parent_path + "/" + group_name */
                char* child_path = NULL;
                int path_len = snprintf(NULL, 0, "%s/%s", parent_info->path, group_name) + 1;
                child_path = malloc(path_len);
                if (child_path) {
                    snprintf(child_path, path_len, "%s/%s", parent_info->path, group_name);
                    keycloak_get_group_by_path(realm, client, child_path, group_id_out);
                    free(child_path);
                }
                keycloak_free_group_info(parent_info);
            }
        }
    } else if (http_code == 409) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_subgroup: Subgroup '%s' already exists (HTTP 409)",
            group_name);
        result = KC_USER_EXISTS;
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_subgroup: Parent group not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_subgroup: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (json_body) {
        free(json_body);
    }
    if (uri) {
        free(uri);
    }

    return result;
}
#endif /* keycloak_create_subgroup - DISABLED */

/* DISABLED: Use keycloak_set_group_attribute_async instead */
#if 0
int keycloak_set_group_attribute(struct kc_realm realm, struct kc_client client,
                                 const char* group_id, const char* attr_name,
                                 const char* attr_value)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !attr_name || !attr_value) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_group_attribute: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = NULL;
    char *json_body = NULL;
    struct memory chunk = {0};

    /* First, get the existing group to preserve its current state */
    struct kc_group_info* info = NULL;
    int rc = keycloak_get_group_info(realm, client, group_id, &info);
    if (rc == KC_NOT_FOUND) {
        return KC_NOT_FOUND;
    }
    if (rc != KC_SUCCESS || !info) {
        return KC_ERROR;
    }

    /* Build URI using endpoint builder */
    uri = kc_build_group_endpoint(realm, group_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_group_attribute: Failed to allocate uri");
        keycloak_free_group_info(info);
        goto cleanup;
    }

    /* Build JSON with existing attributes + new attribute */
    json_t* group_obj = json_object();
    json_t* attrs = json_object();

    /* Copy existing attributes */
    for (struct kc_metadata_entry* e = info->attributes; e; e = e->next) {
        json_t* values = json_array();
        json_array_append_new(values, json_string(e->value));
        json_object_set_new(attrs, e->key, values);
    }

    /* Add/update the new attribute */
    json_t* new_values = json_array();
    json_array_append_new(new_values, json_string(attr_value));
    json_object_set_new(attrs, attr_name, new_values);

    json_object_set_new(group_obj, "name", json_string(info->name));
    json_object_set_new(group_obj, "attributes", attrs);

    json_body = json_dumps(group_obj, JSON_COMPACT);
    json_decref(group_obj);
    keycloak_free_group_info(info);

    if (!json_body) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_group_attribute: Failed to build JSON");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_PUT;
    opts.post_fields = json_body;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 204) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_group_attribute: Attribute '%s' set on group (HTTP 204)",
            attr_name);
        result = KC_SUCCESS;
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_group_attribute: Group not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_group_attribute: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
    }

cleanup:
    if (chunk.response) {
        memset(chunk.response, 0, chunk.size);
        free(chunk.response);
    }
    if (json_body) {
        free(json_body);
    }
    if (uri) {
        free(uri);
    }

    return result;
}
#endif /* keycloak_set_group_attribute - DISABLED */

/* DISABLED: Use keycloak_delete_group_async instead */
#if 0
int keycloak_delete_group(struct kc_realm realm, struct kc_client client,
                          const char* group_id)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !group_id) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_group: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = NULL;
    struct memory chunk = {0};

    /* Build URI using endpoint builder */
    uri = kc_build_group_endpoint(realm, group_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_group: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_DELETE;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 204) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_group: Group deleted (HTTP 204)");
        result = KC_SUCCESS;
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_group: Group not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_group: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
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
#endif /* keycloak_delete_group - DISABLED */

int keycloak_ensure_channels_parent(struct kc_realm realm, struct kc_client client,
                                    char** group_id_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !group_id_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_ensure_channels_parent: Invalid arguments");
        return KC_ERROR;
    }

    *group_id_out = NULL;

    /* Try to find existing "irc-channels" group */
    static const char parent_name[] = "irc-channels";
    int rc = keycloak_get_group_by_name(realm, client, parent_name, group_id_out);

    if (rc == KC_SUCCESS && *group_id_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_ensure_channels_parent: Found existing parent group");
        return KC_SUCCESS;
    }

    /* Create the parent group */
    log_module(KC_LOG, LOG_DEBUG, "keycloak_ensure_channels_parent: Creating parent group '%s'",
        parent_name);

    rc = keycloak_create_group(realm, client, parent_name, group_id_out);
    if (rc == KC_SUCCESS || rc == KC_USER_EXISTS) {
        return KC_SUCCESS;
    }

    return KC_ERROR;
}

/* DISABLED: Unused sync function - use async workflow via chanserv_push_keycloak_access_async
 * This function chains multiple sync HTTP calls and would block the event loop.
 */
#if 0
int keycloak_create_channel_group(struct kc_realm realm, struct kc_client client,
                                  const char* channel_name, unsigned short access_level,
                                  char** group_id_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !channel_name) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_channel_group: Invalid arguments");
        return KC_ERROR;
    }

    if (group_id_out)
        *group_id_out = NULL;

    int result = KC_ERROR;
    char* parent_id = NULL;
    char* channel_group_id = NULL;

    /* Step 1: Ensure parent "irc-channels" group exists */
    int rc = keycloak_ensure_channels_parent(realm, client, &parent_id);
    if (rc != KC_SUCCESS || !parent_id) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_channel_group: Failed to ensure parent group");
        goto cleanup;
    }

    /* Step 2: Create or get the channel group */
    rc = keycloak_create_subgroup(realm, client, parent_id, channel_name, &channel_group_id);
    if (rc != KC_SUCCESS && rc != KC_USER_EXISTS) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_channel_group: Failed to create channel group");
        goto cleanup;
    }

    /* If group already existed, we need to look up its ID */
    if (!channel_group_id) {
        char* path = NULL;
        int path_len = snprintf(NULL, 0, "/irc-channels/%s", channel_name) + 1;
        path = malloc(path_len);
        if (path) {
            snprintf(path, path_len, "/irc-channels/%s", channel_name);
            keycloak_get_group_by_path(realm, client, path, &channel_group_id);
            free(path);
        }
    }

    if (!channel_group_id) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_channel_group: Failed to get channel group ID");
        goto cleanup;
    }

    /* Step 3: Set the access level attribute */
    char level_str[16];
    snprintf(level_str, sizeof(level_str), "%u", access_level);

    rc = keycloak_set_group_attribute(realm, client, channel_group_id,
                                      "x3_access_level", level_str);
    if (rc != KC_SUCCESS) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_channel_group: Failed to set access_level attribute");
        goto cleanup;
    }

    log_module(KC_LOG, LOG_DEBUG, "keycloak_create_channel_group: Created/updated group for %s with level %u",
        channel_name, access_level);

    result = KC_SUCCESS;

    if (group_id_out) {
        *group_id_out = channel_group_id;
        channel_group_id = NULL; /* Don't free it */
    }

cleanup:
    if (parent_id) {
        free(parent_id);
    }
    if (channel_group_id) {
        free(channel_group_id);
    }

    return result;
}
#endif /* keycloak_create_channel_group - DISABLED */

/*
 * Start async group info lookup against Keycloak
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_get_group_info_async(struct kc_realm realm, struct kc_client client,
                               const char *group_id, void *session,
                               kc_group_info_callback callback)
{
    struct kc_async_request *req = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "group_info_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "group_info_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GROUP_INFO;
    req->cb.group_info = callback;

    /* Build URI using endpoint builder */
    req->uri = kc_build_group_endpoint(realm, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "group_info_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "group_info_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "group_info_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "group_info_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "group_info_async: Started async lookup for group %s", group_id);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

/*
 * Start async group members lookup against Keycloak
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_get_group_members_async(struct kc_realm realm, struct kc_client client,
                                  const char *group_id, void *session,
                                  kc_group_members_callback callback)
{
    struct kc_async_request *req = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "group_members_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "group_members_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GROUP_MEMBERS;
    req->cb.group_members = callback;

    /* Build URI using endpoint builder */
    req->uri = kc_build_group_members_endpoint(realm, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "group_members_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "group_members_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "group_members_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "group_members_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "group_members_async: Started async lookup for group %s", group_id);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

/*
 * Phase 3: Async get user by username
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_get_user_async(struct kc_realm realm, struct kc_client client,
                         const char *username, void *session,
                         kc_get_user_callback callback)
{
    struct kc_async_request *req = NULL;
    char *escaped_user = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !username || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "get_user_async: Invalid arguments");
        return -1;
    }

    /* Check user ID cache first */
    const char *cached_id = kc_userid_cache_get(username);
    if (cached_id) {
        /* Cache hit - create minimal user struct and call callback directly */
        struct kc_user user = {0};
        user.id = strdup(cached_id);
        if (user.id) {
            user.username = strdup(username);
            log_module(KC_LOG, LOG_DEBUG, "get_user_async: Cache hit for %s -> %s", username, cached_id);
            callback(session, KC_SUCCESS, &user);
            return 0;
        }
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "get_user_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GET_USER;
    req->cb.get_user = callback;

    /* URL-encode username */
    escaped_user = curl_easy_escape(NULL, username, 0);
    if (!escaped_user) {
        log_module(KC_LOG, LOG_DEBUG, "get_user_async: Failed to escape username");
        goto error;
    }

    /* Build URI: /admin/realms/{realm}/users?username={user}&exact=true */
    req->uri = kc_build_user_by_username_endpoint(realm, escaped_user, 1);
    curl_free(escaped_user);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "get_user_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "get_user_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "get_user_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "get_user_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "get_user_async: Started async lookup for %s", username);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
    }
    return -1;
}

/*
 * Phase 3: Async update user representation
 *
 * IMPORTANT: Keycloak PUT requires the FULL user representation, not a diff.
 * This function uses the user representation cache to merge updates into the
 * complete representation before sending.
 *
 * Flow:
 * 1. Check cache for user representation
 * 2. If cache hit: merge updates into cached repr, PUT directly
 * 3. If cache miss: GET user first, cache it, merge, then PUT
 *
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_update_user_representation_async(struct kc_realm realm, struct kc_client client,
                                           const char *user_id,
                                           const struct kc_user_update *update,
                                           void *session,
                                           kc_update_user_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !update || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "update_user_async: Invalid arguments");
        return -1;
    }

    /* Check if there's anything to update */
    if (!update->email && !update->cred_data) {
        log_module(KC_LOG, LOG_DEBUG, "update_user_async: Nothing to update");
        /* Call callback with success immediately */
        callback(session, KC_SUCCESS);
        return 0;
    }

    /* Credentials require both cred_data and secret_data */
    if (update->cred_data && !update->secret_data) {
        log_module(KC_LOG, LOG_DEBUG, "update_user_async: cred_data requires secret_data");
        return -1;
    }

    /* Check if we have a valid token */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "update_user_async: No valid token available");
        return -1;
    }

    /* Check user representation cache */
    json_t *cached_repr = kc_user_repr_cache_get(user_id);

    if (cached_repr) {
        /* Cache hit - merge updates into cached representation and PUT directly */
        log_module(KC_LOG, LOG_DEBUG, "update_user_async: Cache hit for %s, merging updates", user_id);

        /* Deep copy the representation so we can modify it */
        json_t *repr = json_deep_copy(cached_repr);
        if (!repr) {
            log_module(KC_LOG, LOG_ERROR, "update_user_async: Failed to copy cached repr");
            return -1;
        }

        /* Strip any existing credentials - Keycloak treats credentials in PUT as "add"
         * not "replace", so we must not include old credentials. kc_user_repr_cache_put
         * already strips them, but be defensive for any old cached entries. */
        json_object_del(repr, "credentials");

        /* Merge email if provided */
        if (update->email) {
            json_object_set_new(repr, "email", json_string(update->email));

            /* Update cache with merged repr (now includes email, no credentials).
             * This ensures subsequent operations see the email we're about to set. */
            kc_user_repr_cache_put(user_id, repr);
        }

        /* Add credentials if provided - these are new credentials to set */
        if (update->cred_data && update->secret_data) {
            json_t *cred = json_object();
            json_object_set_new(cred, "type", json_string("password"));
            json_object_set_new(cred, "credentialData", json_string(update->cred_data));
            json_object_set_new(cred, "secretData", json_string(update->secret_data));
            json_object_set_new(cred, "temporary", json_false());

            json_t *creds = json_array();
            json_array_append_new(creds, cred);
            json_object_set_new(repr, "credentials", creds);
        }

        /* Serialize for PUT */
        json_body = json_dumps(repr, JSON_COMPACT);
        json_decref(repr);

        if (!json_body) {
            log_module(KC_LOG, LOG_ERROR, "update_user_async: Failed to serialize JSON");
            return -1;
        }

        /* Build PUT request */
        req = calloc(1, sizeof(*req));
        if (!req) {
            log_module(KC_LOG, LOG_ERROR, "update_user_async: Out of memory");
            free(json_body);
            return -1;
        }

        req->session = session;
        req->type = KC_ASYNC_UPDATE_USER;
        req->cb.update_user = callback;
        req->uri = kc_build_user_endpoint(realm, user_id);
        req->post_fields = json_body;
        req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);

        if (!req->uri || !req->bearer_token_copy) {
            log_module(KC_LOG, LOG_ERROR, "update_user_async: Failed to build request");
            goto error;
        }

        log_module(KC_LOG, LOG_DEBUG, "update_user_async: JSON body = %s", json_body);

        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_PUT;
        opts.post_fields = req->post_fields;
        opts.xoauth2_bearer = req->bearer_token_copy;
        opts.header_list[0] = "Content-Type: application/json";
        opts.header_count = 1;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "update_user_async: curl_perform_async failed");
            goto error;
        }

        log_module(KC_LOG, LOG_DEBUG, "update_user_async: Started PUT with merged repr for %s", user_id);
        return 0;
    }

    /* Cache miss - need to GET user first, then merge and PUT */
    log_module(KC_LOG, LOG_DEBUG, "update_user_async: Cache miss for %s, doing GET first", user_id);

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "update_user_async: Out of memory for GET request");
        return -1;
    }

    req->session = session;
    req->type = KC_ASYNC_UPDATE_USER_GET;
    req->cb.update_user = callback;
    req->uri = kc_build_user_endpoint(realm, user_id);
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);

    /* Store update info for use after GET completes */
    if (update->email) {
        req->update_email = pool_strdup(update->email);
    }
    if (update->username) {
        req->update_username = pool_strdup(update->username);
    }
    if (update->cred_data) {
        req->update_cred_data = strdup(update->cred_data);
    }
    if (update->secret_data) {
        req->update_secret_data = strdup(update->secret_data);
    }

    if (!req->uri || !req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "update_user_async: Failed to build GET request");
        goto error;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "update_user_async: curl_perform_async failed for GET");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "update_user_async: Started GET for %s before merging", user_id);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->post_fields) free(req->post_fields);
        pool_strfree(req->update_email);
        pool_strfree(req->update_username);
        if (req->update_cred_data) {
            memset(req->update_cred_data, 0, strlen(req->update_cred_data));
            free(req->update_cred_data);
        }
        if (req->update_secret_data) {
            memset(req->update_secret_data, 0, strlen(req->update_secret_data));
            free(req->update_secret_data);
        }
        free(req);
    }
    return -1;
}

/*
 * Phase 4: Async get group by path
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_get_group_by_path_async(struct kc_realm realm, struct kc_client client,
                                  const char *group_path, void *session,
                                  kc_get_group_path_callback callback)
{
    struct kc_async_request *req = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_path || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "get_group_path_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "get_group_path_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GET_GROUP_PATH;
    req->cb.get_group_path = callback;

    /* Build URI using endpoint builder */
    req->uri = kc_build_group_by_path_endpoint(realm, group_path);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "get_group_path_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "get_group_path_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "get_group_path_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "get_group_path_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "get_group_path_async: Started async lookup for path %s", group_path);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
    }
    return -1;
}

/*
 * Phase 5 sync cleanup: Async get group by name
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_get_group_by_name_async(struct kc_realm realm, struct kc_client client,
                                  const char *group_name, void *session,
                                  kc_get_group_path_callback callback)
{
    struct kc_async_request *req = NULL;
    char *escaped_name = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "get_group_name_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GET_GROUP_NAME;
    req->cb.get_group_name = callback;

    /* URL-escape the group name */
    escaped_name = curl_easy_escape(NULL, group_name, 0);
    if (!escaped_name) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: Failed to escape group name");
        goto error;
    }

    /* Build URI using endpoint builder */
    req->uri = kc_build_group_search_endpoint(realm, escaped_name);
    curl_free(escaped_name);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "get_group_name_async: Started async lookup for name %s", group_name);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
    }
    return -1;
}

/*
 * Phase 5 sync cleanup: Async delete group
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_delete_group_async(struct kc_realm realm, struct kc_client client,
                             const char *group_id, void *session,
                             kc_async_callback callback)
{
    struct kc_async_request *req = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "delete_group_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "delete_group_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_DELETE_GROUP;
    req->cb.delete_group = callback;

    /* Build URI: DELETE /admin/realms/{realm}/groups/{group_id} */
    req->uri = kc_build_group_endpoint(realm, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "delete_group_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "delete_group_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "delete_group_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_DELETE;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "delete_group_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "delete_group_async: Started async delete for group %s", group_id);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
    }
    return -1;
}

/*
 * Phase 5.10: Async delete user
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_delete_user_async(struct kc_realm realm, struct kc_client client,
                            const char *user_id, void *session,
                            kc_async_callback callback)
{
    struct kc_async_request *req = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "delete_user_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "delete_user_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_DELETE_USER;
    req->cb.delete_user = callback;

    /* Build URI: DELETE /admin/realms/{realm}/users/{user_id} */
    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "delete_user_async: Failed to build URI");
        goto error;
    }

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "delete_user_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "delete_user_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_DELETE;
    opts.xoauth2_bearer = req->bearer_token_copy;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "delete_user_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "delete_user_async: Started async delete for user %s", user_id);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
    }
    return -1;
}

/*
 * Phase 4: Async create subgroup
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_create_subgroup_async(struct kc_realm realm, struct kc_client client,
                                const char *parent_id, const char *name,
                                void *session, kc_create_subgroup_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !parent_id || !name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "create_subgroup_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_CREATE_SUBGROUP;
    req->cb.create_subgroup = callback;

    /* Build URI: POST /admin/realms/{realm}/groups/{parent_id}/children */
    req->uri = kc_build_group_children_endpoint(realm, parent_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: Failed to build URI");
        goto error;
    }

    /* Build JSON body: {"name": "..."} */
    json_t *body = json_object();
    json_object_set_new(body, "name", json_string(name));
    json_body = json_dumps(body, JSON_COMPACT);
    json_decref(body);
    if (!json_body) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: Failed to build JSON body");
        goto error;
    }
    req->post_fields = json_body;

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API - POST request */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_POST;
    opts.xoauth2_bearer = req->bearer_token_copy;
    opts.post_fields = json_body;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "create_subgroup_async: Started async create for %s under %s", name, parent_id);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->post_fields) free(req->post_fields);
        free(req);
    }
    return -1;
}

/*
 * Phase 4: Async set group attribute
 * Note: This is a simplified version that just sets one attribute.
 * The sync version does GET-modify-PUT to preserve existing attributes.
 * For now we use PUT with just the new attribute (may overwrite others).
 * Returns 0 on success (request started), -1 on error
 */
int
keycloak_set_group_attribute_async(struct kc_realm realm, struct kc_client client,
                                    const char *group_id, const char *attr_name,
                                    const char *attr_value, void *session,
                                    kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !attr_name || !attr_value || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "set_group_attr_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_SET_GROUP_ATTR;
    req->cb.generic = callback;

    /* Build URI */
    req->uri = kc_build_group_endpoint(realm, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: Failed to build URI");
        goto error;
    }

    /* Build JSON body: {"attributes": {"attr_name": ["attr_value"]}} */
    json_t *body = json_object();
    json_t *attrs = json_object();
    json_t *values = json_array();
    json_array_append_new(values, json_string(attr_value));
    json_object_set_new(attrs, attr_name, values);
    json_object_set_new(body, "attributes", attrs);
    json_body = json_dumps(body, JSON_COMPACT);
    json_decref(body);
    if (!json_body) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: Failed to build JSON body");
        goto error;
    }
    req->post_fields = json_body;

    /* Copy bearer token from global manager (avoids use-after-free if ctx has stale pointer) */
    if (!kc_token_mgr.token || !kc_token_mgr.token->access_token) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = strdup(kc_token_mgr.token->access_token);
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: Failed to copy bearer token");
        goto error;
    }

    /* Use unified async API - PUT request */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_PUT;
    opts.xoauth2_bearer = req->bearer_token_copy;
    opts.post_fields = json_body;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "set_group_attr_async: Started async set %s=%s for group %s",
               attr_name, attr_value, group_id);
    return 0;

error:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->post_fields) free(req->post_fields);
        free(req);
    }
    return -1;
}

/*
 * =============================================================================
 * Token Manager Implementation (Phase 5 Integration)
 * =============================================================================
 * Centralized token management for all Keycloak operations.
 * Note: kc_token_mgr struct is defined earlier in the file for use by async functions.
 */

/* Token waiter queue for async operations */
struct kc_token_waiter {
    kc_token_callback callback;
    void *context;
    struct kc_token_waiter *next;
};
static struct kc_token_waiter *kc_token_waiters = NULL;
static unsigned int kc_token_waiter_count = 0;

/* Backpressure: max waiters queued during token refresh */
#define KC_TOKEN_WAITER_LIMIT 100

/* Forward declaration for refresh callback */
static int kc_token_refresh_cb(void *session, int result, struct access_token *token);

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

    log_module(KC_LOG, LOG_DEBUG, "Token manager initialized for realm %s", realm.realm);
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
    log_module(KC_LOG, LOG_DEBUG, "Token manager shutdown");
}

int
keycloak_ensure_token(void)
{
    time_t now_time = time(NULL);

    if (!kc_token_mgr.initialized) {
        log_module(KC_LOG, LOG_ERROR, "keycloak_ensure_token: Token manager not initialized");
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
        kc_stats.token_refreshes++;  /* Track successful token refreshes */
        log_module(KC_LOG, LOG_DEBUG, "Async token refresh successful (expires in %ld sec)",
                   token->expires_in);
    } else {
        kc_token_mgr.available = 0;
        log_module(KC_LOG, LOG_WARNING, "Async token refresh failed: %d", result);
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
        log_module(KC_LOG, LOG_ERROR, "keycloak_ensure_token_async: Token manager not initialized");
        return -1;
    }

    if (!callback) {
        log_module(KC_LOG, LOG_ERROR, "keycloak_ensure_token_async: No callback");
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
        log_module(KC_LOG, LOG_WARNING, "keycloak_ensure_token_async: Waiter queue full (%u/%u)",
                   kc_token_waiter_count, KC_TOKEN_WAITER_LIMIT);
        return -1;
    }

    /* Token needs refresh - add to waiter queue */
    waiter = calloc(1, sizeof(*waiter));
    if (!waiter) {
        log_module(KC_LOG, LOG_ERROR, "keycloak_ensure_token_async: Out of memory");
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

        if (keycloak_get_client_token_async(kc_token_mgr.realm, kc_token_mgr.client,
                                             NULL, kc_token_refresh_cb) < 0) {
            log_module(KC_LOG, LOG_ERROR, "keycloak_ensure_token_async: Failed to start refresh");
            /* Remove the waiter we just added and fail */
            kc_token_waiters = waiter->next;
            kc_token_waiter_count--;
            free(waiter);
            kc_token_mgr.refresh_pending = 0;
            return -1;
        }

        log_module(KC_LOG, LOG_DEBUG, "keycloak_ensure_token_async: Started async refresh");
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_ensure_token_async: Refresh pending, queued waiter");
    }

    return 0;
}

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

#endif /* WITH_KEYCLOAK */
