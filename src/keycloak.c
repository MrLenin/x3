#include "config.h"

#ifdef WITH_KEYCLOAK

#include <string.h>
#include <time.h>

#include "keycloak.h"
#include "common.h"
#include "log.h"
#include "ioset.h"
#include "timeq.h"
#include "base64.h"
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

/* Forward declaration for exit handler */
static void keycloak_exit_handler(void *extra);

void
init_keycloak()
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

/* Forward declaration for async cleanup */
static void kc_async_cleanup(void);

void
cleanup_keycloak()
{
    /* Cleanup async infrastructure first */
    kc_async_cleanup();

    /* Cleanup JWKS cache */
    jwks_cleanup();

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
        return KC_ERROR;  /* Fall back to introspection */
    }

    if (!kid) {
        log_module(KC_LOG, LOG_DEBUG, "JWT missing kid");
        json_decref(hdr);
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
static void memory_struct_cleanup(struct memory *mem) {
    if (mem && mem->response) {
        free(mem->response);
        mem->response = NULL;
        mem->size = 0;
    }
}

/* For stack-allocated struct memory - most common case */
#define AUTO_CLEANUP_RESPONSE __attribute__((cleanup(memory_struct_cleanup)))

/* For sensitive data that should be zeroed before free */
static void memory_secure_cleanup(struct memory *mem) {
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
static void string_cleanup(char **str) {
    if (str && *str) {
        free(*str);
        *str = NULL;
    }
}

#define AUTO_FREE_STRING __attribute__((cleanup(string_cleanup)))

/* For strings containing sensitive data */
static void string_secure_cleanup(char **str) {
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

    int len = snprintf(NULL, 0, tmpl, realm.base_uri, realm.realm, path) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_uri, realm.realm, path);
    return uri;
}

/* User search endpoint: /admin/realms/{realm}/users?{query} */
static char *
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
static char *
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

    return 0;
}

/*
 * =============================================================================
 * Async HTTP Infrastructure (curl_multi + ioset integration)
 * =============================================================================
 */

/* curl_multi handle for async HTTP */
static CURLM *kc_curl_multi = NULL;

/* Handle pool for async requests - avoids curl_easy_init() per request */
#define KC_HANDLE_POOL_SIZE 8
static CURL *kc_handle_pool[KC_HANDLE_POOL_SIZE];
static int kc_handle_pool_count = 0;

/* Get a handle from pool (or create new one) */
static CURL *kc_handle_pool_get(void) {
    if (kc_handle_pool_count > 0) {
        CURL *handle = kc_handle_pool[--kc_handle_pool_count];
        curl_easy_reset(handle);
        return handle;
    }
    return curl_easy_init();
}

/* Return handle to pool (or destroy if pool full) */
static void kc_handle_pool_put(CURL *handle) {
    if (!handle) return;
    if (kc_handle_pool_count < KC_HANDLE_POOL_SIZE) {
        kc_handle_pool[kc_handle_pool_count++] = handle;
    } else {
        curl_easy_cleanup(handle);
    }
}

/* Cleanup the handle pool */
static void kc_handle_pool_cleanup(void) {
    while (kc_handle_pool_count > 0) {
        curl_easy_cleanup(kc_handle_pool[--kc_handle_pool_count]);
    }
}

/* Per-socket tracking for ioset integration */
struct kc_sock_info {
    curl_socket_t sockfd;
    struct io_fd *io_fd;
    int action;  /* CURL_POLL_IN, CURL_POLL_OUT, etc */
};

/* Forward declarations */
static void kc_curl_socket_ready(struct io_fd *fd);
static void kc_curl_timeout_fired(void *data);
static void kc_curl_check_completed(void);

/* Async request types */
enum kc_async_type {
    KC_ASYNC_AUTH,          /* Password authentication */
    KC_ASYNC_FINGERPRINT,   /* Certificate fingerprint lookup */
    KC_ASYNC_INTROSPECT,    /* Token introspection */
    KC_ASYNC_SET_ATTR,      /* Set user attribute */
    KC_ASYNC_GROUP_ADD,     /* Add user to group */
    KC_ASYNC_GROUP_REMOVE,  /* Remove user from group */
    KC_ASYNC_WEBPUSH,       /* WebPush notification delivery */
    KC_ASYNC_CREATE_USER    /* User creation */
};

/* Async request tracking */
struct kc_async_request {
    CURL *easy;
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
        void (*webpush)(void *session, int result, long http_code);  /* WebPush callback */
    } cb;
    /* WebPush-specific: copy of binary POST data for async request */
    void *post_data_copy;
    size_t post_data_len;
    /* Timeout tracking (Phase 5.3) */
    time_t started;               /* When request was initiated */
};

/* Called by curl when socket state changes */
static int
kc_curl_socket_cb(CURL *easy, curl_socket_t s, int what,
                  void *userp, void *sockp)
{
    struct kc_sock_info *si = sockp;
    (void)easy;
    (void)userp;

    if (what == CURL_POLL_REMOVE) {
        if (si) {
            if (si->io_fd) {
                ioset_close(si->io_fd, 0);  /* Don't close fd, curl owns it */
            }
            free(si);
        }
        curl_multi_assign(kc_curl_multi, s, NULL);
        return 0;
    }

    if (!si) {
        /* New socket - register with ioset */
        si = calloc(1, sizeof(*si));
        if (!si) return 0;
        si->sockfd = s;
        si->io_fd = ioset_add(s);
        if (!si->io_fd) {
            free(si);
            return 0;
        }
        si->io_fd->state = IO_CONNECTED;  /* Already connected by curl */
        si->io_fd->line_reads = 0;        /* Raw socket, no line buffering */
        si->io_fd->readable_cb = kc_curl_socket_ready;
        si->io_fd->data = si;
        curl_multi_assign(kc_curl_multi, s, si);
        log_module(KC_LOG, LOG_DEBUG, "kc_async: Registered socket %d with ioset", (int)s);
    }

    si->action = what;
    ioset_update(si->io_fd);  /* Update poll flags based on action */
    return 0;
}

/* Called when ioset reports socket ready */
static void
kc_curl_socket_ready(struct io_fd *fd)
{
    struct kc_sock_info *si = fd->data;
    int running;
    int ev_bitmask = 0;

    if (!si || !kc_curl_multi) return;

    /* Determine events based on what curl requested */
    if (si->action & CURL_POLL_IN)
        ev_bitmask |= CURL_CSELECT_IN;
    if (si->action & CURL_POLL_OUT)
        ev_bitmask |= CURL_CSELECT_OUT;

    curl_multi_socket_action(kc_curl_multi, si->sockfd, ev_bitmask, &running);
    kc_curl_check_completed();  /* Check for finished transfers */
}

/* Called by curl when timeout value changes */
static int
kc_curl_timer_cb(CURLM *multi, long timeout_ms, void *userp)
{
    (void)multi;
    (void)userp;

    /* Remove any existing second-precision fallback timer */
    timeq_del(0, kc_curl_timeout_fired, NULL, TIMEQ_IGNORE_WHEN | TIMEQ_IGNORE_DATA);

    if (timeout_ms == -1) {
        /* Clear curl's timer - no pending operations */
        ioset_set_poll_hint_ms(0);
    } else if (timeout_ms == 0) {
        /* Immediate action needed - hint minimal timeout */
        ioset_set_poll_hint_ms(1);
        /* Also schedule immediate timeq callback for safety */
        timeq_add(now, kc_curl_timeout_fired, NULL);
    } else {
        /* Use millisecond-precision poll hint */
        ioset_set_poll_hint_ms(timeout_ms);
        /* Also schedule second-precision fallback (coarse, but ensures we don't miss) */
        timeq_add(now + (timeout_ms / 1000) + 1, kc_curl_timeout_fired, NULL);
    }
    return 0;
}

/* Called by timeq when curl timeout fires */
static void
kc_curl_timeout_fired(UNUSED_ARG(void *data))
{
    int running;
    if (!kc_curl_multi) return;

    /* Clear poll hint - curl will reset it via timer callback if needed */
    ioset_set_poll_hint_ms(0);

    curl_multi_socket_action(kc_curl_multi, CURL_SOCKET_TIMEOUT, 0, &running);
    kc_curl_check_completed();
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

/* Check for completed transfers and invoke callbacks */
static void
kc_curl_check_completed(void)
{
    CURLMsg *msg;
    int msgs_left;

    if (!kc_curl_multi) return;

    while ((msg = curl_multi_info_read(kc_curl_multi, &msgs_left))) {
        if (msg->msg == CURLMSG_DONE) {
            CURL *easy = msg->easy_handle;
            struct kc_async_request *req = NULL;
            long http_code = 0;

            curl_easy_getinfo(easy, CURLINFO_PRIVATE, &req);
            if (!req) {
                log_module(KC_LOG, LOG_ERROR, "kc_async: No request data for completed transfer");
                curl_multi_remove_handle(kc_curl_multi, easy);
                curl_easy_cleanup(easy);
                continue;
            }

            /* Get request_id for logging */
            const char *req_id = req->request_id ? req->request_id : "-";

            /* Check elapsed time (Phase 5.3 timeout tracking) */
            time_t elapsed = 0;
            if (req->started > 0) {
                elapsed = time(NULL) - req->started;
                if (elapsed >= 5) {
                    log_module(KC_LOG, LOG_WARNING, "[%s] kc_async: Request took %ld seconds (type=%d)",
                               req_id, (long)elapsed, req->type);
                }
            }

            /* Get HTTP response code */
            if (msg->data.result == CURLE_OK) {
                curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &http_code);
            } else {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async: CURL error: %s (after %lds)",
                           req_id, curl_easy_strerror(msg->data.result), (long)elapsed);
            }

            /* Dispatch based on request type */
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
                if (req->cb.generic) {
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
            case KC_ASYNC_WEBPUSH: {
                int result = KC_ERROR;
                if (http_code >= 200 && http_code < 300) {
                    result = KC_SUCCESS;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async webpush: Success (HTTP %ld)", req_id, http_code);
                } else if (http_code == 410) {
                    /* Subscription expired - special handling for cleanup */
                    result = KC_FORBIDDEN;  /* Using KC_FORBIDDEN to indicate expired */
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async webpush: Subscription expired (HTTP 410)", req_id);
                } else {
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async webpush: Error (HTTP %ld)", req_id, http_code);
                }
                if (req->cb.webpush) {
                    req->cb.webpush(req->session, result, http_code);
                }
                break;
            }
            case KC_ASYNC_CREATE_USER: {
                int result = KC_ERROR;
                if (http_code == 201) {
                    result = KC_SUCCESS;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_user: User created (HTTP 201)", req_id);
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
            }

            /* Cleanup - return handle to pool for reuse */
            curl_multi_remove_handle(kc_curl_multi, easy);
            kc_handle_pool_put(easy);
            if (req->response.response) {
                memset(req->response.response, 0, req->response.size);
                free(req->response.response);
            }
            if (req->uri) free(req->uri);
            if (req->post_fields) {
                memset(req->post_fields, 0, strlen(req->post_fields));
                free(req->post_fields);
            }
            if (req->post_data_copy) free(req->post_data_copy);
            if (req->header_list) curl_slist_free_all(req->header_list);
            if (req->request_id) free(req->request_id);
            free(req);
        }
    }
}

/* Initialize async HTTP infrastructure */
static void
kc_async_init(void)
{
    if (kc_curl_multi) return;  /* Already initialized */

    kc_curl_multi = curl_multi_init();
    if (!kc_curl_multi) {
        log_module(KC_LOG, LOG_ERROR, "Failed to initialize curl_multi");
        return;
    }

    /* Register callbacks */
    curl_multi_setopt(kc_curl_multi, CURLMOPT_SOCKETFUNCTION, kc_curl_socket_cb);
    curl_multi_setopt(kc_curl_multi, CURLMOPT_TIMERFUNCTION, kc_curl_timer_cb);

    log_module(KC_LOG, LOG_INFO, "Keycloak async HTTP initialized (curl_multi + ioset)");
}

/* Cleanup async HTTP infrastructure */
static void
kc_async_cleanup(void)
{
    if (kc_curl_multi) {
        /* Remove any pending timers and clear poll hint */
        timeq_del(0, kc_curl_timeout_fired, NULL, TIMEQ_IGNORE_WHEN | TIMEQ_IGNORE_DATA);
        ioset_set_poll_hint_ms(0);

        curl_multi_cleanup(kc_curl_multi);
        kc_curl_multi = NULL;
        log_module(KC_LOG, LOG_INFO, "Keycloak async HTTP cleaned up");
    }

    /* Cleanup handle pool */
    kc_handle_pool_cleanup();
}

/*
 * Async version of curl_perform - uses curl_multi for non-blocking HTTP
 * The request struct must have uri, post_fields (if needed), session, type, and callback set.
 * Returns 0 on success (request started), -1 on error
 */
static int
curl_perform_async(struct kc_async_request *req, struct curl_opts opts)
{
    CURL *easy = NULL;
    const char *req_id = opts.request_id ? opts.request_id : "-";

    /* Initialize async infrastructure if needed */
    if (!kc_curl_multi) {
        kc_async_init();
        if (!kc_curl_multi) {
            log_module(KC_LOG, LOG_ERROR, "[%s] curl_perform_async: Failed to init async", req_id);
            return -1;
        }
    }

    if (!req || !opts.uri) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] curl_perform_async: Invalid arguments", req_id);
        return -1;
    }

    /* Store request_id for completion logging */
    if (opts.request_id) {
        req->request_id = strdup(opts.request_id);
    }

    /* Record start time for timeout tracking */
    req->started = time(NULL);

    /* Get handle from pool (or create new one) */
    easy = kc_handle_pool_get();
    if (!easy) {
        log_module(KC_LOG, LOG_ERROR, "[%s] curl_perform_async: Failed to get handle", req_id);
        return -1;
    }
    req->easy = easy;

    /* Initialize response buffer */
    req->response.response = malloc(1);
    if (req->response.response) {
        req->response.response[0] = 0;
        req->response.size = 0;
    }

    /* Apply unified options - track header_list for cleanup */
    if (curl_apply_opts(easy, opts, &req->response, &req->header_list) < 0) {
        log_module(KC_LOG, LOG_ERROR, "[%s] curl_perform_async: Failed to apply options", req_id);
        kc_handle_pool_put(easy);
        req->easy = NULL;
        return -1;
    }

    /* Store request pointer for callback retrieval */
    curl_easy_setopt(easy, CURLOPT_PRIVATE, req);

    /* Add to multi handle - returns immediately */
    CURLMcode mc = curl_multi_add_handle(kc_curl_multi, easy);
    if (mc != CURLM_OK) {
        log_module(KC_LOG, LOG_ERROR, "[%s] curl_perform_async: curl_multi_add_handle failed: %s",
                   req_id, curl_multi_strerror(mc));
        if (req->header_list) curl_slist_free_all(req->header_list);
        req->header_list = NULL;
        curl_easy_cleanup(easy);
        req->easy = NULL;
        return -1;
    }

    log_module(KC_LOG, LOG_DEBUG, "[%s] curl_perform_async: Request started", req_id);
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
        if (req->easy) curl_easy_cleanup(req->easy);
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

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.xoauth2_bearer = client.access_token->access_token;
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
        if (req->easy) curl_easy_cleanup(req->easy);
        if (req->uri) free(req->uri);
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
        if (req->easy) curl_easy_cleanup(req->easy);
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
 * Set a user attribute asynchronously.
 * This is useful for non-blocking attribute updates during SASL flows.
 */
int
keycloak_set_user_attribute_async(struct kc_realm realm, struct kc_client client,
                                   const char *user_id, const char *attr_name,
                                   const char *attr_value, void *session,
                                   kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !attr_name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "set_attr_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_SET_ATTR;
    req->cb.generic = callback;

    /* Build URI */
    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_async: Failed to build URI");
        goto error;
    }

    /* Build JSON body - partial update with just the attribute */
    json_t *attrs = json_object();
    json_t *attr_array = json_array();
    if (attr_value) {
        json_array_append_new(attr_array, json_string(attr_value));
    }
    json_object_set_new(attrs, attr_name, attr_array);

    json_t *user_obj = json_object();
    json_object_set_new(user_obj, "attributes", attrs);
    json_body = json_dumps(user_obj, JSON_COMPACT);
    json_decref(user_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_async: Failed to build JSON");
        goto error;
    }

    /* Store post fields in request for cleanup */
    req->post_fields = json_body;
    json_body = NULL;  /* Transferred ownership */

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_PUT;
    opts.post_fields = req->post_fields;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "set_attr_async: Started attribute update for %s.%s",
               user_id, attr_name);
    return 0;

error:
    if (json_body) free(json_body);
    if (req) {
        if (req->easy) curl_easy_cleanup(req->easy);
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

    /* Use unified async API */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_PUT;
    opts.post_fields = req->post_fields;
    opts.xoauth2_bearer = client.access_token->access_token;
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
        if (req->easy) curl_easy_cleanup(req->easy);
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

    /* Use unified async API - PUT with no body */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_PUT;
    opts.xoauth2_bearer = client.access_token->access_token;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "add_group_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "add_group_async: Started adding user %s to group %s",
               user_id, group_id);
    return 0;

error:
    if (req) {
        if (req->easy) curl_easy_cleanup(req->easy);
        if (req->uri) free(req->uri);
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

    /* Use unified async API - DELETE with no body */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_DELETE;
    opts.xoauth2_bearer = client.access_token->access_token;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "remove_group_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "remove_group_async: Started removing user %s from group %s",
               user_id, group_id);
    return 0;

error:
    if (req) {
        if (req->easy) curl_easy_cleanup(req->easy);
        if (req->uri) free(req->uri);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

/**
 * Send a WebPush notification asynchronously.
 * This is a generic HTTP POST for WebPush that uses the async curl_multi infrastructure.
 *
 * @param endpoint      Push service endpoint URL
 * @param headers       Array of header strings (e.g., "Content-Type: application/octet-stream")
 * @param header_count  Number of headers
 * @param body          Binary body data
 * @param body_len      Length of body data
 * @param session       Opaque session pointer (passed to callback)
 * @param callback      Function to call when request completes
 * @return 0 on success (request started), -1 on error
 */
int
kc_webpush_send_async(const char *endpoint,
                      const char **headers, size_t header_count,
                      const void *body, size_t body_len,
                      void *session,
                      kc_webpush_callback callback)
{
    struct kc_async_request *req = NULL;

    /* Validate inputs */
    if (!endpoint || !body || body_len == 0 || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "webpush_async: Invalid arguments");
        return -1;
    }

    /* Allocate request structure */
    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "webpush_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_WEBPUSH;
    req->cb.webpush = callback;

    /* Copy endpoint URL */
    req->uri = strdup(endpoint);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "webpush_async: Failed to copy URI");
        goto error;
    }

    /* Copy binary body data (must persist until request completes) */
    req->post_data_copy = malloc(body_len);
    if (!req->post_data_copy) {
        log_module(KC_LOG, LOG_ERROR, "webpush_async: Failed to copy body");
        goto error;
    }
    memcpy(req->post_data_copy, body, body_len);
    req->post_data_len = body_len;

    /* Build curl options */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_POST;
    opts.post_data = req->post_data_copy;
    opts.post_data_len = body_len;

    /* Copy headers (up to 10) */
    if (header_count > 10) header_count = 10;
    for (size_t i = 0; i < header_count && headers[i]; i++) {
        opts.header_list[i] = headers[i];
    }
    opts.header_count = header_count;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "webpush_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "webpush_async: Started push to %s", endpoint);
    return 0;

error:
    if (req) {
        if (req->easy) curl_easy_cleanup(req->easy);
        if (req->uri) free(req->uri);
        if (req->post_data_copy) free(req->post_data_copy);
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

    /* Validate inputs */
    if (!realm.base_uri || !realm.realm || !client.access_token || !username || !password || !callback) {
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

    /* Build curl options */
    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = req->uri;
    opts.method = HTTP_POST;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.post_fields = req->post_fields;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    if (curl_perform_async(req, opts) < 0) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: curl_perform_async failed");
        goto error;
    }

    log_module(KC_LOG, LOG_DEBUG, "create_user_async: Started user creation for %s", username);
    return 0;

error:
    if (req) {
        if (req->easy) curl_easy_cleanup(req->easy);
        if (req->uri) free(req->uri);
        if (req->post_fields) {
            memset(req->post_fields, 0, strlen(req->post_fields));
            free(req->post_fields);
        }
        if (req->response.response) free(req->response.response);
        free(req);
    }
    if (user_repr) {
        memset(user_repr, 0, strlen(user_repr));
        free(user_repr);
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

        /* Perform request (blocking) */
        res = curl_easy_perform(curl);
        http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

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
    if (!username || !email || !cred_data || !secret_data) {
        log_module(KC_LOG, LOG_DEBUG, "json_build_user_with_hash: Invalid arguments");
        return NULL;
    }

    char* result = NULL;

    json_t* user_obj = json_object();
    json_t* creds = json_array();
    json_t* cred = json_object();

    /* Build user object */
    json_object_set_new(user_obj, "username", json_string(username));
    json_object_set_new(user_obj, "email", json_string(email));
    json_object_set_new(user_obj, "enabled", json_true());

    /* Build credential with pre-hashed password (credential import format) */
    json_object_set_new(cred, "type", json_string("password"));

    /* credentialData and secretData must be JSON strings containing JSON */
    json_object_set_new(cred, "credentialData", json_string(cred_data));
    json_object_set_new(cred, "secretData", json_string(secret_data));
    json_object_set_new(cred, "temporary", json_false());

    json_array_append_new(creds, cred);
    json_object_set_new(user_obj, "credentials", creds);

    result = json_dumps(user_obj, JSON_COMPACT);

    if (!result) {
        log_module(KC_LOG, LOG_DEBUG, "json_build_user_with_hash: json_dumps failed");
    }

    json_decref(user_obj);

    return result;
}


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

int keycloak_get_user(struct kc_realm realm, struct kc_client client,
                             const char *user, struct kc_user *kc_user_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !user || !kc_user_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user: Invalid arguments");
        return KC_ERROR;
    }

    struct kc_user* kc_users = NULL;
    int result = keycloak_get_users(realm, client, user, NULL, true, &kc_users);

    if (result >= 1) {
        /* User found */
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

int keycloak_update_user_credentials(struct kc_realm realm, struct kc_client client,
                                     const char* user_id,
                                     const char* cred_data, const char* secret_data)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !cred_data || !secret_data) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_credentials: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = kc_build_user_endpoint(realm, user_id);
    char *json_body = NULL;
    struct memory chunk = {0};

    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_credentials: Failed to build uri");
        goto cleanup;
    }

    /* Build user update with credentials array
     * Keycloak expects credentialData and secretData as JSON strings within each credential */
    json_t* cred_obj = json_object();
    json_object_set_new(cred_obj, "type", json_string("password"));
    json_object_set_new(cred_obj, "credentialData", json_string(cred_data));
    json_object_set_new(cred_obj, "secretData", json_string(secret_data));

    json_t* creds_array = json_array();
    json_array_append_new(creds_array, cred_obj);

    json_t* user_obj = json_object();
    json_object_set_new(user_obj, "credentials", creds_array);

    json_body = json_dumps(user_obj, JSON_COMPACT);
    json_decref(user_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_credentials: Failed to build JSON");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_PUT;  /* PUT to /users/{id} with credentials array */
    opts.post_fields = json_body;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.header_list[0] = "Content-Type: application/json";
    opts.header_count = 1;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 204) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_credentials: Credentials updated (HTTP 204)");
        result = KC_SUCCESS;
    } else if (http_code == 404) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_credentials: User not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user_credentials: Failed with HTTP %ld: %s",
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

int keycloak_set_user_attribute(struct kc_realm realm, struct kc_client client,
                                const char* user_id, const char* attr_name,
                                const char* attr_value)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !attr_name || !attr_value) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char *uri = NULL;
    char *json_body = NULL;
    struct memory chunk = {0};

    uri = kc_build_user_endpoint(realm, user_id);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Failed to allocate uri");
        goto cleanup;
    }

    /* Build JSON: { "attributes": { "attr_name": ["attr_value"] } } */
    json_t* user_obj = json_object();
    json_t* attrs = json_object();
    json_t* values = json_array();
    json_array_append_new(values, json_string(attr_value));
    json_object_set_new(attrs, attr_name, values);
    json_object_set_new(user_obj, "attributes", attrs);
    json_body = json_dumps(user_obj, JSON_COMPACT);
    json_decref(user_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Failed to build JSON");
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
                *group_id_out = strdup(json_string_value(id_val));
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
                *group_id_out = strdup(json_string_value(id_val));
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

#endif /* WITH_KEYCLOAK */
