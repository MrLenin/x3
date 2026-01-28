/* kc_http_internal.h - Internal shared HTTP infrastructure for Keycloak modules
 *
 * This header is INTERNAL to the kc_* module family. It exposes common HTTP
 * types, the CURL write callback, the persistent CURL handle, the synchronous
 * curl_perform helper, and a JSON string extraction utility so that code
 * extracted from keycloak.c (kc_jwt.c, kc_token.c, etc.) can reuse them
 * without duplicating definitions.
 *
 * Do NOT include this header from code outside the keycloak module family.
 */

#ifndef KC_HTTP_INTERNAL_H
#define KC_HTTP_INTERNAL_H

#include <curl/curl.h>
#include <jansson.h>
#include <stdbool.h>
#include <stddef.h>

/* Response buffer structure (shared by sync and async) */
struct memory {
    char* response;
    size_t size;
};

/* Write callback (shared by sync and async) */
size_t curl_write_cb(char *data, size_t size, size_t nmemb, void *clientp);

/* Function pointer type for write callbacks */
typedef size_t(*curl_write_cb_ptr)(char*, size_t, size_t, void*);

/* HTTP methods for curl_opts */
enum http_method {
    HTTP_GET = 0,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE
};

/* Header callback type - receives each header line */
typedef size_t (*curl_header_cb_ptr)(char *buffer, size_t size, size_t nitems, void *userdata);

/* Unified HTTP request options */
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

/* Persistent CURL handle for connection reuse (owned by keycloak.c) */
extern CURL* kc_curl_handle;

/* Synchronous HTTP helper with retry logic.
 * Returns HTTP status code on success, KC_ERROR on failure. */
long curl_perform(struct curl_opts opts, struct memory* chunk_out);

/* Extract a string value from a JSON object.
 * Allocates a copy into *value_out. Optionally sets *value_out_size.
 * Returns KC_SUCCESS or KC_ERROR. */
int json_read_object_string(json_t* object, const char* key,
    char** value_out, size_t* value_out_size);

/* Forward declarations for JSON parsers */
struct kc_user;

/* JSON parsers shared between keycloak.c and kc_sync.c */
int json_read_object_boolean(json_t* object, const char* key, bool* value_out);
int json_read_kc_user(json_t* user_object, struct kc_user* user_out);

/* Apply curl options to a handle (shared by sync and async) */
int curl_apply_opts(CURL *curl, struct curl_opts opts, struct memory *chunk_out,
                    struct curl_slist **header_list_out);

/* JSON builders (used by async create_user functions) */
char* json_build_user_representation(const char *username, const char *email, const char *passwd);
char* json_build_user_with_hash(const char *username, const char *email,
                                const char *cred_data, const char *secret_data);

/* Stats recording (used by async result handler) */
void kc_stats_record_request(unsigned long latency_ms, int is_error);

/* Error classification (used by sync retry logic) */
int is_retryable_error(CURLcode curl_res, long http_code);

/* Shared log handle (owned by keycloak.c, initialized in init_keycloak) */
struct log_type;
extern struct log_type *KC_LOG;

#endif /* KC_HTTP_INTERNAL_H */
