/* kc_async.c - Async Keycloak API implementation
 *
 * Extracted from keycloak.c during Phase 7 modularization.
 * Contains all non-blocking HTTP operations via the libkc bridge.
 */

#include "config.h"

#ifdef WITH_KEYCLOAK

#include <string.h>
#include <time.h>
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include "keycloak.h"
#include "kc_async.h"
#include "kc/kc_cache.h"
#include "kc_token.h"
#include "kc_http_internal.h"
#include "kc_sync.h"
#include "common.h"
#include "threadpool.h"
#include "log.h"
#include "ioset.h"
#include "timeq.h"
#include "x3_kc_bridge.h"
#include "mempool.h"
#include <curl/multi.h>

/* KC_LOG is extern from kc_http_internal.h (owned by keycloak.c) */

/*
 * =============================================================================
 * Attribute Update Coalescing
 * =============================================================================
 */

#define KC_COALESCE_DELAY_SEC 1
#define KC_COALESCE_MAX_PENDING 64

struct kc_pending_attr {
    char *name;
    char *value;
    kc_async_callback cb;
    void *session;
};

struct kc_pending_user_update {
    char user_id[64];
    struct kc_pending_attr attrs[KC_COALESCE_MAX_PENDING];
    int attr_count;
    time_t scheduled_flush;
    struct kc_pending_user_update *next;
};

static struct kc_pending_user_update *kc_pending_updates = NULL;

/* Forward declarations */
static void kc_coalesce_flush_cb(void *data);
static void kc_pending_update_free(struct kc_pending_user_update *p);
static void kc_coalesce_cleanup(void);

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

static void
kc_coalesce_cleanup(void)
{
    struct kc_pending_user_update *p, *next;
    int count = 0;

    for (p = kc_pending_updates; p; p = next) {
        next = p->next;
        timeq_del(0, kc_coalesce_flush_cb, p, TIMEQ_IGNORE_WHEN);
        kc_pending_invoke_all_callbacks(p, KC_ERROR);
        kc_pending_update_free(p);
        count++;
    }
    kc_pending_updates = NULL;

    if (count > 0) {
        log_module(KC_LOG, LOG_DEBUG, "coalesce: Cleaned up %d pending updates", count);
    }
}

static struct kc_pending_user_update *
kc_coalesce_get_or_create(const char *user_id)
{
    struct kc_pending_user_update *p;

    for (p = kc_pending_updates; p; p = p->next) {
        if (strcmp(p->user_id, user_id) == 0)
            return p;
    }

    p = calloc(1, sizeof(*p));
    if (!p) {
        log_module(KC_LOG, LOG_ERROR, "coalesce: Out of memory");
        return NULL;
    }

    safestrncpy(p->user_id, user_id, sizeof(p->user_id));
    p->scheduled_flush = now + KC_COALESCE_DELAY_SEC;
    p->next = kc_pending_updates;
    kc_pending_updates = p;

    timeq_add(p->scheduled_flush, kc_coalesce_flush_cb, p);

    log_module(KC_LOG, LOG_DEBUG, "coalesce: Created pending update for %s, flush in %ds",
               user_id, KC_COALESCE_DELAY_SEC);
    return p;
}

static int
kc_coalesce_add_attr(struct kc_pending_user_update *p,
                     const char *attr_name, const char *attr_value,
                     kc_async_callback cb, void *session)
{
    for (int i = 0; i < p->attr_count; i++) {
        if (strcmp(p->attrs[i].name, attr_name) == 0) {
            free(p->attrs[i].value);
            p->attrs[i].value = attr_value ? strdup(attr_value) : NULL;
            p->attrs[i].cb = cb;
            p->attrs[i].session = session;
            log_module(KC_LOG, LOG_DEBUG, "coalesce: Updated pending attr %s for %s",
                       attr_name, p->user_id);
            return 0;
        }
    }

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

/*
 * =============================================================================
 * Auto-cleanup helpers (GCC/Clang cleanup attribute)
 * =============================================================================
 */

static void __attribute__((unused)) memory_struct_cleanup(struct memory *mem) {
    if (mem && mem->response) {
        free(mem->response);
        mem->response = NULL;
        mem->size = 0;
    }
}

#define AUTO_CLEANUP_RESPONSE __attribute__((cleanup(memory_struct_cleanup)))

static void __attribute__((unused)) memory_secure_cleanup(struct memory *mem) {
    if (mem && mem->response) {
        memset(mem->response, 0, mem->size);
        free(mem->response);
        mem->response = NULL;
        mem->size = 0;
    }
}

#define AUTO_CLEANUP_RESPONSE_SECURE __attribute__((cleanup(memory_secure_cleanup)))

static void __attribute__((unused)) string_cleanup(char **str) {
    if (str && *str) {
        free(*str);
        *str = NULL;
    }
}

#define AUTO_FREE_STRING __attribute__((cleanup(string_cleanup)))

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
 * Async Type System
 * =============================================================================
 */

enum kc_async_type {
    KC_ASYNC_AUTH,
    KC_ASYNC_FINGERPRINT,
    KC_ASYNC_INTROSPECT,
    KC_ASYNC_SET_ATTR,
    KC_ASYNC_GROUP_ADD,
    KC_ASYNC_GROUP_REMOVE,
    KC_ASYNC_CREATE_USER,
    KC_ASYNC_GROUP_INFO,
    KC_ASYNC_GROUP_MEMBERS,
    KC_ASYNC_CLIENT_TOKEN,
    KC_ASYNC_GET_USER,
    KC_ASYNC_UPDATE_USER,
    KC_ASYNC_UPDATE_USER_GET,
    KC_ASYNC_GET_GROUP_PATH,
    KC_ASYNC_CREATE_SUBGROUP,
    KC_ASYNC_SET_GROUP_ATTR,
    KC_ASYNC_SET_GROUP_ATTR_GET,
    KC_ASYNC_GET_GROUP_NAME,
    KC_ASYNC_DELETE_GROUP,
    KC_ASYNC_DELETE_USER,
    KC_ASYNC_LIST_ATTRS,
    KC_ASYNC_GET_ATTR,
    KC_ASYNC_SET_USER_ATTR_GET,
    KC_ASYNC_COALESCE_GET
};

struct kc_async_request {
    void *session;
    struct memory response;
    char *uri;
    char *post_fields;
    char *request_id;
    struct curl_slist *header_list;
    enum kc_async_type type;
    union {
        kc_async_callback auth;
        kc_async_callback generic;
        kc_string_callback fingerprint;
        kc_introspect_callback introspect;
        kc_group_info_callback group_info;
        kc_group_members_callback group_members;
        kc_client_token_callback client_token;
        kc_get_user_callback get_user;
        kc_async_callback update_user;
        kc_string_callback get_group_path;
        kc_string_callback create_subgroup;
        kc_string_callback get_group_name;
        kc_async_callback delete_group;
        kc_async_callback delete_user;
        kc_list_attrs_callback list_attrs;
        kc_string_callback get_attr;
    } cb;
    void *post_data_copy;
    size_t post_data_len;
    time_t started;
    char *create_username;
    char location_header[256];
    char *attr_prefix;
    char *attr_name;
    char *group_attr_value;
    char *group_id;
    char *user_attr_name;
    char *user_attr_value;
    char *user_id_copy;
    struct kc_realm realm_copy;
    struct kc_client client_copy;
    char *bearer_token_copy;
    char *update_email;
    char *update_username;
    char *update_cred_data;
    char *update_secret_data;
    int retry_count;
    int max_retries;
    struct kc_pending_user_update *coalesce_pending;
};

/* Forward declarations */
static int curl_perform_async(struct kc_async_request *req, struct curl_opts opts);
static void kc_async_bridge_complete(long http_code, const char *body, size_t body_len,
                                      json_t *json, const char *error, void *req_data);

/*
 * =============================================================================
 * Header Callback and Completion Helpers
 * =============================================================================
 */

static size_t
kc_header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
    size_t realsize = size * nitems;
    struct kc_async_request *req = (struct kc_async_request *)userdata;

    if (realsize > 10 && strncasecmp(buffer, "Location:", 9) == 0) {
        const char *value = buffer + 9;
        while (*value == ' ' || *value == '\t') value++;

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

    json_error_t error;
    json_t *root = json_loads(req->response.response, 0, &error);
    if (!root) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async introspect: Invalid JSON", req_id);
        req->cb.introspect(req->session, KC_ERROR, NULL);
        return;
    }

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

/*
 * =============================================================================
 * Retry Logic
 * =============================================================================
 */

#define KC_ASYNC_MAX_RETRIES 2
#define KC_ASYNC_RETRY_BASE_DELAY_SEC 1

static void kc_async_retry_cb(void *data);
static void kc_async_request_cleanup(struct kc_async_request *req);

static int
kc_async_schedule_retry(struct kc_async_request *req)
{
    const char *req_id = req->request_id ? req->request_id : "-";
    int max_retries = req->max_retries > 0 ? req->max_retries : KC_ASYNC_MAX_RETRIES;

    if (req->retry_count >= max_retries) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async: Max retries (%d) exceeded",
                   req_id, max_retries);
        return 0;
    }

    req->retry_count++;
    int delay_sec = KC_ASYNC_RETRY_BASE_DELAY_SEC * (1 << (req->retry_count - 1));
    time_t retry_time = now + delay_sec;

    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async: Scheduling retry %d/%d in %ds",
               req_id, req->retry_count, req->max_retries, delay_sec);

    timeq_add(retry_time, kc_async_retry_cb, req);
    return 1;
}

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

    if (req->response.response) {
        free(req->response.response);
        req->response.response = NULL;
        req->response.size = 0;
    }

    req->started = time(NULL);

    int max_retries = req->max_retries > 0 ? req->max_retries : KC_ASYNC_MAX_RETRIES;
    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async: Executing retry %d/%d",
               req_id, req->retry_count, max_retries);

    int rc = x3_kc_bridge_submit(
        req->uri, NULL,
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

static void
kc_async_request_cleanup(struct kc_async_request *req)
{
    if (!req) return;

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
    pool_strfree(req->request_id);
    pool_strfree(req->create_username);
    pool_strfree(req->attr_prefix);
    pool_strfree(req->attr_name);
    pool_strfree(req->user_attr_name);
    pool_strfree(req->user_attr_value);
    pool_strfree(req->user_id_copy);
    if (req->bearer_token_copy) free(req->bearer_token_copy);
    pool_strfree(req->group_attr_value);
    pool_strfree(req->group_id);
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
 * =============================================================================
 * Async Result Dispatch (kc_async_handle_result)
 * =============================================================================
 */

/* Forward declaration for continued dispatch */
static void kc_async_handle_result_continued(struct kc_async_request *req,
                                              long http_code, const char *req_id);

static void
kc_async_handle_result(struct kc_async_request *req, long http_code,
                        int curl_failed, unsigned long latency_ms)
{
    const char *req_id = req->request_id ? req->request_id : "-";

    if (req->started > 0) {
        time_t elapsed = time(NULL) - req->started;
        if (elapsed >= 5) {
            log_module(KC_LOG, LOG_WARNING, "[%s] kc_async: Request took %ld seconds (type=%d)",
                       req_id, (long)elapsed, req->type);
        }
    }

    int is_error = (curl_failed || http_code >= 500);
    kc_stats_record_request(latency_ms, is_error);

    if (latency_ms > 1000) {
        log_module(KC_LOG, LOG_INFO, "[%s] Async request slow: %lu ms (HTTP %ld, type=%d)",
                   req_id, latency_ms, http_code, req->type);
    }

    /* Check for retryable errors */
    if (curl_failed || http_code >= 500 || http_code == 429) {
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
            return;
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
            result = KC_SUCCESS;
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
            if (req->create_username && req->location_header[0]) {
                const char *user_id = strrchr(req->location_header, '/');
                if (user_id && user_id[1]) {
                    user_id++;
                    kc_userid_cache_put(req->create_username, user_id);

                    /* Cache the user representation so subsequent updates
                     * (email, attributes) get cache hits instead of racing
                     * concurrent GETs against Keycloak */
                    if (req->post_fields) {
                        json_error_t error;
                        json_t *repr = json_loads(req->post_fields, 0, &error);
                        if (repr) {
                            json_object_set_new(repr, "id", json_string(user_id));
                            json_object_del(repr, "credentials");
                            kc_user_repr_cache_put(user_id, repr);
                            log_module(KC_LOG, LOG_DEBUG,
                                       "[%s] kc_async create_user: Cached repr for %s",
                                       req_id, user_id);
                            json_decref(repr);
                        }
                    }
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
        } else if (token) {
            keycloak_free_access_token(token);
        }
        break;
    }
    case KC_ASYNC_GET_USER: {
        int result = KC_ERROR;
        struct kc_user user = {0};

        if (http_code == 200 && req->response.response) {
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
    /* Continued in next dispatch cases... */
    case KC_ASYNC_UPDATE_USER_GET:
    case KC_ASYNC_GET_GROUP_PATH:
    case KC_ASYNC_CREATE_SUBGROUP:
    case KC_ASYNC_SET_GROUP_ATTR:
    case KC_ASYNC_SET_GROUP_ATTR_GET:
    case KC_ASYNC_GET_GROUP_NAME:
    case KC_ASYNC_DELETE_GROUP:
    case KC_ASYNC_DELETE_USER:
    case KC_ASYNC_LIST_ATTRS:
    case KC_ASYNC_GET_ATTR:
    case KC_ASYNC_SET_USER_ATTR_GET:
    case KC_ASYNC_COALESCE_GET:
        /* These cases are handled in kc_async_handle_result_continued() */
        kc_async_handle_result_continued(req, http_code, req_id);
        break;
    }

    kc_async_request_cleanup(req);
}

/* Split out remaining dispatch cases to keep function size manageable */
static void
kc_async_handle_result_continued(struct kc_async_request *req, long http_code,
                                  const char *req_id)
{
    switch (req->type) {
    case KC_ASYNC_UPDATE_USER_GET: {
        int result = KC_ERROR;

        if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *repr = json_loads(req->response.response, 0, &error);
            if (repr) {
                json_object_del(repr, "credentials");

                if (req->update_email) {
                    json_object_set_new(repr, "email", json_string(req->update_email));
                }

                json_t *id_json = json_object_get(repr, "id");
                if (id_json && json_is_string(id_json)) {
                    kc_user_repr_cache_put(json_string_value(id_json), repr);
                }

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

                char *json_body = json_dumps(repr, JSON_COMPACT);
                json_decref(repr);

                if (json_body) {
                    struct kc_async_request *put_req = calloc(1, sizeof(*put_req));
                    if (put_req) {
                        put_req->session = req->session;
                        put_req->type = KC_ASYNC_UPDATE_USER;
                        put_req->cb.update_user = req->cb.update_user;
                        put_req->uri = strdup(req->uri);
                        put_req->post_fields = json_body;

                        if (keycloak_get_cached_token() && keycloak_get_cached_token()->access_token) {
                            put_req->bearer_token_copy = kc_get_token_copy();
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
        } else if (group_id) {
            pool_strfree(group_id);
        }
        break;
    }
    case KC_ASYNC_CREATE_SUBGROUP: {
        int result = KC_ERROR;
        char *group_id = NULL;

        if (http_code == 201) {
            if (req->location_header[0]) {
                const char *last_slash = strrchr(req->location_header, '/');
                if (last_slash && last_slash[1]) {
                    group_id = pool_strdup(last_slash + 1);
                    result = KC_SUCCESS;
                    log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_subgroup: Created group %s", req_id, group_id);
                }
            }
            if (!group_id) {
                log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_subgroup: Created but no Location header", req_id);
                result = KC_SUCCESS;
            }
        } else if (http_code == 409) {
            result = KC_USER_EXISTS;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_subgroup: Group already exists", req_id);
        } else if (http_code == 404) {
            result = KC_NOT_FOUND;
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_subgroup: Parent not found", req_id);
        } else {
            log_module(KC_LOG, LOG_DEBUG, "[%s] kc_async create_subgroup: Error (HTTP %ld)", req_id, http_code);
        }
        if (req->cb.create_subgroup) {
            req->cb.create_subgroup(req->session, result, group_id);
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
        int result = KC_ERROR;

        if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *repr = json_loads(req->response.response, 0, &error);
            if (repr) {
                json_t *attrs = json_object_get(repr, "attributes");
                if (!attrs) {
                    attrs = json_object();
                    json_object_set_new(repr, "attributes", attrs);
                }

                if (req->group_attr_value) {
                    json_t *attr_array = json_array();
                    json_array_append_new(attr_array, json_string(req->group_attr_value));
                    json_object_set_new(attrs, req->user_attr_name, attr_array);
                }

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

        if (result != KC_SUCCESS && req->cb.generic) {
            req->cb.generic(req->session, result);
        }
        break;
    }
    case KC_ASYNC_GET_GROUP_NAME: {
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
                        if (req->attr_prefix && prefix_len > 0) {
                            if (strncmp(key, req->attr_prefix, prefix_len) != 0)
                                continue;
                        }

                        if (!json_is_array(value) || json_array_size(value) == 0)
                            continue;

                        json_t *first_val = json_array_get(value, 0);
                        if (!first_val || !json_is_string(first_val))
                            continue;

                        const char *val_str = json_string_value(first_val);
                        if (!val_str || !*val_str)
                            continue;

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
        if (result != KC_SUCCESS && attr_value) {
            free(attr_value);
        }
        break;
    }
    case KC_ASYNC_SET_USER_ATTR_GET: {
        int result = KC_ERROR;

        if (http_code == 200 && req->response.response) {
            json_error_t error;
            json_t *repr = json_loads(req->response.response, 0, &error);
            if (repr) {
                json_object_del(repr, "credentials");

                json_t *attrs = json_object_get(repr, "attributes");
                if (!attrs) {
                    attrs = json_object();
                    json_object_set_new(repr, "attributes", attrs);
                }

                if (req->user_attr_value) {
                    json_t *attr_array = json_array();
                    json_array_append_new(attr_array, json_string(req->user_attr_value));
                    json_object_set_new(attrs, req->user_attr_name, attr_array);
                } else {
                    json_t *empty_array = json_array();
                    json_object_set_new(attrs, req->user_attr_name, empty_array);
                }

                json_t *id_json = json_object_get(repr, "id");
                if (id_json && json_is_string(id_json)) {
                    kc_user_repr_cache_put(json_string_value(id_json), repr);
                }

                char *json_body = json_dumps(repr, JSON_COMPACT);
                json_decref(repr);

                if (json_body) {
                    char *put_uri = kc_build_user_endpoint(req->realm_copy, req->user_id_copy);
                    if (put_uri) {
                        struct kc_async_request *put_req = calloc(1, sizeof(*put_req));
                        if (put_req) {
                            put_req->session = req->session;
                            put_req->type = KC_ASYNC_SET_ATTR;
                            put_req->cb.generic = req->cb.generic;
                            put_req->uri = put_uri;
                            put_req->post_fields = json_body;

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

        if (result != KC_SUCCESS && req->cb.generic) {
            req->cb.generic(req->session, result);
        }
        break;
    }
    case KC_ASYNC_COALESCE_GET: {
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
                json_object_del(repr, "credentials");

                json_t *attrs = json_object_get(repr, "attributes");
                if (!attrs) {
                    attrs = json_object();
                    json_object_set_new(repr, "attributes", attrs);
                }

                for (int i = 0; i < pending->attr_count; i++) {
                    if (pending->attrs[i].value) {
                        json_t *attr_array = json_array();
                        json_array_append_new(attr_array, json_string(pending->attrs[i].value));
                        json_object_set_new(attrs, pending->attrs[i].name, attr_array);
                    } else {
                        json_t *empty_array = json_array();
                        json_object_set_new(attrs, pending->attrs[i].name, empty_array);
                    }
                }

                json_t *id_json = json_object_get(repr, "id");
                if (id_json && json_is_string(id_json)) {
                    kc_user_repr_cache_put(json_string_value(id_json), repr);
                }

                char *json_body = json_dumps(repr, JSON_COMPACT);
                json_decref(repr);

                if (json_body) {
                    char *put_uri = kc_build_user_endpoint(req->realm_copy, pending->user_id);
                    if (put_uri) {
                        struct kc_async_request *put_req = calloc(1, sizeof(*put_req));
                        if (put_req) {
                            put_req->type = KC_ASYNC_SET_ATTR;
                            put_req->coalesce_pending = pending;
                            put_req->uri = put_uri;
                            put_req->post_fields = json_body;

                            if (keycloak_get_cached_token() && keycloak_get_cached_token()->access_token) {
                                put_req->bearer_token_copy = kc_get_token_copy();
                            }

                            if (!put_req->bearer_token_copy) {
                                log_module(KC_LOG, LOG_ERROR,
                                           "[%s] kc_async coalesce_get: Failed to get bearer token for PUT",
                                           req_id);
                                put_req->coalesce_pending = NULL;
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

                                /* Save values before curl_perform_async, which may
                                 * complete synchronously and free pending via the
                                 * KC_ASYNC_SET_ATTR completion handler */
                                int saved_pending_count = pending->attr_count;
                                char saved_pending_id[64];
                                snprintf(saved_pending_id, sizeof(saved_pending_id),
                                         "%s", pending->user_id);

                                if (curl_perform_async(put_req, opts) == 0) {
                                    log_module(KC_LOG, LOG_DEBUG,
                                               "[%s] kc_async coalesce_get: GET succeeded, "
                                               "issued PUT with %d merged attrs for %s",
                                               req_id, saved_pending_count, saved_pending_id);
                                    result = KC_SUCCESS;
                                    req->coalesce_pending = NULL;
                                } else {
                                    log_module(KC_LOG, LOG_ERROR,
                                               "[%s] kc_async coalesce_get: Failed to start PUT",
                                               req_id);
                                    put_req->coalesce_pending = NULL;
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

        if (result != KC_SUCCESS) {
            kc_pending_invoke_all_callbacks(pending, result);
            kc_pending_update_free(pending);
            req->coalesce_pending = NULL;
        }
        break;
    }
    default:
        break;
    }
}

/*
 * =============================================================================
 * Bridge Completion, Init/Cleanup, curl_perform_async
 * =============================================================================
 */

static void
kc_async_bridge_complete(long http_code, const char *body, size_t body_len,
                          json_t *json, const char *error, void *req_data)
{
    struct kc_async_request *req = (struct kc_async_request *)req_data;
    (void)json;

    if (body && body_len > 0) {
        req->response.response = malloc(body_len + 1);
        if (req->response.response) {
            memcpy(req->response.response, body, body_len);
            req->response.response[body_len] = '\0';
            req->response.size = body_len;
        }
    }

    unsigned long latency_ms = 0;
    if (req->started > 0) {
        time_t elapsed = time(NULL) - req->started;
        latency_ms = (unsigned long)(elapsed * 1000);
    }

    int curl_failed = (http_code == 0 && error != NULL);
    kc_async_handle_result(req, http_code, curl_failed, latency_ms);
}

void
kc_async_init(void)
{
    if (x3_kc_bridge_is_ready()) return;

    if (x3_kc_bridge_init() != 0) {
        log_module(KC_LOG, LOG_ERROR, "Failed to initialize libkc bridge");
        return;
    }
    log_module(KC_LOG, LOG_INFO, "Keycloak async HTTP initialized (libkc bridge)");
}

void
kc_async_cleanup(void)
{
    kc_coalesce_cleanup();
    x3_kc_bridge_shutdown();
    log_module(KC_LOG, LOG_INFO, "Keycloak async HTTP cleaned up (libkc bridge)");
}

static int
curl_perform_async(struct kc_async_request *req, struct curl_opts opts)
{
    const char *req_id = opts.request_id ? opts.request_id : "-";

    if (!req || !opts.uri) {
        log_module(KC_LOG, LOG_DEBUG, "[%s] curl_perform_async: Invalid arguments", req_id);
        return -1;
    }

    if (!x3_kc_bridge_is_ready()) {
        kc_async_init();
        if (!x3_kc_bridge_is_ready()) {
            log_module(KC_LOG, LOG_ERROR, "[%s] curl_perform_async: Failed to init bridge", req_id);
            return -1;
        }
    }

    if (opts.request_id) {
        req->request_id = pool_strdup(opts.request_id);
    }

    req->started = time(NULL);

    if (opts.max_retries > 0)
        req->max_retries = opts.max_retries;

    const char *method = "GET";
    switch (opts.method) {
    case HTTP_POST:   method = "POST";   break;
    case HTTP_PUT:    method = "PUT";    break;
    case HTTP_DELETE: method = "DELETE"; break;
    default:          method = "GET";    break;
    }

    const char *body = NULL;
    size_t body_len = 0;
    if (opts.post_data && opts.post_data_len > 0) {
        body = (const char *)opts.post_data;
        body_len = opts.post_data_len;
    } else if (opts.post_fields) {
        body = opts.post_fields;
        body_len = strlen(opts.post_fields);
    }

    struct curl_slist *headers = NULL;
    for (size_t i = 0; i < opts.header_count && i < 10; i++) {
        if (opts.header_list[i])
            headers = curl_slist_append(headers, opts.header_list[i]);
    }
    req->header_list = headers;

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
 * =============================================================================
 * Async API Functions
 * =============================================================================
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

    if (!realm.base_uri || !realm.realm || !client.client_id || !client.client_secret ||
        !handle || !password || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "kc_check_auth_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "kc_check_auth_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_AUTH;
    req->cb.auth = callback;

    user_enc = curl_easy_escape(NULL, handle, 0);
    passwd_enc = curl_easy_escape(NULL, password, 0);
    if (!user_enc || !passwd_enc) {
        log_module(KC_LOG, LOG_DEBUG, "kc_check_auth_async: Failed to escape credentials");
        goto error;
    }

    req->uri = kc_build_token_endpoint(realm);
    if (!req->uri) goto error;

    int post_len = snprintf(NULL, 0, query_params_tmpl, user_enc, passwd_enc) + 1;
    req->post_fields = malloc(post_len);
    if (!req->post_fields) goto error;
    snprintf(req->post_fields, post_len, query_params_tmpl, user_enc, passwd_enc);

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

int
keycloak_get_client_token_async(struct kc_realm realm, struct kc_client client,
                                 void *session, kc_client_token_callback callback)
{
    struct kc_async_request *req = NULL;
    static const char query_params[] = "grant_type=client_credentials";

    if (!realm.base_uri || !realm.realm || !client.client_id ||
        !client.client_secret || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "keycloak_get_client_token_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_CLIENT_TOKEN;
    req->cb.client_token = callback;

    req->uri = kc_build_token_endpoint(realm);
    if (!req->uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token_async: Failed to build URI");
        goto error;
    }

    req->post_fields = strdup(query_params);
    if (!req->post_fields) goto error;

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

int
keycloak_find_user_by_fingerprint_async(struct kc_realm realm, struct kc_client client,
                                         const char *fingerprint, void *session,
                                         kc_string_callback callback)
{
    struct kc_async_request *req = NULL;
    char *escaped_fp = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !fingerprint || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "fingerprint_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "fingerprint_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_FINGERPRINT;
    req->cb.fingerprint = callback;

    escaped_fp = curl_easy_escape(NULL, fingerprint, 0);
    if (!escaped_fp) {
        log_module(KC_LOG, LOG_DEBUG, "fingerprint_async: Failed to escape fingerprint");
        goto error;
    }

    req->uri = kc_build_fingerprint_search_endpoint(realm, escaped_fp);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "fingerprint_async: Failed to build URI");
        goto error;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "fingerprint_async: No valid token available (token refresh in progress?)");
        goto error;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "fingerprint_async: Failed to copy bearer token");
        goto error;
    }

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

int
keycloak_introspect_token_async(struct kc_realm realm, struct kc_client client,
                                 const char *token, void *session,
                                 kc_introspect_callback callback)
{
    struct kc_async_request *req = NULL;
    char *token_enc = NULL;
    static const char post_tmpl[] = "token=%s";

    if (!realm.base_uri || !realm.realm || !client.client_id || !client.client_secret ||
        !token || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "introspect_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "introspect_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_INTROSPECT;
    req->cb.introspect = callback;

    token_enc = curl_easy_escape(NULL, token, 0);
    if (!token_enc) {
        log_module(KC_LOG, LOG_DEBUG, "introspect_async: Failed to escape token");
        goto error;
    }

    req->uri = kc_build_introspect_endpoint(realm);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "introspect_async: Failed to build URI");
        goto error;
    }

    int post_len = snprintf(NULL, 0, post_tmpl, token_enc) + 1;
    req->post_fields = malloc(post_len);
    if (!req->post_fields) {
        log_module(KC_LOG, LOG_ERROR, "introspect_async: Failed to allocate POST data");
        goto error;
    }
    snprintf(req->post_fields, post_len, post_tmpl, token_enc);

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

int
keycloak_set_user_attribute_async(struct kc_realm realm, struct kc_client client,
                                   const char *user_id, const char *attr_name,
                                   const char *attr_value, void *session,
                                   kc_async_callback callback)
{
    (void)realm;
    (void)client;

    if (!user_id || !attr_name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "set_attr_async: Invalid arguments");
        return -1;
    }

    struct kc_pending_user_update *p = kc_coalesce_get_or_create(user_id);
    if (!p) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_async: Failed to create pending update");
        return -1;
    }

    if (kc_coalesce_add_attr(p, attr_name, attr_value, callback, session) < 0) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_async: Failed to add attr to pending");
        return -1;
    }

    return 0;
}

static void
kc_coalesce_flush_cb(void *data)
{
    struct kc_pending_user_update *p = data;
    struct kc_pending_user_update **pp;

    for (pp = &kc_pending_updates; *pp; pp = &(*pp)->next) {
        if (*pp == p) {
            *pp = p->next;
            break;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "coalesce: Flushing %d attrs for user %s",
               p->attr_count, p->user_id);

    if (p->attr_count == 0) {
        kc_pending_update_free(p);
        return;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "coalesce: No valid token for flush");
        kc_pending_invoke_all_callbacks(p, KC_ERROR);
        kc_pending_update_free(p);
        return;
    }

    json_t *cached_repr = kc_user_repr_cache_get(p->user_id);

    if (cached_repr) {
        log_module(KC_LOG, LOG_DEBUG, "coalesce: Cache hit for %s, merging %d attrs",
                   p->user_id, p->attr_count);

        json_t *repr = json_deep_copy(cached_repr);
        if (!repr) {
            log_module(KC_LOG, LOG_ERROR, "coalesce: Failed to copy cached repr");
            kc_pending_invoke_all_callbacks(p, KC_ERROR);
            kc_pending_update_free(p);
            return;
        }

        json_object_del(repr, "credentials");

        json_t *attrs = json_object_get(repr, "attributes");
        if (!attrs) {
            attrs = json_object();
            json_object_set_new(repr, "attributes", attrs);
        }

        for (int i = 0; i < p->attr_count; i++) {
            if (p->attrs[i].value) {
                json_t *attr_array = json_array();
                json_array_append_new(attr_array, json_string(p->attrs[i].value));
                json_object_set_new(attrs, p->attrs[i].name, attr_array);
            } else {
                json_t *empty_array = json_array();
                json_object_set_new(attrs, p->attrs[i].name, empty_array);
            }
        }

        /* Update cache with merged attrs BEFORE the PUT, so concurrent
         * operations (e.g. email update) see the merged state immediately
         * rather than racing against the Keycloak round-trip */
        kc_user_repr_cache_put(p->user_id, repr);

        char *json_body = json_dumps(repr, JSON_COMPACT);
        json_decref(repr);

        if (!json_body) {
            log_module(KC_LOG, LOG_ERROR, "coalesce: Failed to serialize JSON");
            kc_pending_invoke_all_callbacks(p, KC_ERROR);
            kc_pending_update_free(p);
            return;
        }

        struct kc_async_request *req = calloc(1, sizeof(*req));
        if (!req) {
            log_module(KC_LOG, LOG_ERROR, "coalesce: Out of memory for request");
            free(json_body);
            kc_pending_invoke_all_callbacks(p, KC_ERROR);
            kc_pending_update_free(p);
            return;
        }

        req->type = KC_ASYNC_SET_ATTR;
        req->coalesce_pending = p;
        req->uri = kc_build_user_endpoint(keycloak_get_realm(), p->user_id);
        req->post_fields = json_body;
        req->bearer_token_copy = kc_get_token_copy();

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

        /* Save values before curl_perform_async, which may complete
         * synchronously and free p via the completion callback */
        int saved_attr_count = p->attr_count;
        char saved_user_id[64];
        snprintf(saved_user_id, sizeof(saved_user_id), "%s", p->user_id);

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
                   saved_attr_count, saved_user_id);
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
    req->coalesce_pending = p;
    req->realm_copy = keycloak_get_realm();

    req->uri = kc_build_user_endpoint(keycloak_get_realm(), p->user_id);
    req->bearer_token_copy = kc_get_token_copy();

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

    /* Save values before curl_perform_async, which may complete
     * synchronously and free p via the completion callback */
    int saved_attr_count2 = p->attr_count;
    char saved_user_id2[64];
    snprintf(saved_user_id2, sizeof(saved_user_id2), "%s", p->user_id);

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
               saved_user_id2, saved_attr_count2);
}

int
keycloak_set_user_attribute_array_async(struct kc_realm realm, struct kc_client client,
                                         const char *user_id, const char *attr_name,
                                         const char **values, size_t value_count,
                                         void *session, kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !attr_name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "set_attr_array_async: Invalid arguments");
        return -1;
    }

    json_t *cached_repr = kc_user_repr_cache_get(user_id);

    if (cached_repr) {
        log_module(KC_LOG, LOG_DEBUG, "set_attr_array_async: Cache hit for %s, merging attribute %s",
                   user_id, attr_name);

        json_t *repr = json_deep_copy(cached_repr);
        if (!repr) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to copy cached repr");
            return -1;
        }

        json_t *attrs = json_object_get(repr, "attributes");
        if (!attrs) {
            attrs = json_object();
            json_object_set_new(repr, "attributes", attrs);
        }

        json_t *attr_array = json_array();
        for (size_t i = 0; i < value_count; i++) {
            if (values && values[i]) {
                json_array_append_new(attr_array, json_string(values[i]));
            }
        }
        json_object_set_new(attrs, attr_name, attr_array);

        json_body = json_dumps(repr, JSON_COMPACT);
        json_decref(repr);

        if (!json_body) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to build JSON from cache");
            return -1;
        }

        req = calloc(1, sizeof(*req));
        if (!req) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Out of memory");
            free(json_body);
            return -1;
        }
        req->session = session;
        req->type = KC_ASYNC_SET_ATTR;
        req->cb.generic = callback;

        req->uri = kc_build_user_endpoint(realm, user_id);
        if (!req->uri) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to build URI");
            free(json_body);
            free(req);
            return -1;
        }

        req->post_fields = json_body;

        if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: No valid token available (token refresh in progress?)");
            free(req->uri);
            free(req->post_fields);
            free(req);
            return -1;
        }
        req->bearer_token_copy = kc_get_token_copy();
        if (!req->bearer_token_copy) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to copy bearer token");
            free(req->uri);
            free(req->post_fields);
            free(req);
            return -1;
        }

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

    /* Cache miss - partial update */
    log_module(KC_LOG, LOG_DEBUG, "set_attr_array_async: Cache miss for %s, using partial update", user_id);

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_SET_ATTR;
    req->cb.generic = callback;

    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to build URI");
        goto error_array;
    }

    {
        json_t *attrs_obj = json_object();
        json_t *attr_arr = json_array();

        for (size_t i = 0; i < value_count; i++) {
            if (values && values[i]) {
                json_array_append_new(attr_arr, json_string(values[i]));
            }
        }
        json_object_set_new(attrs_obj, attr_name, attr_arr);

        json_t *user_obj = json_object();
        json_object_set_new(user_obj, "attributes", attrs_obj);
        json_body = json_dumps(user_obj, JSON_COMPACT);
        json_decref(user_obj);
    }

    if (!json_body) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to build JSON");
        goto error_array;
    }

    req->post_fields = json_body;
    json_body = NULL;

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: No valid token available (token refresh in progress?)");
        goto error_array;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: Failed to copy bearer token");
        goto error_array;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_PUT;
        opts.post_fields = req->post_fields;
        opts.xoauth2_bearer = req->bearer_token_copy;
        opts.header_list[0] = "Content-Type: application/json";
        opts.header_count = 1;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "set_attr_array_async: curl_perform_async failed");
            goto error_array;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "set_attr_array_async: Started attribute array update for %s.%s (%zu values)",
               user_id, attr_name, value_count);
    return 0;

error_array:
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

int
keycloak_set_email_verified_async(struct kc_realm realm, struct kc_client client,
                                   const char *user_id, int verified,
                                   void *session, kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "set_email_verified_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_SET_ATTR;
    req->cb.generic = callback;

    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: Failed to build URI");
        goto error_verified;
    }

    {
        json_t *user_obj = json_object();
        json_object_set_new(user_obj, "emailVerified", verified ? json_true() : json_false());
        json_body = json_dumps(user_obj, JSON_COMPACT);
        json_decref(user_obj);
    }

    if (!json_body) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: Failed to build JSON");
        goto error_verified;
    }

    req->post_fields = json_body;
    json_body = NULL;

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: No valid token available (token refresh in progress?)");
        goto error_verified;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: Failed to copy bearer token");
        goto error_verified;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_PUT;
        opts.post_fields = req->post_fields;
        opts.xoauth2_bearer = req->bearer_token_copy;
        opts.header_list[0] = "Content-Type: application/json";
        opts.header_count = 1;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "set_email_verified_async: curl_perform_async failed");
            goto error_verified;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "set_email_verified_async: Started for user %s (verified=%d)",
               user_id, verified);
    return 0;

error_verified:
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

int
keycloak_add_user_to_group_async(struct kc_realm realm, struct kc_client client,
                                  const char *user_id, const char *group_id,
                                  void *session, kc_async_callback callback)
{
    struct kc_async_request *req = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !group_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "add_group_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "add_group_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GROUP_ADD;
    req->cb.generic = callback;

    req->uri = kc_build_user_group_endpoint(realm, user_id, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "add_group_async: Failed to build URI");
        goto error_add_group;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "add_group_async: No valid token available (token refresh in progress?)");
        goto error_add_group;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "add_group_async: Failed to copy bearer token");
        goto error_add_group;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_PUT;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "add_group_async: curl_perform_async failed");
            goto error_add_group;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "add_group_async: Started adding user %s to group %s",
               user_id, group_id);
    return 0;

error_add_group:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

int
keycloak_remove_user_from_group_async(struct kc_realm realm, struct kc_client client,
                                       const char *user_id, const char *group_id,
                                       void *session, kc_async_callback callback)
{
    struct kc_async_request *req = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !group_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "remove_group_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "remove_group_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GROUP_REMOVE;
    req->cb.generic = callback;

    req->uri = kc_build_user_group_endpoint(realm, user_id, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "remove_group_async: Failed to build URI");
        goto error_rm_group;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "remove_group_async: No valid token available (token refresh in progress?)");
        goto error_rm_group;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "remove_group_async: Failed to copy bearer token");
        goto error_rm_group;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_DELETE;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "remove_group_async: curl_perform_async failed");
            goto error_rm_group;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "remove_group_async: Started removing user %s from group %s",
               user_id, group_id);
    return 0;

error_rm_group:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

int
keycloak_create_user_async(struct kc_realm realm, struct kc_client client,
                           const char *username, const char *email,
                           const char *password, void *session,
                           kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *user_repr = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token || !username || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "create_user_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_CREATE_USER;
    req->cb.generic = callback;

    req->create_username = pool_strdup(username);
    if (!req->create_username) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: Failed to copy username");
        free(req);
        return -1;
    }

    req->uri = kc_build_users_endpoint(realm);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: Failed to build URI");
        goto error_create;
    }

    user_repr = json_build_user_representation(username, email ? email : "", password);
    if (!user_repr) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: Failed to build user JSON");
        goto error_create;
    }

    req->post_fields = user_repr;
    user_repr = NULL;

    req->location_header[0] = '\0';

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: No valid token available (token refresh in progress?)");
        goto error_create;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "create_user_async: Failed to copy bearer token");
        goto error_create;
    }

    {
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
            goto error_create;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "create_user_async: Started user creation for %s", username);
    return 0;

error_create:
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

int
keycloak_create_user_with_hash_async(struct kc_realm realm, struct kc_client client,
                                      const char *username, const char *email,
                                      const char *cred_data, const char *secret_data,
                                      void *session, kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *user_repr = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !username || !cred_data || !secret_data || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "create_user_with_hash_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_CREATE_USER;
    req->cb.generic = callback;

    req->create_username = pool_strdup(username);
    if (!req->create_username) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: Failed to copy username");
        free(req);
        return -1;
    }

    req->uri = kc_build_users_endpoint(realm);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: Failed to build URI");
        goto error_hash;
    }

    user_repr = json_build_user_with_hash(username, email ? email : "", cred_data, secret_data);
    if (!user_repr) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: Failed to build user JSON");
        goto error_hash;
    }

    req->post_fields = user_repr;
    user_repr = NULL;

    req->location_header[0] = '\0';

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: No valid token available (token refresh in progress?)");
        goto error_hash;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "create_user_with_hash_async: Failed to copy bearer token");
        goto error_hash;
    }

    {
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
            goto error_hash;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "create_user_with_hash_async: Started user creation for %s",
               username);
    return 0;

error_hash:
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

int
keycloak_list_user_attributes_async(struct kc_realm realm, struct kc_client client,
                                     const char *user_id, const char *prefix,
                                     void *session, kc_list_attrs_callback callback)
{
    struct kc_async_request *req = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "list_user_attrs_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_LIST_ATTRS;
    req->cb.list_attrs = callback;

    if (prefix) {
        req->attr_prefix = pool_strdup(prefix);
        if (!req->attr_prefix) {
            log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: Failed to copy prefix");
            goto error_list;
        }
    }

    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: Failed to build URI");
        goto error_list;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: No valid token available (token refresh in progress?)");
        goto error_list;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: Failed to copy bearer token");
        goto error_list;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_GET;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "list_user_attrs_async: curl_perform_async failed");
            goto error_list;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "list_user_attrs_async: Started for user %s (prefix: %s)",
               user_id, prefix ? prefix : "(none)");
    return 0;

error_list:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->attr_prefix) free(req->attr_prefix);
        free(req);
    }
    return -1;
}

int
keycloak_get_user_attribute_async(struct kc_realm realm, struct kc_client client,
                                   const char *user_id, const char *attr_name,
                                   void *session, kc_string_callback callback)
{
    struct kc_async_request *req = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !attr_name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "get_user_attr_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GET_ATTR;
    req->cb.get_attr = callback;

    req->attr_name = pool_strdup(attr_name);
    if (!req->attr_name) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: Failed to copy attr_name");
        goto error_get_attr;
    }

    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: Failed to build URI");
        goto error_get_attr;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: No valid token available (token refresh in progress?)");
        goto error_get_attr;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: Failed to copy bearer token");
        goto error_get_attr;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_GET;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "get_user_attr_async: curl_perform_async failed");
            goto error_get_attr;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "get_user_attr_async: Started for user %s, attr %s",
               user_id, attr_name);
    return 0;

error_get_attr:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->attr_name) free(req->attr_name);
        free(req);
    }
    return -1;
}

int
keycloak_get_group_info_async(struct kc_realm realm, struct kc_client client,
                               const char *group_id, void *session,
                               kc_group_info_callback callback)
{
    struct kc_async_request *req = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "group_info_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "group_info_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GROUP_INFO;
    req->cb.group_info = callback;

    req->uri = kc_build_group_endpoint(realm, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "group_info_async: Failed to build URI");
        goto error_gi;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "group_info_async: No valid token available (token refresh in progress?)");
        goto error_gi;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "group_info_async: Failed to copy bearer token");
        goto error_gi;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_GET;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "group_info_async: curl_perform_async failed");
            goto error_gi;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "group_info_async: Started async lookup for group %s", group_id);
    return 0;

error_gi:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

int
keycloak_get_group_members_async(struct kc_realm realm, struct kc_client client,
                                  const char *group_id, void *session,
                                  kc_group_members_callback callback)
{
    struct kc_async_request *req = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "group_members_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "group_members_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GROUP_MEMBERS;
    req->cb.group_members = callback;

    req->uri = kc_build_group_members_endpoint(realm, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "group_members_async: Failed to build URI");
        goto error_gm;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "group_members_async: No valid token available (token refresh in progress?)");
        goto error_gm;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "group_members_async: Failed to copy bearer token");
        goto error_gm;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_GET;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "group_members_async: curl_perform_async failed");
            goto error_gm;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "group_members_async: Started async lookup for group %s", group_id);
    return 0;

error_gm:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->response.response) free(req->response.response);
        free(req);
    }
    return -1;
}

int
keycloak_get_user_async(struct kc_realm realm, struct kc_client client,
                         const char *username, void *session,
                         kc_get_user_callback callback)
{
    struct kc_async_request *req = NULL;
    char *escaped_user = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !username || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "get_user_async: Invalid arguments");
        return -1;
    }

    const char *cached_id = kc_userid_cache_get(username);
    if (cached_id) {
        struct kc_user user = {0};
        user.id = strdup(cached_id);
        if (user.id) {
            user.username = strdup(username);
            log_module(KC_LOG, LOG_DEBUG, "get_user_async: Cache hit for %s -> %s", username, cached_id);
            callback(session, KC_SUCCESS, &user);
            return 0;
        }
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "get_user_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GET_USER;
    req->cb.get_user = callback;

    escaped_user = curl_easy_escape(NULL, username, 0);
    if (!escaped_user) {
        log_module(KC_LOG, LOG_DEBUG, "get_user_async: Failed to escape username");
        goto error_gu;
    }

    req->uri = kc_build_user_by_username_endpoint(realm, escaped_user, 1);
    curl_free(escaped_user);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "get_user_async: Failed to build URI");
        goto error_gu;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "get_user_async: No valid token available (token refresh in progress?)");
        goto error_gu;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "get_user_async: Failed to copy bearer token");
        goto error_gu;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_GET;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "get_user_async: curl_perform_async failed");
            goto error_gu;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "get_user_async: Started async lookup for %s", username);
    return 0;

error_gu:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
    }
    return -1;
}

int
keycloak_update_user_representation_async(struct kc_realm realm, struct kc_client client,
                                           const char *user_id,
                                           const struct kc_user_update *update,
                                           void *session,
                                           kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !update || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "update_user_async: Invalid arguments");
        return -1;
    }

    if (!update->email && !update->cred_data) {
        log_module(KC_LOG, LOG_DEBUG, "update_user_async: Nothing to update");
        callback(session, KC_SUCCESS);
        return 0;
    }

    if (update->cred_data && !update->secret_data) {
        log_module(KC_LOG, LOG_DEBUG, "update_user_async: cred_data requires secret_data");
        return -1;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "update_user_async: No valid token available");
        return -1;
    }

    json_t *cached_repr = kc_user_repr_cache_get(user_id);

    if (cached_repr) {
        log_module(KC_LOG, LOG_DEBUG, "update_user_async: Cache hit for %s, merging updates", user_id);

        json_t *repr = json_deep_copy(cached_repr);
        if (!repr) {
            log_module(KC_LOG, LOG_ERROR, "update_user_async: Failed to copy cached repr");
            return -1;
        }

        json_object_del(repr, "credentials");

        if (update->email) {
            json_object_set_new(repr, "email", json_string(update->email));
            kc_user_repr_cache_put(user_id, repr);
        }

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

        json_body = json_dumps(repr, JSON_COMPACT);
        json_decref(repr);

        if (!json_body) {
            log_module(KC_LOG, LOG_ERROR, "update_user_async: Failed to serialize JSON");
            return -1;
        }

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
        req->bearer_token_copy = kc_get_token_copy();

        if (!req->uri || !req->bearer_token_copy) {
            log_module(KC_LOG, LOG_ERROR, "update_user_async: Failed to build request");
            goto error_upd;
        }

        log_module(KC_LOG, LOG_DEBUG, "update_user_async: JSON body = %s", json_body);

        {
            struct curl_opts opts = CURL_OPTS_INIT;
            opts.uri = req->uri;
            opts.method = HTTP_PUT;
            opts.post_fields = req->post_fields;
            opts.xoauth2_bearer = req->bearer_token_copy;
            opts.header_list[0] = "Content-Type: application/json";
            opts.header_count = 1;

            if (curl_perform_async(req, opts) < 0) {
                log_module(KC_LOG, LOG_ERROR, "update_user_async: curl_perform_async failed");
                goto error_upd;
            }
        }

        log_module(KC_LOG, LOG_DEBUG, "update_user_async: Started PUT with merged repr for %s", user_id);
        return 0;
    }

    /* Cache miss */
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
    req->bearer_token_copy = kc_get_token_copy();

    if (update->email)
        req->update_email = pool_strdup(update->email);
    if (update->username)
        req->update_username = pool_strdup(update->username);
    if (update->cred_data)
        req->update_cred_data = strdup(update->cred_data);
    if (update->secret_data)
        req->update_secret_data = strdup(update->secret_data);

    if (!req->uri || !req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "update_user_async: Failed to build GET request");
        goto error_upd;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_GET;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "update_user_async: curl_perform_async failed for GET");
            goto error_upd;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "update_user_async: Started GET for %s before merging", user_id);
    return 0;

error_upd:
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

int
keycloak_get_group_by_path_async(struct kc_realm realm, struct kc_client client,
                                  const char *group_path, void *session,
                                  kc_string_callback callback)
{
    struct kc_async_request *req = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_path || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "get_group_path_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "get_group_path_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GET_GROUP_PATH;
    req->cb.get_group_path = callback;

    req->uri = kc_build_group_by_path_endpoint(realm, group_path);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "get_group_path_async: Failed to build URI");
        goto error_gbp;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "get_group_path_async: No valid token available (token refresh in progress?)");
        goto error_gbp;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "get_group_path_async: Failed to copy bearer token");
        goto error_gbp;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_GET;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "get_group_path_async: curl_perform_async failed");
            goto error_gbp;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "get_group_path_async: Started async lookup for path %s", group_path);
    return 0;

error_gbp:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
    }
    return -1;
}

int
keycloak_get_group_by_name_async(struct kc_realm realm, struct kc_client client,
                                  const char *group_name, void *session,
                                  kc_string_callback callback)
{
    struct kc_async_request *req = NULL;
    char *escaped_name = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "get_group_name_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_GET_GROUP_NAME;
    req->cb.get_group_name = callback;

    escaped_name = curl_easy_escape(NULL, group_name, 0);
    if (!escaped_name) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: Failed to escape group name");
        goto error_gbn;
    }

    req->uri = kc_build_group_search_endpoint(realm, escaped_name);
    curl_free(escaped_name);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: Failed to build URI");
        goto error_gbn;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: No valid token available (token refresh in progress?)");
        goto error_gbn;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "get_group_name_async: Failed to copy bearer token");
        goto error_gbn;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_GET;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "get_group_name_async: curl_perform_async failed");
            goto error_gbn;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "get_group_name_async: Started async lookup for name %s", group_name);
    return 0;

error_gbn:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
    }
    return -1;
}

int
keycloak_delete_group_async(struct kc_realm realm, struct kc_client client,
                             const char *group_id, void *session,
                             kc_async_callback callback)
{
    struct kc_async_request *req = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "delete_group_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "delete_group_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_DELETE_GROUP;
    req->cb.delete_group = callback;

    req->uri = kc_build_group_endpoint(realm, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "delete_group_async: Failed to build URI");
        goto error_dg;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "delete_group_async: No valid token available (token refresh in progress?)");
        goto error_dg;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "delete_group_async: Failed to copy bearer token");
        goto error_dg;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_DELETE;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "delete_group_async: curl_perform_async failed");
            goto error_dg;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "delete_group_async: Started async delete for group %s", group_id);
    return 0;

error_dg:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
    }
    return -1;
}

int
keycloak_delete_user_async(struct kc_realm realm, struct kc_client client,
                            const char *user_id, void *session,
                            kc_async_callback callback)
{
    struct kc_async_request *req = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "delete_user_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "delete_user_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_DELETE_USER;
    req->cb.delete_user = callback;

    req->uri = kc_build_user_endpoint(realm, user_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "delete_user_async: Failed to build URI");
        goto error_du;
    }

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "delete_user_async: No valid token available (token refresh in progress?)");
        goto error_du;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "delete_user_async: Failed to copy bearer token");
        goto error_du;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_DELETE;
        opts.xoauth2_bearer = req->bearer_token_copy;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "delete_user_async: curl_perform_async failed");
            goto error_du;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "delete_user_async: Started async delete for user %s", user_id);
    return 0;

error_du:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        free(req);
    }
    return -1;
}

int
keycloak_create_subgroup_async(struct kc_realm realm, struct kc_client client,
                                const char *parent_id, const char *name,
                                void *session, kc_string_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !parent_id || !name || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "create_subgroup_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_CREATE_SUBGROUP;
    req->cb.create_subgroup = callback;

    req->uri = kc_build_group_children_endpoint(realm, parent_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: Failed to build URI");
        goto error_csg;
    }

    {
        json_t *body = json_object();
        json_object_set_new(body, "name", json_string(name));
        json_body = json_dumps(body, JSON_COMPACT);
        json_decref(body);
    }
    if (!json_body) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: Failed to build JSON body");
        goto error_csg;
    }
    req->post_fields = json_body;

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: No valid token available (token refresh in progress?)");
        goto error_csg;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: Failed to copy bearer token");
        goto error_csg;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_POST;
        opts.xoauth2_bearer = req->bearer_token_copy;
        opts.post_fields = json_body;
        opts.header_list[0] = "Content-Type: application/json";
        opts.header_count = 1;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "create_subgroup_async: curl_perform_async failed");
            goto error_csg;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "create_subgroup_async: Started async create for %s under %s", name, parent_id);
    return 0;

error_csg:
    if (req) {
        if (req->uri) free(req->uri);
        if (req->bearer_token_copy) free(req->bearer_token_copy);
        if (req->post_fields) free(req->post_fields);
        free(req);
    }
    return -1;
}

int
keycloak_set_group_attribute_async(struct kc_realm realm, struct kc_client client,
                                    const char *group_id, const char *attr_name,
                                    const char *attr_value, void *session,
                                    kc_async_callback callback)
{
    struct kc_async_request *req = NULL;
    char *json_body = NULL;

    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_id || !attr_name || !attr_value || !callback) {
        log_module(KC_LOG, LOG_DEBUG, "set_group_attr_async: Invalid arguments");
        return -1;
    }

    req = calloc(1, sizeof(*req));
    if (!req) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: Out of memory");
        return -1;
    }
    req->session = session;
    req->type = KC_ASYNC_SET_GROUP_ATTR;
    req->cb.generic = callback;

    req->uri = kc_build_group_endpoint(realm, group_id);
    if (!req->uri) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: Failed to build URI");
        goto error_sga;
    }

    {
        json_t *body = json_object();
        json_t *attrs = json_object();
        json_t *values = json_array();
        json_array_append_new(values, json_string(attr_value));
        json_object_set_new(attrs, attr_name, values);
        json_object_set_new(body, "attributes", attrs);
        json_body = json_dumps(body, JSON_COMPACT);
        json_decref(body);
    }
    if (!json_body) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: Failed to build JSON body");
        goto error_sga;
    }
    req->post_fields = json_body;

    if (!keycloak_get_cached_token() || !keycloak_get_cached_token()->access_token) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: No valid token available (token refresh in progress?)");
        goto error_sga;
    }
    req->bearer_token_copy = kc_get_token_copy();
    if (!req->bearer_token_copy) {
        log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: Failed to copy bearer token");
        goto error_sga;
    }

    {
        struct curl_opts opts = CURL_OPTS_INIT;
        opts.uri = req->uri;
        opts.method = HTTP_PUT;
        opts.xoauth2_bearer = req->bearer_token_copy;
        opts.post_fields = json_body;
        opts.header_list[0] = "Content-Type: application/json";
        opts.header_count = 1;

        if (curl_perform_async(req, opts) < 0) {
            log_module(KC_LOG, LOG_ERROR, "set_group_attr_async: curl_perform_async failed");
            goto error_sga;
        }
    }

    log_module(KC_LOG, LOG_DEBUG, "set_group_attr_async: Started async set %s=%s for group %s",
               attr_name, attr_value, group_id);
    return 0;

error_sga:
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
 * Async HTTP Worker Infrastructure (threadpool-based)
 * =============================================================================
 */

struct kc_http_work {
    char *uri;
    char *post_data;
    char *bearer_token;
    enum http_method method;
    int max_retries;
    struct memory response;
    long http_code;
    int result;
    void (*callback)(struct kc_http_work *work, void *ctx);
    void *callback_ctx;
};

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

    work->response.response = NULL;
    work->response.size = 0;

    curl_easy_setopt(curl, CURLOPT_URL, work->uri);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &work->response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);

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

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (work->bearer_token) {
        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", work->bearer_token);
        headers = curl_slist_append(headers, auth_header);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

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

static void
kc_http_done(void *result, void *user_data, tp_state_t state)
{
    struct kc_http_work *work = user_data;
    (void)result;

    if (state != TP_STATE_COMPLETED) {
        work->result = KC_ERROR;
    }

    if (work->callback) {
        work->callback(work, work->callback_ctx);
    }

    free(work->uri);
    if (work->post_data) {
        memset(work->post_data, 0, strlen(work->post_data));
        free(work->post_data);
    }
    free(work->bearer_token);
    free(work);
}

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

    token = kc_get_token_copy();
    work->bearer_token = token;

    if (!work->uri || (post_data && !work->post_data)) {
        free(work->uri);
        free(work->post_data);
        free(work->bearer_token);
        free(work);
        return -1;
    }

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

#endif /* WITH_KEYCLOAK */
