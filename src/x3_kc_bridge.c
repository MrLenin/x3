/*
 * x3_kc_bridge.c - Bridge between X3's keycloak.c and libkc HTTP transport
 *
 * Replaces keycloak.c's direct curl_multi usage with libkc's kc_http layer.
 * Provides x3_kc_bridge_submit() as the async HTTP submission function.
 *
 * Architecture:
 *   keycloak.c  →  x3_kc_bridge  →  kc_http_request()  →  kc_event_ops (ioset)
 *
 * keycloak.c still handles:
 *   - URL building, JSON body construction
 *   - Token management (waiter queue, refresh)
 *   - Response parsing and type dispatch
 *   - Retry logic (by re-calling x3_kc_bridge_submit)
 *   - User ID cache, user repr cache
 *   - Statistics
 *
 * libkc handles:
 *   - curl_multi lifecycle
 *   - Socket monitoring via kc_event_ops (→ ioset)
 *   - Timer management via kc_event_ops (→ timeq)
 *   - Response buffering and JSON parsing
 *   - Connection pooling (internal to curl_multi)
 */

#include "x3_kc_bridge.h"
#include "x3_kc_adapter.h"

#include "kc/kc.h"
#include "kc/kc_http.h"

#include <stdlib.h>
#include <string.h>

static int bridge_initialized = 0;

/* Per-request bridge context: wraps the completion callback + request data */
struct bridge_ctx {
    x3_kc_bridge_cb completion;
    void *req_data;
    /* Copies of data that must outlive the kc_http_request submission */
    char *url_copy;
    char *body_copy;
    char *bearer_copy;
    char *auth_user_copy;
    char *auth_passwd_copy;
    struct curl_slist *headers_copy;
};

static void bridge_ctx_free(struct bridge_ctx *ctx);
static void bridge_http_callback(struct kc_http_response *resp, void *data);

/* --- Public API --- */

int
x3_kc_bridge_init(void)
{
    if (bridge_initialized)
        return 0;

    x3_kc_adapter_init();

    if (kc_init(x3_kc_get_event_ops(), x3_kc_get_log_ops()) != 0) {
        x3_kc_adapter_cleanup();
        return -1;
    }

    bridge_initialized = 1;
    return 0;
}

void
x3_kc_bridge_shutdown(void)
{
    if (!bridge_initialized)
        return;

    kc_shutdown();
    x3_kc_adapter_cleanup();
    bridge_initialized = 0;
}

int
x3_kc_bridge_is_ready(void)
{
    return bridge_initialized;
}

int
x3_kc_bridge_submit(const char *url, const char *method,
                     const char *body, size_t body_len,
                     struct curl_slist *headers,
                     const char *bearer_token,
                     const char *auth_user, const char *auth_passwd,
                     x3_kc_bridge_cb completion,
                     void *req_data)
{
    struct bridge_ctx *ctx;
    struct kc_http_request req;
    int rc;

    if (!bridge_initialized || !url || !completion)
        return -1;

    /* Auto-initialize if needed */
    if (!bridge_initialized) {
        if (x3_kc_bridge_init() != 0)
            return -1;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->completion = completion;
    ctx->req_data = req_data;

    /*
     * Copy URL and body: keycloak.c's kc_async_request owns these strings,
     * but kc_http_request needs them to remain valid until the callback fires.
     * Since kc_http stores the request data internally, we need owned copies
     * in the bridge context.
     */
    ctx->url_copy = strdup(url);
    if (!ctx->url_copy) {
        free(ctx);
        return -1;
    }

    if (body && body_len > 0) {
        ctx->body_copy = malloc(body_len + 1);
        if (!ctx->body_copy) {
            bridge_ctx_free(ctx);
            return -1;
        }
        memcpy(ctx->body_copy, body, body_len);
        ctx->body_copy[body_len] = '\0';
    }

    if (bearer_token) {
        ctx->bearer_copy = strdup(bearer_token);
        if (!ctx->bearer_copy) {
            bridge_ctx_free(ctx);
            return -1;
        }
    }

    /* HTTP Basic auth (used for client_credentials grant) */
    if (auth_user) {
        ctx->auth_user_copy = strdup(auth_user);
        if (!ctx->auth_user_copy) {
            bridge_ctx_free(ctx);
            return -1;
        }
    }
    if (auth_passwd) {
        ctx->auth_passwd_copy = strdup(auth_passwd);
        if (!ctx->auth_passwd_copy) {
            bridge_ctx_free(ctx);
            return -1;
        }
    }

    /* Deep-copy the headers list since keycloak.c may free them */
    if (headers) {
        struct curl_slist *src = headers;
        struct curl_slist *copy = NULL;
        while (src) {
            copy = curl_slist_append(copy, src->data);
            src = src->next;
        }
        ctx->headers_copy = copy;
    }

    /* Build kc_http_request */
    memset(&req, 0, sizeof(req));
    req.url = ctx->url_copy;
    req.method = method;  /* Static string literals, no copy needed */
    req.body = ctx->body_copy;
    req.body_len = body ? body_len : 0;
    req.headers = ctx->headers_copy;
    req.bearer_token = ctx->bearer_copy;
    req.auth_user = ctx->auth_user_copy;
    req.auth_passwd = ctx->auth_passwd_copy;
    req.timeout_ms = 30000;  /* 30s default; keycloak.c's ASYNC_TIMEOUT_SEC is 30 */

    rc = kc_http_request(&req, bridge_http_callback, ctx);
    if (rc != 0) {
        bridge_ctx_free(ctx);
        return -1;
    }

    return 0;
}

/* --- Internal --- */

/*
 * Called by libkc when the HTTP request completes.
 * Translates kc_http_response to the bridge callback format.
 */
static void
bridge_http_callback(struct kc_http_response *resp, void *data)
{
    struct bridge_ctx *ctx = (struct bridge_ctx *)data;

    if (!ctx || !ctx->completion) {
        bridge_ctx_free(ctx);
        return;
    }

    ctx->completion(resp->status_code,
                    resp->body, resp->body_len,
                    resp->json,
                    resp->error,
                    ctx->req_data);

    bridge_ctx_free(ctx);
}

static void
bridge_ctx_free(struct bridge_ctx *ctx)
{
    if (!ctx)
        return;
    free(ctx->url_copy);
    if (ctx->body_copy) {
        /* Zero sensitive data (passwords, tokens) before freeing */
        memset(ctx->body_copy, 0, strlen(ctx->body_copy));
        free(ctx->body_copy);
    }
    if (ctx->bearer_copy) {
        memset(ctx->bearer_copy, 0, strlen(ctx->bearer_copy));
        free(ctx->bearer_copy);
    }
    if (ctx->auth_user_copy) {
        memset(ctx->auth_user_copy, 0, strlen(ctx->auth_user_copy));
        free(ctx->auth_user_copy);
    }
    if (ctx->auth_passwd_copy) {
        memset(ctx->auth_passwd_copy, 0, strlen(ctx->auth_passwd_copy));
        free(ctx->auth_passwd_copy);
    }
    if (ctx->headers_copy)
        curl_slist_free_all(ctx->headers_copy);
    free(ctx);
}
