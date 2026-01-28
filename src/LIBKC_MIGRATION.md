# keycloak.c → libkc Migration Guide

## Overview

This documents the changes needed in `keycloak.c` to replace its direct curl_multi
integration with libkc's HTTP transport layer via the `x3_kc_bridge`.

**Files already written:**
- `x3_kc_adapter.h/c` — X3 event loop adapter (ioset → kc_event_ops)
- `x3_kc_bridge.h/c` — HTTP transport bridge (curl_perform_async → kc_http_request)

## Architecture Change

```
Before:
  keycloak.c  →  curl_multi  →  ioset (direct)

After:
  keycloak.c  →  x3_kc_bridge  →  kc_http_request()  →  kc_event_ops  →  ioset
```

keycloak.c retains: URL building, JSON body construction, token management,
response parsing, type dispatch, retry logic, caches, stats.

libkc handles: curl_multi lifecycle, socket monitoring, timer management,
response buffering, JSON auto-parsing.

## Step 1: Extract `kc_async_handle_result()` from `kc_curl_check_completed()`

The completion handler at line 2301 has this structure:

```c
static void kc_curl_check_completed(void) {
    while ((msg = curl_multi_info_read(...))) {
        // A: Extract req, http_code, curl_result (lines 2309-2346)
        // B: Record stats (lines 2348-2357)
        // C: Check retry (lines 2359-2398)
        // D: Dispatch switch (lines 2402-3375)
        // E: Cleanup (line 3376)
    }
}
```

Extract sections B-E into a new function:

```c
/* Forward declare before kc_curl_check_completed */
static void kc_async_handle_result(struct kc_async_request *req,
                                    long http_code,
                                    int curl_failed,
                                    unsigned long latency_ms);

/* Refactored: call from both curl_multi and bridge paths */
static void
kc_async_handle_result(struct kc_async_request *req, long http_code,
                        int curl_failed, unsigned long latency_ms)
{
    const char *req_id = req->request_id ? req->request_id : "-";

    /* Stats */
    int is_error = (curl_failed || http_code >= 500);
    kc_stats_record_request(latency_ms, is_error);

    if (latency_ms > 1000) {
        log_module(KC_LOG, LOG_INFO, "[%s] Async request slow: %lu ms (HTTP %ld, type=%d)",
                   req_id, latency_ms, http_code, req->type);
    }

    /* Retry check */
    int retryable = 0;
    if (curl_failed || http_code >= 500 || http_code == 429)
        retryable = 1;

    if (retryable) {
        /* ... existing retry type check switch ... */
        if (should_retry && kc_async_schedule_retry(req))
            return;  /* Retry scheduled, don't dispatch yet */
    }

    /* Dispatch by type - MOVE the entire switch statement here */
    switch (req->type) {
    case KC_ASYNC_AUTH:
        /* ... existing code ... */
        break;
    /* ... all other cases ... */
    }

    /* Cleanup */
    kc_async_request_cleanup(req);
}
```

Then simplify `kc_curl_check_completed()`:

```c
static void
kc_curl_check_completed(void)
{
    CURLMsg *msg;
    int msgs_left;
    if (!kc_curl_multi) return;

    while ((msg = curl_multi_info_read(kc_curl_multi, &msgs_left))) {
        if (msg->msg != CURLMSG_DONE) continue;

        CURL *easy = msg->easy_handle;
        struct kc_async_request *req = NULL;
        long http_code = 0;
        double total_time = 0;

        curl_easy_getinfo(easy, CURLINFO_PRIVATE, &req);
        if (!req) {
            curl_multi_remove_handle(kc_curl_multi, easy);
            curl_easy_cleanup(easy);
            continue;
        }

        int curl_failed = (msg->data.result != CURLE_OK);
        if (!curl_failed) {
            curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &http_code);
            curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME, &total_time);
        }

        unsigned long latency_ms = (unsigned long)(total_time * 1000);
        kc_async_handle_result(req, http_code, curl_failed, latency_ms);
    }
}
```

## Step 2: Add Bridge Completion Callback

Add this after `kc_async_handle_result()`:

```c
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
```

## Step 3: Replace `curl_perform_async()`

Replace lines 3426-3493:

```c
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
        if (x3_kc_bridge_init() != 0) {
            log_module(KC_LOG, LOG_ERROR, "[%s] curl_perform_async: Failed to init bridge", req_id);
            return -1;
        }
    }

    /* Store request_id for completion logging */
    if (opts.request_id)
        req->request_id = pool_strdup(opts.request_id);

    /* Record start time */
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
```

## Step 4: Replace `kc_async_init()` and `kc_async_cleanup()`

### kc_async_init (line 3382)
```c
static void
kc_async_init(void)
{
    if (x3_kc_bridge_is_ready()) return;
    if (x3_kc_bridge_init() != 0) {
        log_module(KC_LOG, LOG_ERROR, "Failed to initialize libkc bridge");
        return;
    }
    log_module(KC_LOG, LOG_INFO, "Keycloak async HTTP initialized (libkc bridge)");
}
```

### kc_async_cleanup (line 3401)
```c
static void
kc_async_cleanup(void)
{
    x3_kc_bridge_shutdown();
    log_module(KC_LOG, LOG_INFO, "Keycloak async HTTP cleaned up (libkc bridge)");
}
```

## Step 5: Update `kc_async_retry_cb()`

Replace lines 2200-2244. Instead of re-adding to curl_multi, re-submit through bridge:

```c
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

    /* Re-submit through bridge using stored URI */
    int rc = x3_kc_bridge_submit(
        req->uri, NULL /* method stored in req */,
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
```

**Note:** Retry needs the original URL/method/body to re-submit. These are already stored in `req->uri` and `req->post_fields`. The HTTP method needs to be stored in the request struct (currently not tracked — add a field).

## Step 6: Update `kc_async_request_cleanup()`

In the cleanup function (line 2248), the curl handle management changes:

```c
/* OLD: Return curl handle to pool */
if (req->easy) {
    if (kc_curl_multi)
        curl_multi_remove_handle(kc_curl_multi, req->easy);
    kc_handle_pool_put(req->easy);
}

/* NEW: No curl handle to manage — bridge owns the HTTP lifecycle */
/* (remove the above block entirely) */
```

## Step 7: Add Include

At the top of keycloak.c, add:
```c
#include "x3_kc_bridge.h"
```

## Step 8: Dead Code Removal (Optional, Later)

After the bridge integration is working, remove:
- `kc_curl_multi` global (line 1710)
- `kc_handle_pool*` (lines 1712-1742)
- `kc_sock_info` struct (lines 1745-1750)
- `kc_pending_cleanup` (line 1757-1758)
- `kc_process_pending_cleanup()` (lines 1769-1779)
- `kc_curl_socket_cb()` (lines 1907-1976)
- `kc_curl_socket_ready()` (lines 1978-2005)
- `kc_curl_timer_cb()` (lines 2009-2032)
- `kc_curl_timeout_fired()` (lines 2036-2049)
- Forward declarations for removed functions (lines 1760-1762)
- `curl_apply_opts()` if no longer used by sync path (lines 1613-1703)

## Build System Changes (Makefile.in)

Add to `x3_SOURCES`:
```
x3_kc_adapter.c x3_kc_adapter.h
x3_kc_bridge.c x3_kc_bridge.h
```

Add to `CFLAGS`:
```
-I$(top_srcdir)/../libkc/include
```

Add to `LDADD`:
```
$(top_srcdir)/../libkc/libkc_static.a
```

(Assumes libkc is built as a static library and lives alongside x3 in the testnet directory.)
