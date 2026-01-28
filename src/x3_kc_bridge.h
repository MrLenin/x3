/*
 * x3_kc_bridge.h - Bridge between X3's keycloak.c and libkc HTTP transport
 *
 * Provides a libkc-backed HTTP submission function that replaces keycloak.c's
 * direct curl_multi usage. keycloak.c calls x3_kc_bridge_submit() instead of
 * curl_perform_async(), and the bridge routes through kc_http_request().
 *
 * This eliminates the duplicated curl_multi integration (socket/timer callbacks,
 * handle pool, deferred cleanup) from keycloak.c — all of that is now in libkc.
 */

#ifndef X3_KC_BRIDGE_H
#define X3_KC_BRIDGE_H

#include <stddef.h>
#include <curl/curl.h>
#include <jansson.h>

/*
 * Completion callback type for bridge HTTP requests.
 * Called when the HTTP request completes (success or failure).
 *
 * @param http_code   HTTP status code (0 if connection failed)
 * @param body        Response body (may be NULL)
 * @param body_len    Response body length
 * @param json        Parsed JSON response (may be NULL if not JSON)
 * @param error       Error string (only set if http_code == 0)
 * @param req_data    Opaque request context (the kc_async_request pointer)
 */
typedef void (*x3_kc_bridge_cb)(long http_code, const char *body,
                                 size_t body_len, json_t *json,
                                 const char *error, void *req_data);

/*
 * Header callback type for capturing response headers.
 * Called for each response header line.
 *
 * @param name     Header name (e.g., "Location")
 * @param value    Header value (trimmed)
 * @param req_data Opaque request context
 */
typedef void (*x3_kc_header_cb)(const char *name, const char *value,
                                 void *req_data);

/*
 * Initialize the bridge (and libkc).
 * Must be called once during X3 startup, before any Keycloak operations.
 * Initializes the X3 event loop adapter and calls kc_init().
 *
 * @return 0 on success, -1 on error
 */
int x3_kc_bridge_init(void);

/*
 * Shutdown the bridge (and libkc).
 * Call during X3 shutdown.
 */
void x3_kc_bridge_shutdown(void);

/*
 * Check if the bridge is initialized.
 * @return 1 if initialized, 0 otherwise
 */
int x3_kc_bridge_is_ready(void);

/*
 * Submit an HTTP request through libkc.
 * Replaces keycloak.c's curl_perform_async().
 *
 * @param url          Request URL (must remain valid until callback)
 * @param method       HTTP method: "GET", "POST", "PUT", "DELETE"
 * @param body         Request body (NULL for no body)
 * @param body_len     Body length in bytes
 * @param headers      Additional HTTP headers (caller owns, freed after callback)
 * @param bearer_token Bearer token for Authorization header (NULL for none)
 * @param auth_user    HTTP Basic auth username (NULL for none)
 * @param auth_passwd  HTTP Basic auth password (NULL for none)
 * @param completion   Callback invoked when request completes
 * @param req_data     Opaque data passed to callback
 * @return 0 on success (request started), -1 on error
 */
int x3_kc_bridge_submit(const char *url, const char *method,
                         const char *body, size_t body_len,
                         struct curl_slist *headers,
                         const char *bearer_token,
                         const char *auth_user, const char *auth_passwd,
                         x3_kc_bridge_cb completion,
                         void *req_data);

#endif /* X3_KC_BRIDGE_H */
