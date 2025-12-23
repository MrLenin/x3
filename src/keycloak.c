#include <string.h>

#include "keycloak.h"
#include "log.h"

static struct log_type* KC_LOG;

void
init_keycloak()
{
    KC_LOG = log_register_type("keycloak", "file:keycloak.log");
}

typedef size_t(*curl_write_cb_ptr)(char*, size_t, size_t, void*);

struct memory {
    char* response;
    size_t size;
};

enum http_method {
    HTTP_GET = 0,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE
};

struct curl_opts {
    char* uri;
    const char* header_list[10];
    size_t header_count;
    char* post_fields;
    char* auth_user;
    char* auth_passwd;
    char* xoauth2_bearer;
    curl_write_cb_ptr write_callback;
    enum http_method method;
};

static void kc_user_free_fields(struct kc_user* user)
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

    kc_user_free_fields(user);
    free(user);
}

static long curl_perform(struct curl_opts opts, struct memory* chunk_out)
{
    CURL* curl = NULL;
    CURLcode res = CURLE_FAILED_INIT;
    char* user_pwd = NULL;
    long result = KC_ERROR;  // assume failure
    long http_code = 0;
    struct curl_slist* header_list = NULL;

    // Input validation
    if (!opts.uri) {
        log_module(KC_LOG, LOG_DEBUG, "curl_perform: Invalid arguments");
        return KC_ERROR;
    }

    // Initialize curl
    curl = curl_easy_init();
    if (!curl) {
        log_module(KC_LOG, LOG_DEBUG, "curl_perform: Failed to init curl");
        return KC_ERROR;
    }

    // Setup write callback if output buffer provided
    if (chunk_out && opts.write_callback) {
        // Allocate response buffer
        chunk_out->response = malloc(1);
        if (!chunk_out->response) {
            log_module(KC_LOG, LOG_DEBUG, "curl_perform: Failed to allocate response buffer");
            goto cleanup;
        }
        chunk_out->size = 0;  // Initialize size

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, opts.write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)chunk_out);
    }

    // Setup HTTP method
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
            // GET is default
            break;
    }

    // Setup POST/PUT fields if provided
    if (opts.post_fields) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, opts.post_fields);
    }

    // Setup headers if provided
    if (opts.header_count > 0) {
        for (size_t i = 0; i < opts.header_count; i++) {
            header_list = curl_slist_append(header_list, opts.header_list[i]);
        }
        if (!header_list) {
            log_module(KC_LOG, LOG_DEBUG, "curl_perform: Failed to build headers");
            goto cleanup;
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

    if (opts.auth_user && opts.auth_passwd) {
        // URL-encode credentials
        char* user_enc  = curl_easy_escape(NULL, opts.auth_user, 0);
        if (!user_enc) {
            log_module(KC_LOG, LOG_DEBUG, "curl_perform: Failed to escape admin");
            goto cleanup;
        }
    
        char* passwd_enc = curl_easy_escape(NULL, opts.auth_passwd, 0);
        if (!passwd_enc) {
            log_module(KC_LOG, LOG_DEBUG, "curl_perform: Failed to escape passwd");
            curl_free(user_enc);
            goto cleanup;
        }

        // Build "user:passwd" string
        size_t user_pwd_len = strlen(user_enc) + 1 + strlen(passwd_enc) + 1;
        user_pwd = malloc(user_pwd_len);
        if (!user_pwd) {
            log_module(KC_LOG, LOG_DEBUG, "curl_perform: Failed to allocate user_pwd");
            curl_free(user_enc);
            memset(passwd_enc, 0, strlen(passwd_enc));
            curl_free(passwd_enc);
            goto cleanup;
        }
        snprintf(user_pwd, user_pwd_len, "%s:%s", user_enc, passwd_enc);

        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERPWD, user_pwd);

        memset(passwd_enc, 0, strlen(passwd_enc));
        curl_free(passwd_enc);
        curl_free(user_enc);
    }

    if (opts.xoauth2_bearer) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, opts.xoauth2_bearer);
    }

    // Set URL and perform request
    curl_easy_setopt(curl, CURLOPT_URL, opts.uri);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        log_module(KC_LOG, LOG_DEBUG, "curl_perform failed: %s", curl_easy_strerror(res));
        goto cleanup;
    }

    // Get HTTP response code
    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code) == CURLE_OK) {
        result = http_code;
    }

cleanup:
    if (user_pwd) {
        memset(user_pwd, 0, strlen(user_pwd));
        free(user_pwd);
    }

    // Free header list if we created one
    if (header_list) {
        curl_slist_free_all(header_list);
    }

    // Cleanup on failure
    if (result < 0 && chunk_out && chunk_out->response) {
        free(chunk_out->response);
        chunk_out->response = NULL;
        chunk_out->size = 0;
    }

    if (curl) {
        curl_easy_cleanup(curl);
    }

    return result;
}

// Convenience wrapper for calls without response body
static long curl_perform_simple(struct curl_opts opts)
{
    if (!opts.uri) {
        log_module(KC_LOG, LOG_DEBUG, "curl_perform: Invalid arguments");
        return KC_ERROR;
    }

    return curl_perform(opts, NULL);
}

static size_t curl_write_cb(char* data, size_t size, size_t nmemb, void* clientp)
{
    size_t realsize = size * nmemb;
    struct memory* mem = (struct memory*)clientp;

    char* ptr = realloc(mem->response, mem->size + realsize + 1);
    if (!ptr) {
        return 0;  // Out of memory
    }

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
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

    if (json_read_object_string(user_object, "email", &user_out->email, &user_out->email_size) != KC_SUCCESS) {
        free(user_out->id);
        free(user_out->username);
        return KC_ERROR;
    }

    if (json_read_object_boolean(user_object, "emailVerified", &user_out->emailVerified) != KC_SUCCESS) {
        free(user_out->id);
        free(user_out->username);
        free(user_out->email);
        return KC_ERROR;
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
    // Input validation
    if (!username || !email || !passwd) {
        log_module(KC_LOG, LOG_DEBUG, "json_build_user_representation: Invalid arguments");
        return NULL;
    }

    char* result = NULL;

    json_t* user_obj = json_object();
    json_t* creds = json_array();
    json_t* cred = json_object();

    // Build JSON using Jansson API
    json_object_set_new(user_obj, "username", json_string(username));
    json_object_set_new(user_obj, "email", json_string(email));
    json_object_set_new(user_obj, "enabled", json_true());

    json_object_set_new(cred, "type", json_string("password"));
    json_object_set_new(cred, "value", json_string(passwd));
    json_object_set_new(cred, "temporary", json_false());
    json_array_append_new(creds, cred);
    json_object_set_new(user_obj, "credentials", creds);

    result = json_dumps(user_obj, JSON_COMPACT);

    if (!result) {
        log_module(KC_LOG, LOG_DEBUG, "json_build_user_representation: json_dumps failed");
    }

    json_decref(user_obj);

    return result;
}


int keycloak_get_client_token(struct kc_realm realm, struct kc_client client, struct access_token** access_token)
{
    // Input validation
    if (!realm.base_uri || !realm.realm || !client.client_id || !client.client_secret || !access_token) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char* uri = NULL;
    struct memory chunk = {
        .response = NULL,
        .size = 0
    };

    static const char query_params[] = "&grant_type=client_credentials";
    static const char uri_tmpl[] = "%s/realms/%s/protocol/openid-connect/token";

    // Build URI safely
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_client_token: Failed to build uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm);

    struct curl_opts opts = {
        .uri = uri,
        .post_fields = query_params,
        .write_callback = curl_write_cb,
        .auth_user = client.client_id,
        .auth_passwd = client.client_secret,
        .header_count = 0
    };

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
    // Input validation
    if (!realm.base_uri || !realm.realm || !user || !passwd || !user_access_token) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char* uri = NULL;
    char* user_enc = NULL;
    char* passwd_enc = NULL;
    char* query_params = NULL;
    struct memory chunk = {
        .response = NULL,
        .size = 0
    };

    // URL-encode credentials
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
    static const char uri_tmpl[] = "%s/realms/%s/protocol/openid-connect/token";

    // Build URI safely
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Failed to build uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm);

    // Build query parameters safely
    int query_params_len = snprintf(NULL, 0, query_params_tmpl, user_enc, passwd_enc) + 1;
    query_params = malloc(query_params_len);
    if (!query_params) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Failed to build query_params");
        goto cleanup;
    }
    snprintf(query_params, query_params_len, query_params_tmpl, user_enc, passwd_enc);

    struct curl_opts opts = {
        .uri = uri,
        .post_fields = query_params,
        .auth_user = client.client_id,
        .auth_passwd = client.client_secret,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

    long http_code = curl_perform(opts, &chunk);

    if (http_code != 200 || !chunk.response) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Failed with HTTP %ld: %s",
            http_code, chunk.response ? chunk.response : "no response");
        goto cleanup;
    } else {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_token: Token retrieved successfully (HTTP 200)");
        result = json_read_kc_access_token(chunk.response, user_access_token);
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
    if (!realm.base_uri || !realm.realm || !client.access_token || !user || !user_out) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_users: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char* uri = NULL;
    char* escaped_user = NULL;
    struct memory chunk = { 0 };

    static const char exact_tmpl[] = "&exact=true";
    static const char uri_tmpl[] = "%s/admin/realms/%s/users/?username=%s%s";

    // URL-encode username
    escaped_user = curl_easy_escape(NULL, user, 0);
    if (!escaped_user) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_users: Failed to escape user");
        goto cleanup;
    }

    // Build URI safely
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, escaped_user, exact ? exact_tmpl : "") + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_users: Failed to build uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, escaped_user, exact ? exact_tmpl : "");

    struct curl_opts opts = {
        .uri = uri,
        .write_callback = curl_write_cb,
        .xoauth2_bearer = client.access_token->access_token,
        .header_count = 0
    };

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
    // Input validation
    if (!realm.base_uri || !realm.realm || !client.access_token || !username || !email || !passwd) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    int auth_header_len = 0;

    char* uri = NULL;
    char* auth_header = NULL;
    char* user_repr = NULL;

    struct memory chunk = {
        .response = NULL,
        .size = 0
    };

    static const char uri_tmpl[] = "%s/admin/realms/%s/users";

    // Build URI safely
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user: Failed to build uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm);


    user_repr = json_build_user_representation(username, email, passwd);
    if (!user_repr) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_user: Failed to build user representation");
        goto cleanup;
    }

    struct curl_opts opts = {
        .uri = uri,
        .post_fields = user_repr,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

    long http_code = curl_perform(opts, &chunk);

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
    if (auth_header) {
        memset(auth_header, 0, auth_header_len);
        free(auth_header);
    }
    if (user_repr) {
        memset(user_repr, 0, strlen(user_repr));
        free(user_repr);
    }
    if (uri) {
        free(uri);
    }

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

    if (keycloak_get_users(realm, client, user, NULL, true, &kc_users) == 1) {
        *kc_user_out = kc_users[0];
        free(kc_users);
        return KC_SUCCESS;
    }

    return KC_ERROR;
}

void keycloak_free_users(struct kc_user* users, size_t count)
{
    if (!users) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        kc_user_free_fields(&users[i]);
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

    // Update email if provided (requires PUT to user endpoint)
    if (new_email) {
        static const char uri_tmpl[] = "%s/admin/realms/%s/users/%s";
        int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, user_id) + 1;
        uri = malloc(uri_len);
        if (!uri) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Failed to allocate uri");
            goto cleanup;
        }
        snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, user_id);

        json_t* user_obj = json_object();
        json_object_set_new(user_obj, "email", json_string(new_email));
        json_body = json_dumps(user_obj, JSON_COMPACT);
        json_decref(user_obj);

        if (!json_body) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Failed to build JSON");
            goto cleanup;
        }

        struct curl_opts opts = {
            .uri = uri,
            .method = HTTP_PUT,
            .post_fields = json_body,
            .xoauth2_bearer = client.access_token->access_token,
            .write_callback = curl_write_cb,
            .header_list = { "Content-Type: application/json" },
            .header_count = 1
        };

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

    // Update password if provided (requires PUT to reset-password endpoint)
    if (new_password) {
        static const char uri_tmpl[] = "%s/admin/realms/%s/users/%s/reset-password";
        int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, user_id) + 1;
        uri = malloc(uri_len);
        if (!uri) {
            log_module(KC_LOG, LOG_DEBUG, "keycloak_update_user: Failed to allocate uri");
            goto cleanup;
        }
        snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, user_id);

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

        struct curl_opts opts = {
            .uri = uri,
            .method = HTTP_PUT,
            .post_fields = json_body,
            .xoauth2_bearer = client.access_token->access_token,
            .write_callback = curl_write_cb,
            .header_list = { "Content-Type: application/json" },
            .header_count = 1
        };

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

int keycloak_delete_user(struct kc_realm realm, struct kc_client client,
                         const char* user_id)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !user_id) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_user: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char* uri = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    static const char uri_tmpl[] = "%s/admin/realms/%s/users/%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, user_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_user: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, user_id);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_DELETE,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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
    if (uri) {
        free(uri);
    }

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
    char* uri = NULL;
    char* json_body = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    static const char uri_tmpl[] = "%s/admin/realms/%s/users/%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, user_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_user_attribute: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, user_id);

    // Build JSON: { "attributes": { "attr_name": ["attr_value"] } }
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

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_PUT,
        .post_fields = json_body,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_list = { "Content-Type: application/json" },
        .header_count = 1
    };

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
    char* uri = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    static const char uri_tmpl[] = "%s/admin/realms/%s/users/%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, user_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_user_attribute: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, user_id);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_GET,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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

int keycloak_add_user_to_group(struct kc_realm realm, struct kc_client client,
                               const char* user_id, const char* group_id)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !user_id || !group_id) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_add_user_to_group: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char* uri = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    static const char uri_tmpl[] = "%s/admin/realms/%s/users/%s/groups/%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, user_id, group_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_add_user_to_group: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, user_id, group_id);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_PUT,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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
    if (uri) {
        free(uri);
    }

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
    char* uri = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    static const char uri_tmpl[] = "%s/admin/realms/%s/users/%s/groups/%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, user_id, group_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_remove_user_from_group: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, user_id, group_id);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_DELETE,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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
    char* uri = NULL;
    char* escaped_name = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    escaped_name = curl_easy_escape(NULL, group_name, 0);
    if (!escaped_name) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Failed to escape group name");
        goto cleanup;
    }

    static const char uri_tmpl[] = "%s/admin/realms/%s/groups?search=%s&exact=true";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, escaped_name) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, escaped_name);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_GET,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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
    char* uri = NULL;
    char* post_fields = NULL;
    char* escaped_token = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    static const char uri_tmpl[] = "%s/realms/%s/protocol/openid-connect/token/introspect";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_introspect_token: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm);

    // URL-encode token
    escaped_token = curl_easy_escape(NULL, bearer_token, 0);
    if (!escaped_token) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_introspect_token: Failed to escape token");
        goto cleanup;
    }

    // Build POST body
    static const char post_tmpl[] = "token=%s&token_type_hint=access_token";
    int post_len = snprintf(NULL, 0, post_tmpl, escaped_token) + 1;
    post_fields = malloc(post_len);
    if (!post_fields) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_introspect_token: Failed to allocate post_fields");
        goto cleanup;
    }
    snprintf(post_fields, post_len, post_tmpl, escaped_token);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_POST,
        .post_fields = post_fields,
        .auth_user = client.client_id,
        .auth_passwd = client.client_secret,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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
