#include "config.h"

#ifdef WITH_KEYCLOAK

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
    (void)filter; /* TODO: implement additional filtering */

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
        .header_list = { "Content-Type: application/json" },
        .header_count = 1
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
    char* uri = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };
    size_t prefix_len = prefix ? strlen(prefix) : 0;

    static const char uri_tmpl[] = "%s/admin/realms/%s/users/%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, user_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: Failed to allocate uri");
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
    char* uri = NULL;
    char* escaped_path = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    /* URL-encode the path (preserving slashes for Keycloak API) */
    escaped_path = curl_easy_escape(NULL, group_path, 0);
    if (!escaped_path) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_path: Failed to escape path");
        goto cleanup;
    }

    /* Keycloak endpoint: GET /admin/realms/{realm}/group-by-path/{path}
     * Note: The path should start with /
     */
    static const char uri_tmpl[] = "%s/admin/realms/%s/group-by-path%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, group_path) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_by_path: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, group_path);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_GET,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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
    if (escaped_path) {
        curl_free(escaped_path);
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
    char* uri = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    /* Build URI: /admin/realms/{realm}/groups/{id}/members */
    static const char uri_tmpl[] = "%s/admin/realms/%s/groups/%s/members?max=1000";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, group_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_members: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, group_id);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_GET,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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
    char* uri = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    /* Build URI: GET /admin/realms/{realm}/groups/{group_id} */
    static const char uri_tmpl[] = "%s/admin/realms/%s/groups/%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, group_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_get_group_info: Failed to allocate uri");
        return KC_ERROR;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, group_id);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_GET,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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
    char* uri = NULL;
    char* escaped_fp = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    /* URL-encode the fingerprint for the query parameter
     * Keycloak's Admin API supports q= for attribute search:
     * GET /admin/realms/{realm}/users?q=x509_fingerprints:{fingerprint}
     */
    escaped_fp = curl_easy_escape(NULL, fingerprint, 0);
    if (!escaped_fp) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Failed to escape fingerprint");
        goto cleanup;
    }

    /* Build the search URI */
    static const char uri_tmpl[] = "%s/admin/realms/%s/users?q=x509_fingerprints:%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, escaped_fp) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, escaped_fp);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_GET,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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
    char* uri = NULL;
    char* json_body = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    /* Build URI: POST /admin/realms/{realm}/groups */
    static const char uri_tmpl[] = "%s/admin/realms/%s/groups";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_group: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm);

    /* Build JSON: { "name": "group_name" } */
    json_t* group_obj = json_object();
    json_object_set_new(group_obj, "name", json_string(group_name));
    json_body = json_dumps(group_obj, JSON_COMPACT);
    json_decref(group_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_group: Failed to build JSON");
        goto cleanup;
    }

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_POST,
        .post_fields = json_body,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_list = { "Content-Type: application/json" },
        .header_count = 1
    };

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
    char* uri = NULL;
    char* json_body = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    /* Build URI: POST /admin/realms/{realm}/groups/{parent_id}/children */
    static const char uri_tmpl[] = "%s/admin/realms/%s/groups/%s/children";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, parent_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_subgroup: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, parent_id);

    /* Build JSON: { "name": "group_name" } */
    json_t* group_obj = json_object();
    json_object_set_new(group_obj, "name", json_string(group_name));
    json_body = json_dumps(group_obj, JSON_COMPACT);
    json_decref(group_obj);

    if (!json_body) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_create_subgroup: Failed to build JSON");
        goto cleanup;
    }

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_POST,
        .post_fields = json_body,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_list = { "Content-Type: application/json" },
        .header_count = 1
    };

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
    char* uri = NULL;
    char* json_body = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    /* First, get the existing group to preserve its current state */
    struct kc_group_info* info = NULL;
    int rc = keycloak_get_group_info(realm, client, group_id, &info);
    if (rc == KC_NOT_FOUND) {
        return KC_NOT_FOUND;
    }
    if (rc != KC_SUCCESS || !info) {
        return KC_ERROR;
    }

    /* Build URI: PUT /admin/realms/{realm}/groups/{group_id} */
    static const char uri_tmpl[] = "%s/admin/realms/%s/groups/%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, group_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_set_group_attribute: Failed to allocate uri");
        keycloak_free_group_info(info);
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, group_id);

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
    char* uri = NULL;
    struct memory chunk = { .response = NULL, .size = 0 };

    /* Build URI: DELETE /admin/realms/{realm}/groups/{group_id} */
    static const char uri_tmpl[] = "%s/admin/realms/%s/groups/%s";
    int uri_len = snprintf(NULL, 0, uri_tmpl, realm.base_uri, realm.realm, group_id) + 1;
    uri = malloc(uri_len);
    if (!uri) {
        log_module(KC_LOG, LOG_DEBUG, "keycloak_delete_group: Failed to allocate uri");
        goto cleanup;
    }
    snprintf(uri, uri_len, uri_tmpl, realm.base_uri, realm.realm, group_id);

    struct curl_opts opts = {
        .uri = uri,
        .method = HTTP_DELETE,
        .xoauth2_bearer = client.access_token->access_token,
        .write_callback = curl_write_cb,
        .header_count = 0
    };

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
