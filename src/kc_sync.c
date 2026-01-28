/* kc_sync.c - Synchronous Keycloak API functions
 *
 * These are blocking HTTP calls used during startup/shutdown when the
 * event loop isn't running, or from contexts that can tolerate blocking.
 *
 * Extracted from keycloak.c as part of Phase 6 modularization.
 */

#include "config.h"

#ifdef WITH_KEYCLOAK

#include <string.h>
#include <curl/curl.h>
#include <jansson.h>

#include "keycloak.h"
#include "kc_sync.h"
#include "kc/kc_cache.h"
#include "kc_http_internal.h"
#include "log.h"
#include "mempool.h"

static struct log_type *SYNC_LOG;

void kc_sync_init(struct log_type *log)
{
    SYNC_LOG = log;
}

/*
 * =============================================================================
 * JSON Parsing (sync-only)
 * =============================================================================
 */

static int json_read_kc_users(const char* json_users_array,
    struct kc_user** kc_users_out)
{
    if (!json_users_array) {
        log_module(SYNC_LOG, LOG_DEBUG, "json_read_kc_users: Invalid arguments");
        return KC_ERROR;
    }

    *kc_users_out = NULL;

    log_module(SYNC_LOG, LOG_DEBUG, "json_read_kc_users: json_users_array: %s",
        json_users_array);

    json_error_t error;
    json_t* root = json_loads(json_users_array, 0, &error);
    if (!root) {
        log_module(SYNC_LOG, LOG_DEBUG, "json_read_kc_users: Failed to parse JSON: %s",
            error.text);
        return KC_ERROR;
    }

    if (!json_is_array(root)) {
        log_module(SYNC_LOG, LOG_DEBUG, "json_read_kc_users: Response is not a JSON array");
        json_decref(root);
        return KC_ERROR;
    }

    const size_t array_size = json_array_size(root);
    if (array_size == 0) {
        log_module(SYNC_LOG, LOG_DEBUG, "json_read_kc_users: Array is empty");
        json_decref(root);
        return KC_SUCCESS;
    }

    struct kc_user* users = (struct kc_user*)malloc(array_size * sizeof(struct kc_user));
    if (!users) {
        log_module(SYNC_LOG, LOG_DEBUG, "json_read_kc_users: Failed to allocate memory");
        json_decref(root);
        return KC_ERROR;
    }

    size_t success_count = 0;

    // Parse users, collecting successful ones
    for (size_t i = 0; i < array_size; i++) {
        json_t* user_object = json_array_get(root, i);
        if (!user_object || !json_is_object(user_object)) {
            log_module(SYNC_LOG, LOG_DEBUG,
                "json_read_kc_users: Skipping element %zu (not an object)", i);
            continue;
        }

        if (json_read_kc_user(user_object, &users[success_count]) == KC_SUCCESS) {
            success_count++;
        } else {
            log_module(SYNC_LOG, LOG_DEBUG,
                "json_read_kc_users: Skipping user at index %zu (parse failed)", i);
        }
    }

    if (success_count == 0) {
        log_module(SYNC_LOG, LOG_DEBUG, "json_read_kc_users: No users parsed successfully");
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

/*
 * =============================================================================
 * Synchronous User API
 * =============================================================================
 */

/* Still needed: called by keycloak_get_user() */
int keycloak_get_users(struct kc_realm realm, struct kc_client client, const char* user, const char* filter, bool exact, struct kc_user** user_out)
{
    (void)filter; /* TODO: implement additional filtering */

    if (!realm.base_uri || !realm.realm || !client.access_token || !user || !user_out) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_users: Invalid arguments");
        return KC_ERROR;
    }

    int result = KC_ERROR;
    char* uri = NULL;
    char* escaped_user = NULL;
    struct memory chunk = { 0 };

    /* URL-encode username */
    escaped_user = curl_easy_escape(NULL, user, 0);
    if (!escaped_user) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_users: Failed to escape user");
        goto cleanup;
    }

    /* Build URI using endpoint builder */
    uri = kc_build_user_by_username_endpoint(realm, escaped_user, exact);
    if (!uri) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_users: Failed to build uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.xoauth2_bearer = client.access_token->access_token;
    opts.method = HTTP_GET;

    long http_code = curl_perform(opts, &chunk);

    if (http_code == 200) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_users: User returned successfully (HTTP 200)");
        result = json_read_kc_users(chunk.response, user_out);
    } else if (http_code == 403) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_users: Forbidden to retrieve users (HTTP 403)");
        result = KC_FORBIDDEN;
    } else {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_users: Failed with HTTP %ld: %s",
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



int keycloak_get_user(struct kc_realm realm, struct kc_client client,
                             const char *user, struct kc_user *kc_user_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !user || !kc_user_out) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_user: Invalid arguments");
        return KC_ERROR;
    }

    /* Check user ID cache first (populated after user creation) */
    const char *cached_id = kc_userid_cache_get(user);
    if (cached_id) {
        /* Cache hit - return minimal user struct with just the ID */
        memset(kc_user_out, 0, sizeof(*kc_user_out));
        kc_user_out->id = strdup(cached_id);
        if (!kc_user_out->id) {
            log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_user: Failed to copy cached ID");
            return KC_ERROR;
        }
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_user: Cache hit for %s -> %s", user, cached_id);
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

/*
 * =============================================================================
 * Synchronous User Attributes API
 * =============================================================================
 */

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
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: Invalid arguments");
        return KC_ERROR;
    }

    *entries_out = NULL;
    int result = KC_ERROR;
    char *uri = NULL;
    struct memory chunk = {0};
    size_t prefix_len = prefix ? strlen(prefix) : 0;

    uri = kc_build_user_endpoint(realm, user_id);
    if (!uri) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: Failed to allocate uri");
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
            log_module(SYNC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: Failed to parse JSON: %s", error.text);
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
            log_module(SYNC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: No attributes on user");
            result = KC_SUCCESS; /* Empty list is valid */
        }

        json_decref(root);
    } else if (http_code == 404) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: User not found (HTTP 404)");
        result = KC_NOT_FOUND;
    } else {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_list_user_attributes: Failed with HTTP %ld: %s",
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

/*
 * =============================================================================
 * Synchronous Group API
 * =============================================================================
 */

int keycloak_get_group_by_name(struct kc_realm realm, struct kc_client client,
                               const char* group_name, char** group_id_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !group_name || !group_id_out) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Invalid arguments");
        return KC_ERROR;
    }

    *group_id_out = NULL;
    int result = KC_ERROR;
    char *uri = NULL;
    char *escaped_name = NULL;
    struct memory chunk = {0};

    escaped_name = curl_easy_escape(NULL, group_name, 0);
    if (!escaped_name) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Failed to escape group name");
        goto cleanup;
    }

    /* Build URI using endpoint builder */
    uri = kc_build_group_search_endpoint(realm, escaped_name);
    if (!uri) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Failed to allocate uri");
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
            log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Failed to parse JSON: %s", error.text);
            goto cleanup;
        }

        if (json_is_array(root) && json_array_size(root) > 0) {
            json_t* first_group = json_array_get(root, 0);
            json_t* id_val = json_object_get(first_group, "id");
            if (id_val && json_is_string(id_val)) {
                *group_id_out = pool_strdup(json_string_value(id_val));
                if (*group_id_out) {
                    result = KC_SUCCESS;
                    log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Found group '%s' with ID '%s'",
                        group_name, *group_id_out);
                }
            }
        } else {
            log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Group '%s' not found", group_name);
            result = KC_NOT_FOUND;
        }

        json_decref(root);
    } else {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_get_group_by_name: Failed with HTTP %ld: %s",
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

/*
 * =============================================================================
 * Synchronous Group Memory Management
 * =============================================================================
 */

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

/*
 * =============================================================================
 * Synchronous Fingerprint Lookup
 * =============================================================================
 */

int keycloak_find_user_by_fingerprint(struct kc_realm realm, struct kc_client client,
                                       const char* fingerprint, char** username_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token ||
        !fingerprint || !username_out) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Invalid arguments");
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
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Failed to escape fingerprint");
        goto cleanup;
    }

    /* Build the search URI using endpoint builder */
    uri = kc_build_fingerprint_search_endpoint(realm, escaped_fp);
    if (!uri) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Failed to allocate uri");
        goto cleanup;
    }

    struct curl_opts opts = CURL_OPTS_INIT;
    opts.uri = uri;
    opts.method = HTTP_GET;
    opts.xoauth2_bearer = client.access_token->access_token;

    long http_code = curl_perform(opts, &chunk);

    if (http_code != 200 || !chunk.response) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Failed with HTTP %ld",
            http_code);
        goto cleanup;
    }

    /* Parse JSON array response */
    json_error_t error;
    json_t* root = json_loads(chunk.response, 0, &error);
    if (!root) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Failed to parse JSON: %s",
            error.text);
        goto cleanup;
    }

    if (!json_is_array(root)) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Response is not an array");
        json_decref(root);
        goto cleanup;
    }

    size_t count = json_array_size(root);

    if (count == 0) {
        /* Fingerprint not registered to any user */
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Fingerprint not found");
        result = KC_NOT_FOUND;
        json_decref(root);
        goto cleanup;
    }

    if (count > 1) {
        /* Fingerprint collision! This should never happen if uniqueness is enforced */
        log_module(SYNC_LOG, LOG_ERROR,
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
            log_module(SYNC_LOG, LOG_DEBUG, "keycloak_find_user_by_fingerprint: Found user '%s'",
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

/*
 * =============================================================================
 * Synchronous Group Creation
 * =============================================================================
 */

int keycloak_create_group(struct kc_realm realm, struct kc_client client,
                          const char* group_name, char** group_id_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !group_name) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_create_group: Invalid arguments");
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
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_create_group: Failed to allocate uri");
        goto cleanup;
    }

    /* Build JSON: { "name": "group_name" } */
    json_t* group_obj = json_object();
    json_object_set_new(group_obj, "name", json_string(group_name));
    json_body = json_dumps(group_obj, JSON_COMPACT);
    json_decref(group_obj);

    if (!json_body) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_create_group: Failed to build JSON");
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
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_create_group: Group '%s' created (HTTP 201)",
            group_name);
        result = KC_SUCCESS;

        /* Try to get the group ID - need to look it up since Keycloak doesn't return it */
        if (group_id_out) {
            keycloak_get_group_by_name(realm, client, group_name, group_id_out);
        }
    } else if (http_code == 409) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_create_group: Group '%s' already exists (HTTP 409)",
            group_name);
        result = KC_USER_EXISTS;

        /* Still get the ID if requested */
        if (group_id_out) {
            keycloak_get_group_by_name(realm, client, group_name, group_id_out);
        }
    } else {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_create_group: Failed with HTTP %ld: %s",
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



int keycloak_ensure_channels_parent(struct kc_realm realm, struct kc_client client,
                                    char** group_id_out)
{
    if (!realm.base_uri || !realm.realm || !client.access_token || !group_id_out) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_ensure_channels_parent: Invalid arguments");
        return KC_ERROR;
    }

    *group_id_out = NULL;

    /* Try to find existing "irc-channels" group */
    static const char parent_name[] = "irc-channels";
    int rc = keycloak_get_group_by_name(realm, client, parent_name, group_id_out);

    if (rc == KC_SUCCESS && *group_id_out) {
        log_module(SYNC_LOG, LOG_DEBUG, "keycloak_ensure_channels_parent: Found existing parent group");
        return KC_SUCCESS;
    }

    /* Create the parent group */
    log_module(SYNC_LOG, LOG_DEBUG, "keycloak_ensure_channels_parent: Creating parent group '%s'",
        parent_name);

    rc = keycloak_create_group(realm, client, parent_name, group_id_out);
    if (rc == KC_SUCCESS || rc == KC_USER_EXISTS) {
        return KC_SUCCESS;
    }

    return KC_ERROR;
}

#endif /* WITH_KEYCLOAK */
