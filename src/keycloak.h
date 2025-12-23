#ifndef KEYCLOAK_H
#define KEYCLOAK_H

#include <stdbool.h>
#include <stddef.h>

#include <curl/curl.h>
#include <jansson.h>

// Error codes
enum kc_error {
    KC_SUCCESS = 0,
    KC_ERROR = -1,
    KC_USER_EXISTS = -2,
    KC_FORBIDDEN = -3,
    KC_NOT_FOUND = -4
};

// Data structures
struct access_token {
    char* access_token;
    size_t access_token_size;
    long expires_in;
    long refresh_expires_in;
    char* refresh_token;
    size_t refresh_token_size;
    char* token_type;
    size_t token_type_size;
    long not_before_policy;
    char* session_state;
    size_t session_state_size;
    char* scope;
    size_t scope_size;
};

struct kc_user {
    char* id;
    size_t id_size;
    char* username;
    size_t username_size;
    char* email;
    size_t email_size;
    bool emailVerified;
    struct access_token* access_token;
    int opserv_level;           // Custom attribute: x3_opserv_level
};

// Token introspection result
struct kc_token_info {
    bool active;
    char* username;
    size_t username_size;
    char* email;
    size_t email_size;
    char* sub;                  // Subject (user ID)
    size_t sub_size;
    int opserv_level;           // From token claims or user attributes
    long exp;                   // Expiration timestamp
    long iat;                   // Issued at timestamp
};

struct kc_realm {
    char* base_uri;
    const char* realm;
};

struct kc_client {
    char* client_id;
    char* client_secret;
    struct access_token* access_token;
};

// Public API functions

/**
 * Retrieves an access token from Keycloak using password grant
 * @param realm         Keycloak realm configuration (must not be NULL)
 * @param client        Admin username (must not be NULL)
 * @param access_token  Output pointer for access token
 * @return KC_SUCCESS on success, KC_ERROR on failure
 */
int keycloak_get_client_token(struct kc_realm realm, struct kc_client client, struct access_token** access_token);

/**
 * Retrieves an access token from Keycloak using password grant
 * @param realm         Keycloak realm configuration (must not be NULL)
 * @param admin         Admin username (must not be NULL)
 * @param passwd        Admin password (must not be NULL)
 * @param access_token  Output pointer for access token
 * @return KC_SUCCESS on success, KC_ERROR on failure
 */
int keycloak_get_user_token(struct kc_realm realm, struct kc_client client, const char* user, const char* passwd, struct access_token** user_access_token);
/**
 * Retrieves users from Keycloak matching the search criteria
 * @param realm     Keycloak realm configuration
 * @param user      Username to search for (must not be NULL)
 * @param filter    Additional filter (can be NULL, currently unused)
 * @param exact     Whether to perform exact match
 * @param user_out  Output pointer for user array (caller must free)
 * @return Number of users found (>= 0), KC_ERROR on failure, KC_FORBIDDEN on permission denied
 */
int keycloak_get_users(struct kc_realm realm, struct kc_client client, const char* user, const char* filter, bool exact, struct kc_user** user_out);

/**
 * Retrieves a single user from Keycloak by exact username match
 * @param realm        Keycloak realm configuration
 * @param user         Username to search for (must not be NULL)
 * @param kc_user_out  Output pointer for user data
 * @return KC_SUCCESS if exactly one user found, KC_ERROR otherwise
 */
int keycloak_get_user(struct kc_realm realm, struct kc_client client, const char *user, struct kc_user *kc_user_out);

/**
 * Creates a new user in Keycloak
 * @param realm     Keycloak realm configuration
 * @param username  New user's username (must not be NULL)
 * @param email     New user's email (must not be NULL)
 * @param passwd    New user's password (must not be NULL)
 * @return KC_SUCCESS on creation, KC_USER_EXISTS if user already exists, KC_ERROR on other failures
 */
int keycloak_create_user(struct kc_realm realm, struct kc_client client, const char* username, const char* email, const char* passwd);

/**
 * Frees memory allocated for a kc_user structure and its fields
 * @param user      Pointer to user (can be NULL)
 */
void keycloak_user_free(struct kc_user* user);

/**
 * Frees memory allocated for an array of kc_user structures
 * @param users     Pointer to user array (can be NULL)
 * @param count     Number of users in the array
 */
void keycloak_free_users(struct kc_user* users, size_t count);

/**
 * Frees memory allocated for an access_token structure
 * @param token     Pointer to access_token (can be NULL)
 */
void keycloak_free_access_token(struct access_token* token);

/**
 * Updates a user's password and/or email in Keycloak
 * @param realm         Keycloak realm configuration
 * @param client        Client with admin access token
 * @param user_id       User's Keycloak ID (UUID)
 * @param new_password  New password (can be NULL to skip)
 * @param new_email     New email (can be NULL to skip)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if user doesn't exist, KC_ERROR on failure
 */
int keycloak_update_user(struct kc_realm realm, struct kc_client client,
                         const char* user_id, const char* new_password,
                         const char* new_email);

/**
 * Deletes a user from Keycloak
 * @param realm     Keycloak realm configuration
 * @param client    Client with admin access token
 * @param user_id   User's Keycloak ID (UUID)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if user doesn't exist, KC_ERROR on failure
 */
int keycloak_delete_user(struct kc_realm realm, struct kc_client client,
                         const char* user_id);

/**
 * Sets a custom attribute on a Keycloak user
 * @param realm      Keycloak realm configuration
 * @param client     Client with admin access token
 * @param user_id    User's Keycloak ID (UUID)
 * @param attr_name  Attribute name (e.g., "x3_opserv_level")
 * @param attr_value Attribute value as string
 * @return KC_SUCCESS on success, KC_NOT_FOUND if user doesn't exist, KC_ERROR on failure
 */
int keycloak_set_user_attribute(struct kc_realm realm, struct kc_client client,
                                const char* user_id, const char* attr_name,
                                const char* attr_value);

/**
 * Gets a custom attribute from a Keycloak user
 * @param realm      Keycloak realm configuration
 * @param client     Client with admin access token
 * @param user_id    User's Keycloak ID (UUID)
 * @param attr_name  Attribute name (e.g., "x3_opserv_level")
 * @param value_out  Output pointer for attribute value (caller must free)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if user or attr doesn't exist, KC_ERROR on failure
 */
int keycloak_get_user_attribute(struct kc_realm realm, struct kc_client client,
                                const char* user_id, const char* attr_name,
                                char** value_out);

/**
 * Adds a user to a Keycloak group
 * @param realm     Keycloak realm configuration
 * @param client    Client with admin access token
 * @param user_id   User's Keycloak ID (UUID)
 * @param group_id  Group's Keycloak ID (UUID)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if user/group doesn't exist, KC_ERROR on failure
 */
int keycloak_add_user_to_group(struct kc_realm realm, struct kc_client client,
                               const char* user_id, const char* group_id);

/**
 * Removes a user from a Keycloak group
 * @param realm     Keycloak realm configuration
 * @param client    Client with admin access token
 * @param user_id   User's Keycloak ID (UUID)
 * @param group_id  Group's Keycloak ID (UUID)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if user/group doesn't exist, KC_ERROR on failure
 */
int keycloak_remove_user_from_group(struct kc_realm realm, struct kc_client client,
                                    const char* user_id, const char* group_id);

/**
 * Gets a Keycloak group by name
 * @param realm        Keycloak realm configuration
 * @param client       Client with admin access token
 * @param group_name   Group name to search for
 * @param group_id_out Output pointer for group ID (caller must free)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if group doesn't exist, KC_ERROR on failure
 */
int keycloak_get_group_by_name(struct kc_realm realm, struct kc_client client,
                               const char* group_name, char** group_id_out);

/**
 * Introspects/validates an OAuth2 bearer token
 * @param realm         Keycloak realm configuration
 * @param client        Client credentials for introspection
 * @param bearer_token  The bearer token to validate
 * @param info_out      Output pointer for token info (caller must free with keycloak_free_token_info)
 * @return KC_SUCCESS if token is valid/active, KC_FORBIDDEN if inactive/invalid, KC_ERROR on failure
 */
int keycloak_introspect_token(struct kc_realm realm, struct kc_client client,
                              const char* bearer_token,
                              struct kc_token_info** info_out);

/**
 * Frees memory allocated for a kc_token_info structure
 * @param info      Pointer to token info (can be NULL)
 */
void keycloak_free_token_info(struct kc_token_info* info);

#endif /* KEYCLOAK_H */
