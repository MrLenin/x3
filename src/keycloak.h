#ifndef KEYCLOAK_H
#define KEYCLOAK_H

#include "config.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef WITH_KEYCLOAK

#include <curl/curl.h>
#include <jansson.h>

// Error codes
enum kc_error {
    KC_SUCCESS = 0,
    KC_ERROR = -1,
    KC_USER_EXISTS = -2,
    KC_FORBIDDEN = -3,
    KC_NOT_FOUND = -4,
    KC_COLLISION = -5   // Multiple users matched (e.g., fingerprint collision)
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
    const char* base_uri;
    const char* realm;
};

struct kc_client {
    const char* client_id;
    const char* client_secret;
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
 * Frees only the internal fields of a kc_user structure (not the struct itself)
 * Use this for stack-allocated kc_user structs
 * @param user      Pointer to user (can be NULL)
 */
void keycloak_user_free_fields(struct kc_user* user);

/**
 * Frees memory allocated for a kc_user structure and its fields
 * Use this only for heap-allocated (malloc'd) kc_user structs
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
 * Metadata key-value pair for listing attributes
 */
struct kc_metadata_entry {
    char* key;
    char* value;
    struct kc_metadata_entry* next;
};

/**
 * Lists all user attributes matching a prefix
 * @param realm       Keycloak realm configuration
 * @param client      Client with admin access token
 * @param user_id     User's Keycloak ID (UUID)
 * @param prefix      Attribute prefix to match (e.g., "metadata.")
 * @param entries_out Output pointer for linked list of entries (caller must free with keycloak_free_metadata_entries)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if user doesn't exist, KC_ERROR on failure
 */
int keycloak_list_user_attributes(struct kc_realm realm, struct kc_client client,
                                  const char* user_id, const char* prefix,
                                  struct kc_metadata_entry** entries_out);

/**
 * Frees a linked list of metadata entries
 * @param entries     Head of the list to free (can be NULL)
 */
void keycloak_free_metadata_entries(struct kc_metadata_entry* entries);

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
 * Gets a Keycloak group by hierarchical path
 * Keycloak paths use forward slashes: /parent/child/grandchild
 * @param realm        Keycloak realm configuration
 * @param client       Client with admin access token
 * @param group_path   Full path to group (e.g., "/irc-channels/#help/owner")
 * @param group_id_out Output pointer for group ID (caller must free)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if group doesn't exist, KC_ERROR on failure
 */
int keycloak_get_group_by_path(struct kc_realm realm, struct kc_client client,
                               const char* group_path, char** group_id_out);

/**
 * Group member entry for iteration
 */
struct kc_group_member {
    char* username;
    char* user_id;
    unsigned short access_level;   /* Access level from group attribute (0 if not set) */
    struct kc_group_member* next;
};

/**
 * Group information including attributes
 */
struct kc_group_info {
    char* id;
    char* name;
    char* path;
    unsigned short access_level;   /* Parsed from x3_access_level attribute */
    struct kc_metadata_entry* attributes;
};

/**
 * Gets members of a Keycloak group
 * @param realm        Keycloak realm configuration
 * @param client       Client with admin access token
 * @param group_id     Group's Keycloak ID (UUID)
 * @param members_out  Output pointer for linked list of members (caller must free with keycloak_free_group_members)
 * @return Number of members found (>= 0), KC_NOT_FOUND if group doesn't exist, KC_ERROR on failure
 */
int keycloak_get_group_members(struct kc_realm realm, struct kc_client client,
                               const char* group_id, struct kc_group_member** members_out);

/**
 * Frees a linked list of group member entries
 * @param members     Head of the list to free (can be NULL)
 */
void keycloak_free_group_members(struct kc_group_member* members);

/**
 * Gets a Keycloak group by ID with full attributes
 * @param realm        Keycloak realm configuration
 * @param client       Client with admin access token
 * @param group_id     Group's Keycloak ID (UUID)
 * @param info_out     Output pointer for group info (caller must free with keycloak_free_group_info)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if group doesn't exist, KC_ERROR on failure
 */
int keycloak_get_group_info(struct kc_realm realm, struct kc_client client,
                            const char* group_id, struct kc_group_info** info_out);

/**
 * Gets a custom attribute from a Keycloak group
 * @param realm        Keycloak realm configuration
 * @param client       Client with admin access token
 * @param group_id     Group's Keycloak ID (UUID)
 * @param attr_name    Attribute name (e.g., "x3_access_level")
 * @param value_out    Output pointer for attribute value (caller must free)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if group or attr doesn't exist, KC_ERROR on failure
 */
int keycloak_get_group_attribute(struct kc_realm realm, struct kc_client client,
                                 const char* group_id, const char* attr_name,
                                 char** value_out);

/**
 * Gets group members with access level from group attribute
 * Convenience function that fetches group info first to get access_level,
 * then fetches members and populates their access_level field
 * @param realm        Keycloak realm configuration
 * @param client       Client with admin access token
 * @param group_id     Group's Keycloak ID (UUID)
 * @param members_out  Output pointer for linked list of members with access_level populated
 * @return Number of members found (>= 0), KC_NOT_FOUND if group doesn't exist, KC_ERROR on failure
 */
int keycloak_get_group_members_with_level(struct kc_realm realm, struct kc_client client,
                                          const char* group_id, struct kc_group_member** members_out);

/**
 * Frees memory allocated for a kc_group_info structure
 * @param info      Pointer to group info (can be NULL)
 */
void keycloak_free_group_info(struct kc_group_info* info);

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
 * Validate a JWT token locally using cached JWKS public keys
 * This avoids an HTTP round-trip to Keycloak for token validation.
 * Falls back to introspection if local validation fails (unknown key, etc).
 *
 * @param realm         Keycloak realm configuration (for JWKS endpoint)
 * @param token         The JWT bearer token to validate
 * @param info_out      Output pointer for token info (caller must free with keycloak_free_token_info)
 * @return KC_SUCCESS if valid, KC_FORBIDDEN if expired/invalid signature, KC_ERROR if can't validate locally
 */
int keycloak_validate_jwt_local(struct kc_realm realm, const char *token,
                                struct kc_token_info **info_out);

/**
 * Frees memory allocated for a kc_token_info structure
 * @param info      Pointer to token info (can be NULL)
 */
void keycloak_free_token_info(struct kc_token_info* info);

/**
 * Find a Keycloak user by certificate fingerprint
 *
 * Searches for users with the given fingerprint in their x509_fingerprints
 * attribute. This is used for SASL EXTERNAL authentication (Scenario 1).
 *
 * @param realm         Keycloak realm configuration
 * @param client        Client with admin access token
 * @param fingerprint   SHA-256 certificate fingerprint (with colons, e.g. "AA:BB:CC:...")
 * @param username_out  Output pointer for username (caller must free)
 * @return KC_SUCCESS if exactly one user found
 *         KC_NOT_FOUND if no user has this fingerprint
 *         KC_COLLISION if multiple users have this fingerprint (security error!)
 *         KC_ERROR on failure
 */
int keycloak_find_user_by_fingerprint(struct kc_realm realm, struct kc_client client,
                                       const char* fingerprint, char** username_out);

/**
 * Creates a new top-level group in Keycloak
 * @param realm        Keycloak realm configuration
 * @param client       Client with admin access token
 * @param group_name   Name of the group to create
 * @param group_id_out Output pointer for created group's ID (caller must free, can be NULL)
 * @return KC_SUCCESS on success, KC_USER_EXISTS if group already exists, KC_ERROR on failure
 */
int keycloak_create_group(struct kc_realm realm, struct kc_client client,
                          const char* group_name, char** group_id_out);

/**
 * Creates a new subgroup under an existing parent group
 * @param realm          Keycloak realm configuration
 * @param client         Client with admin access token
 * @param parent_id      Parent group's Keycloak ID (UUID)
 * @param group_name     Name of the subgroup to create
 * @param group_id_out   Output pointer for created group's ID (caller must free, can be NULL)
 * @return KC_SUCCESS on success, KC_USER_EXISTS if group already exists,
 *         KC_NOT_FOUND if parent doesn't exist, KC_ERROR on failure
 */
int keycloak_create_subgroup(struct kc_realm realm, struct kc_client client,
                             const char* parent_id, const char* group_name,
                             char** group_id_out);

/**
 * Sets a custom attribute on a Keycloak group
 * @param realm        Keycloak realm configuration
 * @param client       Client with admin access token
 * @param group_id     Group's Keycloak ID (UUID)
 * @param attr_name    Attribute name (e.g., "x3_access_level")
 * @param attr_value   Attribute value as string
 * @return KC_SUCCESS on success, KC_NOT_FOUND if group doesn't exist, KC_ERROR on failure
 */
int keycloak_set_group_attribute(struct kc_realm realm, struct kc_client client,
                                 const char* group_id, const char* attr_name,
                                 const char* attr_value);

/**
 * Deletes a Keycloak group
 * @param realm     Keycloak realm configuration
 * @param client    Client with admin access token
 * @param group_id  Group's Keycloak ID (UUID)
 * @return KC_SUCCESS on success, KC_NOT_FOUND if group doesn't exist, KC_ERROR on failure
 */
int keycloak_delete_group(struct kc_realm realm, struct kc_client client,
                          const char* group_id);

/**
 * Creates a group hierarchy for a channel with a specific access level
 * Convenience function that creates /irc-channels/#channelname and sets x3_access_level
 * @param realm          Keycloak realm configuration
 * @param client         Client with admin access token
 * @param channel_name   IRC channel name (e.g., "#help")
 * @param access_level   Access level to set (1-500)
 * @param group_id_out   Output pointer for created channel group's ID (caller must free, can be NULL)
 * @return KC_SUCCESS on success, KC_ERROR on failure
 */
int keycloak_create_channel_group(struct kc_realm realm, struct kc_client client,
                                  const char* channel_name, unsigned short access_level,
                                  char** group_id_out);

/**
 * Ensures the parent "irc-channels" group exists, creating it if needed
 * @param realm          Keycloak realm configuration
 * @param client         Client with admin access token
 * @param group_id_out   Output pointer for parent group's ID (caller must free)
 * @return KC_SUCCESS on success, KC_ERROR on failure
 */
int keycloak_ensure_channels_parent(struct kc_realm realm, struct kc_client client,
                                    char** group_id_out);

/**
 * Initialize keycloak module (creates persistent CURL handle for connection reuse)
 */
void init_keycloak(void);

/**
 * Cleanup keycloak module (frees persistent CURL handle)
 */
void cleanup_keycloak(void);

/**
 * Async authentication callback type
 * @param session  Opaque session pointer passed to kc_check_auth_async
 * @param result   KC_SUCCESS, KC_FORBIDDEN, or KC_ERROR
 */
typedef void (*kc_async_callback)(void *session, int result);

/**
 * Async fingerprint lookup callback type
 * @param session   Opaque session pointer
 * @param result    KC_SUCCESS, KC_NOT_FOUND, KC_COLLISION, or KC_ERROR
 * @param username  Username found (only valid if result==KC_SUCCESS, caller must free)
 */
typedef void (*kc_fingerprint_callback)(void *session, int result, char *username);

/**
 * Async token introspection callback type
 * @param session    Opaque session pointer
 * @param result     KC_SUCCESS or KC_ERROR
 * @param token_info Token info (only valid if result==KC_SUCCESS, caller must free)
 */
typedef void (*kc_introspect_callback)(void *session, int result, struct kc_token_info *token_info);

/**
 * Start async authentication check against Keycloak
 * This function returns immediately and invokes the callback when complete.
 * Uses curl_multi integrated with X3's ioset event loop.
 *
 * @param realm     Keycloak realm configuration
 * @param client    Client credentials (client_id, client_secret)
 * @param handle    Username to authenticate
 * @param password  Password to verify
 * @param session   Opaque session pointer (passed to callback)
 * @param callback  Function to call when auth completes
 * @return 0 on success (request started), -1 on error
 */
int kc_check_auth_async(struct kc_realm realm, struct kc_client client,
                        const char *handle, const char *password,
                        void *session, kc_async_callback callback);

/**
 * Start async fingerprint lookup against Keycloak
 * This function returns immediately and invokes the callback when complete.
 *
 * @param realm       Keycloak realm configuration
 * @param client      Client with admin access token
 * @param fingerprint Certificate fingerprint to search for
 * @param session     Opaque session pointer (passed to callback)
 * @param callback    Function to call when lookup completes
 * @return 0 on success (request started), -1 on error
 */
int keycloak_find_user_by_fingerprint_async(struct kc_realm realm, struct kc_client client,
                                             const char *fingerprint, void *session,
                                             kc_fingerprint_callback callback);

/**
 * Start async token introspection against Keycloak
 * This function returns immediately and invokes the callback when complete.
 *
 * @param realm    Keycloak realm configuration
 * @param client   Client credentials
 * @param token    Bearer token to introspect
 * @param session  Opaque session pointer (passed to callback)
 * @param callback Function to call when introspection completes
 * @return 0 on success (request started), -1 on error
 */
int keycloak_introspect_token_async(struct kc_realm realm, struct kc_client client,
                                     const char *token, void *session,
                                     kc_introspect_callback callback);

/**
 * Set a user attribute asynchronously.
 * Uses generic kc_async_callback for success/failure notification.
 *
 * @param realm      Keycloak realm info
 * @param client     Client with valid access_token
 * @param user_id    Keycloak user UUID
 * @param attr_name  Attribute name to set
 * @param attr_value Attribute value (NULL to clear)
 * @param session    Opaque session pointer (passed to callback)
 * @param callback   Function to call when operation completes
 * @return 0 on success (request started), -1 on error
 */
int keycloak_set_user_attribute_async(struct kc_realm realm, struct kc_client client,
                                       const char *user_id, const char *attr_name,
                                       const char *attr_value, void *session,
                                       kc_async_callback callback);

/**
 * Add a user to a group asynchronously.
 * Useful for non-blocking channel access sync.
 *
 * @param realm    Keycloak realm info
 * @param client   Client with valid access_token
 * @param user_id  Keycloak user UUID
 * @param group_id Keycloak group UUID
 * @param session  Opaque session pointer (passed to callback)
 * @param callback Function to call when operation completes
 * @return 0 on success (request started), -1 on error
 */
int keycloak_add_user_to_group_async(struct kc_realm realm, struct kc_client client,
                                      const char *user_id, const char *group_id,
                                      void *session, kc_async_callback callback);

/**
 * Remove a user from a group asynchronously.
 * Useful for non-blocking channel access sync.
 *
 * @param realm    Keycloak realm info
 * @param client   Client with valid access_token
 * @param user_id  Keycloak user UUID
 * @param group_id Keycloak group UUID
 * @param session  Opaque session pointer (passed to callback)
 * @param callback Function to call when operation completes
 * @return 0 on success (request started), -1 on error
 */
int keycloak_remove_user_from_group_async(struct kc_realm realm, struct kc_client client,
                                           const char *user_id, const char *group_id,
                                           void *session, kc_async_callback callback);

/**
 * WebPush callback type.
 * @param session   Opaque session pointer
 * @param result    KC_SUCCESS, KC_FORBIDDEN (expired), or KC_ERROR
 * @param http_code Raw HTTP response code for detailed handling
 */
typedef void (*kc_webpush_callback)(void *session, int result, long http_code);

/**
 * Send a WebPush notification asynchronously.
 * Uses the async curl_multi infrastructure for non-blocking HTTP.
 *
 * @param endpoint      Push service endpoint URL
 * @param headers       Array of header strings (e.g., "Content-Type: application/octet-stream")
 * @param header_count  Number of headers (max 10)
 * @param body          Binary body data (encrypted payload)
 * @param body_len      Length of body data
 * @param session       Opaque session pointer (passed to callback)
 * @param callback      Function to call when request completes
 * @return 0 on success (request started), -1 on error
 */
int kc_webpush_send_async(const char *endpoint,
                          const char **headers, size_t header_count,
                          const void *body, size_t body_len,
                          void *session,
                          kc_webpush_callback callback);

#endif /* WITH_KEYCLOAK */

#endif /* KEYCLOAK_H */
