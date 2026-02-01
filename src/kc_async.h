/* kc_async.h - Async Keycloak API declarations
 *
 * All asynchronous Keycloak operations (non-blocking HTTP via libkc bridge).
 * Extracted from keycloak.h during Phase 7 modularization.
 *
 * These functions return immediately and invoke a callback when the HTTP
 * request completes. They use the x3_kc_bridge for non-blocking I/O.
 */

#ifndef KC_ASYNC_H
#define KC_ASYNC_H

#include "config.h"

#ifdef WITH_KEYCLOAK

#include "keycloak.h"  /* For struct types: kc_realm, kc_client, kc_user, etc. */

/*
 * =============================================================================
 * Async Callback Typedefs
 * =============================================================================
 */

/**
 * Async authentication callback type
 * @param session  Opaque session pointer passed to kc_check_auth_async
 * @param result   KC_SUCCESS, KC_FORBIDDEN, or KC_ERROR
 * @return 0 if session may continue processing, 1 if session is terminal
 */
typedef int (*kc_async_callback)(void *session, int result);

/**
 * Generic async callback for operations returning a string value.
 * Used for fingerprint lookups (returns username), group path lookups (returns group_id),
 * subgroup creation (returns group_id), and attribute retrieval (returns value).
 *
 * @param session  Opaque session pointer
 * @param result   Operation result code (KC_SUCCESS, KC_NOT_FOUND, KC_ERROR, etc.)
 * @param value    String result (only valid if result==KC_SUCCESS, caller must free)
 * @return 0 if session may continue processing, 1 if session is terminal
 */
typedef int (*kc_string_callback)(void *session, int result, char *value);

/**
 * Async token introspection callback type
 * @param session    Opaque session pointer
 * @param result     KC_SUCCESS or KC_ERROR
 * @param token_info Token info (only valid if result==KC_SUCCESS, caller must free)
 * @return 0 if session may continue processing, 1 if session is terminal
 */
typedef int (*kc_introspect_callback)(void *session, int result, struct kc_token_info *token_info);

/* kc_client_token_callback is defined in kc_token.h (included via keycloak.h) */

/**
 * Async get user callback type (Phase 3)
 * @param session  Opaque session pointer
 * @param result   KC_SUCCESS, KC_NOT_FOUND, or KC_ERROR
 * @param user     User data (only valid if result==KC_SUCCESS, caller must free with keycloak_user_free_fields)
 * @return 0 if session may continue processing, 1 if session is terminal
 */
typedef int (*kc_get_user_callback)(void *session, int result, struct kc_user *user);

/**
 * Async list user attributes callback type (Phase 5.10)
 * @param session  Opaque session pointer
 * @param result   KC_SUCCESS, KC_NOT_FOUND, or KC_ERROR
 * @param entries  Linked list of metadata entries (only valid if result==KC_SUCCESS, caller must free)
 * @return 0 if session may continue processing, 1 if session is terminal
 */
typedef int (*kc_list_attrs_callback)(void *session, int result, struct kc_metadata_entry *entries);

/**
 * Callback type for async group info lookup.
 * @param session       Opaque session pointer
 * @param result        KC_SUCCESS, KC_NOT_FOUND, or KC_ERROR
 * @param info          Group info (only valid if result==KC_SUCCESS, caller must free)
 * @return 0 if session may continue processing, 1 if session is terminal
 */
typedef int (*kc_group_info_callback)(void *session, int result,
                                       struct kc_group_info *info);

/**
 * Callback type for async group members lookup.
 * @param session       Opaque session pointer
 * @param result        Number of members (>=0), KC_NOT_FOUND, or KC_ERROR
 * @param members       Linked list of members (only valid if result>=0, caller must free)
 * @return 0 if session may continue processing, 1 if session is terminal
 */
typedef int (*kc_group_members_callback)(void *session, int result,
                                          struct kc_group_member *members);

/*
 * =============================================================================
 * Async API Functions
 * =============================================================================
 */

int kc_check_auth_async(struct kc_realm realm, struct kc_client client,
                        const char *handle, const char *password,
                        void *session, kc_async_callback callback);

int keycloak_get_client_token_async(struct kc_realm realm, struct kc_client client,
                                     void *session, kc_client_token_callback callback);

int keycloak_find_user_by_fingerprint_async(struct kc_realm realm, struct kc_client client,
                                             const char *fingerprint, void *session,
                                             kc_string_callback callback);

int keycloak_introspect_token_async(struct kc_realm realm, struct kc_client client,
                                     const char *token, void *session,
                                     kc_introspect_callback callback);

int keycloak_set_user_attribute_async(struct kc_realm realm, struct kc_client client,
                                       const char *user_id, const char *attr_name,
                                       const char *attr_value, void *session,
                                       kc_async_callback callback);

int keycloak_set_user_attribute_array_async(struct kc_realm realm, struct kc_client client,
                                             const char *user_id, const char *attr_name,
                                             const char **values, size_t value_count,
                                             void *session, kc_async_callback callback);

int keycloak_set_email_verified_async(struct kc_realm realm, struct kc_client client,
                                       const char *user_id, int verified,
                                       void *session, kc_async_callback callback);

int keycloak_add_user_to_group_async(struct kc_realm realm, struct kc_client client,
                                      const char *user_id, const char *group_id,
                                      void *session, kc_async_callback callback);

int keycloak_remove_user_from_group_async(struct kc_realm realm, struct kc_client client,
                                           const char *user_id, const char *group_id,
                                           void *session, kc_async_callback callback);

int keycloak_create_user_async(struct kc_realm realm, struct kc_client client,
                               const char *username, const char *email,
                               const char *password, void *session,
                               kc_async_callback callback);

int keycloak_create_user_with_hash_async(struct kc_realm realm, struct kc_client client,
                                          const char *username, const char *email,
                                          const char *cred_data, const char *secret_data,
                                          void *session, kc_async_callback callback);

int keycloak_get_group_info_async(struct kc_realm realm, struct kc_client client,
                                   const char *group_id, void *session,
                                   kc_group_info_callback callback);

int keycloak_get_group_members_async(struct kc_realm realm, struct kc_client client,
                                      const char *group_id, void *session,
                                      kc_group_members_callback callback);

int keycloak_get_user_async(struct kc_realm realm, struct kc_client client,
                             const char *username, void *session,
                             kc_get_user_callback callback);

int keycloak_update_user_representation_async(struct kc_realm realm, struct kc_client client,
                                               const char *user_id,
                                               const struct kc_user_update *update,
                                               void *session,
                                               kc_async_callback callback);

/* Coalesced update functions - batch multiple updates into one PUT */
int keycloak_coalesce_email(const char *user_id, const char *email,
                            void *session, kc_async_callback callback);
int keycloak_coalesce_credentials(const char *user_id,
                                  const char *cred_data, const char *secret_data,
                                  void *session, kc_async_callback callback);
int keycloak_coalesce_email_verified(const char *user_id, int verified);

int keycloak_get_group_by_path_async(struct kc_realm realm, struct kc_client client,
                                      const char *group_path, void *session,
                                      kc_string_callback callback);

int keycloak_get_group_by_name_async(struct kc_realm realm, struct kc_client client,
                                      const char *group_name, void *session,
                                      kc_string_callback callback);

int keycloak_delete_group_async(struct kc_realm realm, struct kc_client client,
                                 const char *group_id, void *session,
                                 kc_async_callback callback);

int keycloak_delete_user_async(struct kc_realm realm, struct kc_client client,
                                const char *user_id, void *session,
                                kc_async_callback callback);

int keycloak_list_user_attributes_async(struct kc_realm realm, struct kc_client client,
                                         const char *user_id, const char *prefix,
                                         void *session, kc_list_attrs_callback callback);

int keycloak_get_user_attribute_async(struct kc_realm realm, struct kc_client client,
                                       const char *user_id, const char *attr_name,
                                       void *session, kc_string_callback callback);

int keycloak_create_subgroup_async(struct kc_realm realm, struct kc_client client,
                                    const char *parent_id, const char *name,
                                    void *session, kc_string_callback callback);

int keycloak_set_group_attribute_async(struct kc_realm realm, struct kc_client client,
                                        const char *group_id, const char *attr_name,
                                        const char *attr_value, void *session,
                                        kc_async_callback callback);

/*
 * =============================================================================
 * Async Infrastructure (internal, called from init_keycloak/cleanup_keycloak)
 * =============================================================================
 */

void kc_async_init(void);
void kc_async_cleanup(void);

#endif /* WITH_KEYCLOAK */

#endif /* KC_ASYNC_H */
