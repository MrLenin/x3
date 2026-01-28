/* kc_sync.h - Synchronous Keycloak API functions
 *
 * These are blocking HTTP calls used during startup/shutdown when the
 * event loop isn't running, or from contexts that can tolerate blocking.
 *
 * NOTE: This header is included by keycloak.h after all struct definitions.
 * Do NOT include keycloak.h from here (circular dependency).
 */

#ifndef KC_SYNC_H
#define KC_SYNC_H

#include <stdbool.h>
#include <stddef.h>

/* Forward declarations - full definitions are in keycloak.h */
struct kc_realm;
struct kc_client;
struct kc_user;
struct kc_metadata_entry;
struct kc_group_member;
struct kc_group_info;
struct log_type;

/* Initialize sync module with log handle */
void kc_sync_init(struct log_type *log);

/* User lookup */
int keycloak_get_users(struct kc_realm realm, struct kc_client client,
                       const char* user, const char* filter, bool exact,
                       struct kc_user** user_out);
int keycloak_get_user(struct kc_realm realm, struct kc_client client,
                      const char *user, struct kc_user *kc_user_out);
void keycloak_free_users(struct kc_user* users, size_t count);

/* User attributes */
int keycloak_list_user_attributes(struct kc_realm realm, struct kc_client client,
                                  const char* user_id, const char* prefix,
                                  struct kc_metadata_entry** entries_out);
void keycloak_free_metadata_entries(struct kc_metadata_entry* entries);

/* Fingerprint lookup */
int keycloak_find_user_by_fingerprint(struct kc_realm realm, struct kc_client client,
                                       const char* fingerprint, char** username_out);

/* Group operations */
int keycloak_get_group_by_name(struct kc_realm realm, struct kc_client client,
                               const char* group_name, char** group_id_out);
int keycloak_create_group(struct kc_realm realm, struct kc_client client,
                          const char* group_name, char** group_id_out);
int keycloak_ensure_channels_parent(struct kc_realm realm, struct kc_client client,
                                    char** group_id_out);

/* Group memory management */
void keycloak_free_group_members(struct kc_group_member* members);
void keycloak_free_group_info(struct kc_group_info* info);

#endif /* KC_SYNC_H */
