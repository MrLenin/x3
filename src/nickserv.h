/* nickserv.h - Nick/authentiction service
 * Copyright 2000-2004 srvx Development Team
 *
 * This file is part of x3.
 *
 * x3 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with srvx; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#ifndef _nickserv_h
#define _nickserv_h

#include "hash.h"   /* for NICKLEN, etc., and common.h */
#include "dict.h"
#include <tre/regex.h> /* for regex in nickserv_config */
struct svccmd;
struct kc_metadata_entry;

#define NICKSERV_HANDLE_LEN ACCOUNTLEN
#define COOKIELEN 10

/* HI_FLAG_* go into handle_info.flags */
#define HI_FLAG_OPER_SUSPENDED 0x00000001
#define HI_FLAG_USE_PRIVMSG    0x00000002
#define HI_FLAG_SUPPORT_HELPER 0x00000004
#define HI_FLAG_HELPING        0x00000008
#define HI_FLAG_SUSPENDED      0x00000010
#define HI_FLAG_MIRC_COLOR     0x00000020
#define HI_FLAG_FROZEN         0x00000040
#define HI_FLAG_NODELETE       0x00000080
#define HI_FLAG_NETWORK_HELPER 0x00000100
#define HI_FLAG_BOT            0x00000200
#define HI_FLAG_AUTOHIDE       0x00000400
#define HI_FLAG_IMPERSONATE    0x00000800
#define HI_FLAG_ADVANCED       0x00001000
/* Flag characters for the above.  First char is LSB, etc. */
#define HANDLE_FLAGS "SphgscfnHbxI"

/* HI_STYLE_* go into handle_info.userlist_style */
#define HI_STYLE_NORMAL	       'n'
#define HI_STYLE_CLEAN	       'c'
#define HI_STYLE_ADVANCED      'a'
#define HI_STYLE_CLASSIC       'k'

#define HI_DEFAULT_FLAGS       (HI_FLAG_MIRC_COLOR)

/* This is overridden by conf file */
#define HI_DEFAULT_STYLE       HI_STYLE_NORMAL

#define HANDLE_FLAGGED(hi, tok) ((hi)->flags & HI_FLAG_##tok)
#define HANDLE_SET_FLAG(hi, tok) ((hi)->flags |= HI_FLAG_##tok)
#define HANDLE_TOGGLE_FLAG(hi, tok) ((hi)->flags ^= HI_FLAG_##tok)
#define HANDLE_CLEAR_FLAG(hi, tok) ((hi)->flags &= ~HI_FLAG_##tok)

#define IsSupportHelper(user) (user->handle_info && HANDLE_FLAGGED(user->handle_info, SUPPORT_HELPER))
#define IsNetworkHelper(user) (user->handle_info && HANDLE_FLAGGED(user->handle_info, NETWORK_HELPER))
#define IsHelper(user) (IsSupportHelper(user) || IsNetworkHelper(user))
#define IsHelping(user) (user->handle_info && HANDLE_FLAGGED(user->handle_info, HELPING))
#define IsStaff(user) (IsOper(user) || IsSupportHelper(user) || IsNetworkHelper(user))
#define IsBot(user) (user->handle_info && HANDLE_FLAGGED(user->handle_info, BOT))

enum cookie_type {
    ACTIVATION,
    PASSWORD_CHANGE,
    EMAIL_CHANGE,
    ALLOWAUTH
};

struct handle_cookie {
    struct handle_info *hi;
    char *data;
    enum cookie_type type;
    time_t expires;
    char cookie[COOKIELEN+1];
};

struct handle_note {
    char            setter[NICKSERV_HANDLE_LEN+1];
    time_t          date;
    char            note[1];
};

struct handle_info {
    struct nick_info *nicks;
    struct string_list *masks;
    struct string_list *sslfps;
    struct string_list *ignores;
    struct userNode *users;
    struct userData *channels;
    struct handle_cookie *cookie;
    struct handle_note *note;
    struct language *language;
    char *email_addr;
    char *epithet;
    char *infoline;
    char *handle;
    char *fakehost;
    time_t registered;
    time_t lastseen;
    time_t last_present;  /* last time any connection was present (not away) */
    int karma;
    unsigned short flags;
    unsigned short opserv_level;
    unsigned short screen_width;
    unsigned short table_width;
    unsigned char userlist_style;
    unsigned char announcements;
    unsigned char maxlogins;
    char passwd[PASSWD_LEN];
    char last_quit_host[USERLEN+HOSTLEN+2];
    char *ecdsa_pubkey;  /* ECDSA-NIST256P-CHALLENGE public key (base64 encoded) */
};

struct nick_info {
    struct handle_info *owner;
    struct nick_info *next; /* next nick owned by same handle */
    char nick[NICKLEN+1];
    time_t registered;
    time_t lastseen;
};

struct handle_info_list {
    unsigned int used, size;
    struct handle_info **list;
    char *tag; /* e.g. email address */
};

/* Prototypes for DEFINE_LIST(handle_info_list, ...) generated functions */
void handle_info_list_init(struct handle_info_list *list);
void handle_info_list_append(struct handle_info_list *list, struct handle_info *new_item);
int handle_info_list_remove(struct handle_info_list *list, struct handle_info *new_item);
void handle_info_list_clean(struct handle_info_list *list);

extern const char *handle_flags;

enum reclaim_action {
    RECLAIM_NONE,
    RECLAIM_WARN,
    RECLAIM_SVSNICK,
    RECLAIM_KILL
};

struct nickserv_config {
    unsigned int disable_nicks : 1;
    unsigned int valid_handle_regex_set : 1;
    unsigned int valid_nick_regex_set : 1;
    unsigned int valid_fakehost_regex_set : 1;
    unsigned int autogag_enabled : 1;
    unsigned int email_enabled : 1;
    unsigned int email_required : 1;
    unsigned int default_hostmask : 1;
    unsigned int warn_nick_owned : 1;
    unsigned int warn_clone_auth : 1;
    unsigned int sync_log : 1;
    unsigned int expire_nicks : 1;
    unsigned long nicks_per_handle;
    unsigned long password_min_length;
    unsigned long password_min_digits;
    unsigned long password_min_upper;
    unsigned long password_min_lower;
    unsigned long db_backup_frequency;
    unsigned long handle_expire_frequency;
    unsigned long autogag_duration;
    unsigned long email_visible_level;
    unsigned long cookie_timeout;
    unsigned long handle_expire_delay;
    unsigned long nochan_handle_expire_delay;
    unsigned long modoper_level;
    unsigned long set_epithet_level;
    unsigned long set_title_level;
    unsigned long set_fakehost_level;
    unsigned long handles_per_email;
    unsigned long email_search_level;
    unsigned long nick_expire_frequency;
    unsigned long nick_expire_delay;
    const char *network_name;
    const char *titlehost_suffix;
    regex_t valid_handle_regex;
    regex_t valid_nick_regex;
    regex_t valid_fakehost_regex;
    dict_t weak_password_dict;
    struct policer_params *auth_policer_params;
    enum reclaim_action reclaim_action;
    enum reclaim_action auto_reclaim_action;
    unsigned long auto_reclaim_delay;
    unsigned char default_maxlogins;
    unsigned char hard_maxlogins;
    unsigned long ounregister_inactive;
    unsigned long ounregister_flags;
    const char *auto_oper;
    const char *auto_admin;
    const char *auto_oper_privs;
    const char *auto_admin_privs;
    char default_style;
    struct string_list *denied_fakehost_words;
    unsigned int force_handles_lowercase;
    unsigned int ldap_enable;
#ifdef WITH_LDAP
    const char *ldap_uri;
    const char *ldap_base;
    const char *ldap_dn_fmt;
    unsigned int ldap_version;
    unsigned int ldap_autocreate;

    const char *ldap_admin_dn;
    const char *ldap_admin_pass;
    const char *ldap_field_account;
    const char *ldap_field_password;
    const char *ldap_field_email;
    const char *ldap_field_oslevel;
    struct string_list *ldap_object_classes;
    const char *ldap_oper_group_dn;
    unsigned int ldap_oper_group_level;
    const char *ldap_field_group_member;
    unsigned int ldap_timeout;
#endif
    unsigned int keycloak_enable;
#ifdef WITH_KEYCLOAK
    const char *keycloak_uri;               // Keycloak server URL
    const char *keycloak_realm;             // Realm name
    const char *keycloak_client_id;         // Service account client ID
    const char *keycloak_client_secret;     // Service account client secret
    unsigned int keycloak_autocreate;       // Auto-create local accounts from Keycloak
    const char *keycloak_oper_group;        // Group name for opers (optional)
    unsigned int keycloak_oper_group_level; // Min level to add to oper group
    const char *keycloak_attr_oslevel;      // Attribute name for opserv_level
    unsigned int keycloak_email_policy;     // 0=trust KC, 1=always X3 cookie, 2=check emailVerified
    unsigned int keycloak_webhook_port;     // Port for Keycloak webhook listener (0=disabled)
    const char *keycloak_webhook_secret;    // Shared secret for webhook authentication
    const char *keycloak_webhook_bind;      // Bind address for webhook (NULL = all interfaces)
#endif
    /* Password hashing configuration */
    const char *password_algorithm;         // "pbkdf2-sha256", "pbkdf2-sha512", "bcrypt"
    unsigned long password_pbkdf2_iterations; // PBKDF2 iterations (default: 10000)
    unsigned int password_bcrypt_cost;      // bcrypt cost factor (default: 12)
    unsigned int password_lazy_migration;   // Rehash legacy passwords on login (default: 1)
    unsigned int scram_iterations;          // SCRAM-SHA-256 iterations (default: 4096, RFC min)
    unsigned int lmdb_nosync;               // LMDB nosync mode (default: 0, trades durability for speed)
    unsigned int lmdb_sync_interval;        // LMDB sync interval in seconds when nosync enabled (default: 10)
    /* Certificate auto-registration */
    unsigned int cert_autoregister;         // Auto-register certs on SASL PLAIN auth (default: 0)
};

void init_nickserv(const char *nick);
struct handle_info *get_handle_info(const char *handle);
struct handle_info *smart_get_handle_info(struct userNode *service, struct userNode *user, const char *name);
int oper_try_set_access(struct userNode *user, struct userNode *bot, struct handle_info *target, unsigned int new_level);
int oper_outranks(struct userNode *user, struct handle_info *hi);
struct nick_info *get_nick_info(const char *nick);
struct modeNode *find_handle_in_channel(struct chanNode *channel, struct handle_info *handle, struct userNode *except);
int nickserv_modify_handle_flags(struct userNode *user, struct userNode *bot, const char *str, unsigned long *add, unsigned long *remove);
int oper_has_access(struct userNode *user, struct userNode *bot, unsigned int min_level, unsigned int quiet);
void nickserv_show_oper_accounts(struct userNode *user, struct svccmd *cmd);

void nickserv_do_autoauth(struct userNode *user);

/* Get the SASL mechanism list based on current configuration */
const char *nickserv_get_sasl_mechanisms(void);
/* Check if mechanism list has changed and broadcast update to IRCd */
void nickserv_update_sasl_mechanisms(void);
/* Clear cached SASL mechanism list (call on uplink disconnect to force re-broadcast) */
void nickserv_clear_sasl_cache(void);

struct handle_info *get_victim_oper(struct userNode *user, const char *target);
struct handle_info *loc_auth(char *sslfp, char *handle, char *password, char *userhost);

typedef void (*user_mode_func_t)(struct userNode *user, const char *mode_change, void *extra);
void reg_user_mode_func(user_mode_func_t func, void *extra);
typedef void (*channel_mode_func_t)(struct userNode *who, struct chanNode *channel, char **mode, unsigned int argc, void *extra);
void reg_channel_mode_func(channel_mode_func_t func, void *extra);

/* auth_funcs are called when a user gets a new handle_info.  They are
 * called *after* user->handle_info has been updated.  */
typedef void (*auth_func_t)(struct userNode *user, struct handle_info *old_handle, void *extra);
void reg_auth_func(auth_func_t func, void *extra);

/* Called just after a handle is renamed. */
typedef void (*handle_rename_func_t)(struct handle_info *handle, const char *old_handle, void *extra);
void reg_handle_rename_func(handle_rename_func_t func, void *extra);

/* unreg_funcs are called right before a handle is unregistered.
 * `user' is the person who caused the handle to be unregistered (either a
 * client authed to the handle, or an oper). */
typedef void (*unreg_func_t)(struct userNode *user, struct handle_info *handle, void *extra);
void reg_unreg_func(unreg_func_t func, void *extra);

/* Called just before a handle is merged */
typedef void (*handle_merge_func_t)(struct userNode *user, struct handle_info *handle_to, struct handle_info *handle_from, void *extra);
void reg_handle_merge_func(handle_merge_func_t, void *extra);

/* Called after an allowauth. handle is null if allowauth authorization was
 * removed */
typedef void (*allowauth_func_t)(struct userNode *user, struct userNode *target, struct handle_info *handle, void *extra);
void reg_allowauth_func(allowauth_func_t func, void *extra);

/* Called when an auth attempt fails because of a bad password */
typedef void (*failpw_func_t)(struct userNode *user, struct handle_info *handle, void *extra);
void reg_failpw_func(failpw_func_t func, void *extra);

void send_func_list(struct userNode *user);

extern dict_t nickserv_handle_dict;

/* IRCv3 account-registration support (REGISTER/VERIFY commands via RG/VF P10 tokens) */

/* Result codes for nickserv_ircv3_register */
enum nickserv_register_result {
    NSREG_SUCCESS,              /* Account created and authenticated */
    NSREG_VERIFY_REQUIRED,      /* Verification email sent */
    NSREG_ACCOUNT_EXISTS,       /* Account name already taken */
    NSREG_WEAK_PASSWORD,        /* Password doesn't meet requirements */
    NSREG_INVALID_EMAIL,        /* Invalid email address format */
    NSREG_EMAIL_PROHIBITED,     /* Email address on blacklist */
    NSREG_EMAIL_LIMIT,          /* Too many accounts with this email */
    NSREG_INVALID_HANDLE,       /* Invalid account name */
    NSREG_ALREADY_AUTHED,       /* User already authenticated */
    NSREG_INTERNAL_ERROR        /* Internal error */
};

/* Result codes for nickserv_ircv3_verify */
enum nickserv_verify_result {
    NSVERIFY_SUCCESS,           /* Verification successful, user authenticated */
    NSVERIFY_NO_ACCOUNT,        /* Account not found */
    NSVERIFY_NO_COOKIE,         /* No pending verification */
    NSVERIFY_BAD_CODE,          /* Invalid verification code */
    NSVERIFY_SUSPENDED,         /* Account is suspended */
    NSVERIFY_INTERNAL_ERROR     /* Internal error */
};

/**
 * Register a new account via IRCv3 REGISTER command.
 * @param user The user requesting registration
 * @param handle Account name to register ("*" means use current nick)
 * @param email Email address ("*" means no email)
 * @param password Plaintext password
 * @param result_msg Buffer to receive human-readable result message (at least 256 bytes)
 * @return Result code indicating success or failure reason
 */
enum nickserv_register_result nickserv_ircv3_register(struct userNode *user,
    const char *handle, const char *email, const char *password, char *result_msg);

/**
 * Process a registration request from P10 RG command (draft/account-registration).
 * This handles the async Keycloak flow and sends replies via irc_regreply.
 * @param uid      The server!fd.cookie identifier for the pre-registration client
 * @param handle   Account name to register
 * @param email    Email address (or "*" if not provided)
 * @param password Plaintext password
 * @return 0 if processing started (async or sync), -1 on immediate error
 */
int nickserv_ircv3_register_p10(const char *uid, const char *handle,
    const char *email, const char *password);

/**
 * Verify a pending account via IRCv3 VERIFY command.
 * @param user The user requesting verification
 * @param handle Account name to verify
 * @param code Verification code
 * @param result_msg Buffer to receive human-readable result message (at least 256 bytes)
 * @return Result code indicating success or failure reason
 */
enum nickserv_verify_result nickserv_ircv3_verify(struct userNode *user,
    const char *handle, const char *code, char *result_msg);

/* IRCv3 metadata-2 support */

/** Metadata visibility levels */
#define METADATA_VIS_PUBLIC  0  /* Anyone can see */
#define METADATA_VIS_PRIVATE 1  /* Only owner can see */
#define METADATA_VIS_ERROR   2  /* Error response (no such target) */

/** Maximum length of a metadata key */
#define METADATA_KEY_LEN 64

/** Maximum length of a metadata value (increased for compression support) */
#define METADATA_VALUE_LEN 4096

/* Push profile metadata to Nefarious on auth */
void nickserv_sync_profile_metadata_to_ircd(struct userNode *user);

/* Presence aggregation support */

/** Presence states for aggregation */
enum presence_state {
    PRESENCE_PRESENT = 0,    /* Not away */
    PRESENCE_AWAY = 1,       /* Away with message */
    PRESENCE_AWAY_STAR = 2   /* Hidden connection (AWAY *) */
};

/**
 * Compute the effective presence for an account.
 * Uses "most-present-wins" logic:
 * - PRESENT beats everything
 * - AWAY beats AWAY_STAR
 * - AWAY_STAR only if all connections are AWAY_STAR
 * @param hi The handle_info to check
 * @return Effective presence state
 */
enum presence_state handle_get_presence(struct handle_info *hi);

/**
 * Check if any connection for an account is present (not away).
 * @param hi The handle_info to check
 * @return 1 if at least one connection is present, 0 otherwise
 */
int handle_is_present(struct handle_info *hi);

/**
 * Update last_present timestamp for an account.
 * Called when a connection becomes present.
 * @param hi The handle_info to update
 */
void handle_update_last_present(struct handle_info *hi);

/* Positive auth cache support (for Keycloak webhook invalidation) */
#ifdef WITH_MDBX
/**
 * Invalidate positive auth cache for a user.
 * Called by keycloak_webhook when password changes.
 * @param username The username to invalidate
 */
void invalidate_authsuccess_cache(const char *username);
#else
#define invalidate_authsuccess_cache(u) do {} while(0)
#endif

#endif
