/*
 * X3 - LMDB Wrapper Module
 * Copyright (C) 2024 AfterNET Development Team
 *
 * Provides LMDB-based persistent storage for X3 metadata and account data.
 * Used as a cache layer and fallback when Keycloak is unavailable.
 */
#ifndef X3_LMDB_H
#define X3_LMDB_H

#include "config.h"

/* Error codes - always defined so code compiles without LMDB */
enum lmdb_error {
    LMDB_SUCCESS = 0,
    LMDB_ERROR = -1,
    LMDB_NOT_FOUND = -2,
    LMDB_FULL = -3,
    LMDB_EXPIRED = -4   /* Entry found but expired (auto-deleted) */
};

#ifdef WITH_LMDB

#include <lmdb.h>
#include <stddef.h>

/* Database names */
#define LMDB_DB_ACCOUNTS    "accounts"
#define LMDB_DB_CHANNELS    "channels"
#define LMDB_DB_METADATA    "metadata"

/* Key prefixes */
#define LMDB_PREFIX_ACCOUNT  "acct:"
#define LMDB_PREFIX_CHANNEL  "chan:"
#define LMDB_PREFIX_META     "meta:"
#define LMDB_PREFIX_CHANACCESS "chanaccess:"
#define LMDB_PREFIX_FINGERPRINT "fp:"  /* Certificate fingerprint → username cache */
#define LMDB_PREFIX_CERTEXP "certexp:"  /* Certificate expiry: fingerprint → expiry timestamp */
#define LMDB_PREFIX_AUTHFAIL "authfail:"  /* Failed auth attempts cache (hash → timestamp) */
#define LMDB_PREFIX_FPFAIL "fpfail:"  /* Failed fingerprint lookups cache (fingerprint → timestamp) */
#define LMDB_PREFIX_SESSION "session:"  /* Session tokens: token_id → expiry:username */
#define LMDB_PREFIX_SESSVER "sessver:"  /* Session version: username → version_number */
#define LMDB_PREFIX_SCRAM_ACCT "scram_acct:"  /* Account SCRAM: hash_type:account → SCRAM verifier */

/* Core data prefixes (for SAXDB-optional mode) */
#define LMDB_PREFIX_HANDLE "handle:"      /* Account core: handle → JSON {passwd, email, flags, ...} */
#define LMDB_PREFIX_NICK "nick:"          /* Nick mapping: nick → handle */
#define LMDB_PREFIX_MASK "mask:"          /* Account mask: handle:index → mask_string */
#define LMDB_PREFIX_IGNORE "ignore:"      /* Account ignore: handle:index → ignore_mask */
#define LMDB_PREFIX_COOKIE "cookie:"      /* Auth cookie: handle → JSON {type, data, expires} */
#define LMDB_PREFIX_CHANREG "chanreg:"    /* Channel registration: #channel → JSON {...} */
#define LMDB_PREFIX_CHANUSER "chanuser:"  /* Channel user: #channel:handle → JSON {access, flags, ...} */
#define LMDB_PREFIX_CHANBAN "chanban:"    /* Channel ban: #channel:index → JSON {mask, reason, ...} */
#define LMDB_PREFIX_CHANNOTE "channote:"  /* Channel note: #channel:id → JSON {setter, text, ...} */
#define LMDB_PREFIX_GLINE "gline:"        /* G-line: mask → JSON {issuer, reason, expires, ...} */
#define LMDB_PREFIX_SHUN "shun:"          /* Shun: mask → JSON {issuer, reason, expires, ...} */
#define LMDB_PREFIX_TRUSTED "trusted:"    /* Trusted host: mask → JSON {issuer, limit, ...} */
#define LMDB_PREFIX_GAG "gag:"            /* Gag: mask → JSON {owner, reason, expires} */
#define LMDB_PREFIX_ALERT "alert:"        /* Alert: name → JSON {discrim, owner, reaction, ...} */
#define LMDB_PREFIX_GLOBAL "global:"      /* Global message: id → JSON {flags, posted, duration, from, message} */

/* Metadata entry for iteration */
struct lmdb_metadata_entry {
    char *key;
    char *value;
    struct lmdb_metadata_entry *next;
};

/* Account metadata entry */
struct lmdb_account_entry {
    char *account;
    char *key;
    char *value;
    int visibility;
    unsigned long timestamp;
};

/* Channel access entry for iteration */
struct lmdb_chanaccess_entry {
    char *channel;
    char *account;
    unsigned short access;
    struct lmdb_chanaccess_entry *next;
};

/* Raw metadata entry for compression passthrough */
struct lmdb_raw_metadata_entry {
    char *key;
    unsigned char *raw_value;
    size_t raw_len;
    int is_compressed;
    struct lmdb_raw_metadata_entry *next;
};

/* ========== Initialization ========== */

/**
 * Initialize the LMDB environment
 * @param dbpath Path to the database directory
 * @param mapsize Maximum database size in bytes (0 for default 100MB)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_init(const char *dbpath, size_t mapsize);

/**
 * Shutdown the LMDB environment and close all databases
 */
void x3_lmdb_shutdown(void);

/**
 * Check if LMDB is available
 * @return 1 if available, 0 if not
 */
int x3_lmdb_is_available(void);

/* ========== Account Metadata ========== */

/**
 * Get account metadata value
 * @param account Account name
 * @param key Metadata key
 * @param value Buffer for value (must be at least 1024 bytes)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_account_get(const char *account, const char *key, char *value);

/**
 * Set account metadata value
 * @param account Account name
 * @param key Metadata key
 * @param value Value to set (NULL to delete)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_account_set(const char *account, const char *key, const char *value);

/**
 * Delete account metadata value
 * @param account Account name
 * @param key Metadata key
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_account_delete(const char *account, const char *key);

/**
 * List all metadata for an account
 * @param account Account name
 * @param entries_out Output pointer for linked list (caller must free with x3_lmdb_free_entries)
 * @return Number of entries found, LMDB_ERROR on failure
 */
int x3_lmdb_account_list(const char *account, struct lmdb_metadata_entry **entries_out);

/**
 * Clear all metadata for an account
 * @param account Account name
 * @return Number of entries deleted, LMDB_ERROR on failure
 */
int x3_lmdb_account_clear(const char *account);

/**
 * Set account metadata value with explicit expiry
 * @param account Account name
 * @param key Metadata key
 * @param value Value to set (NULL to delete)
 * @param expires Expiry timestamp (0 = no expiry)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_account_set_ex(const char *account, const char *key,
                           const char *value, time_t expires);

/**
 * Get account metadata value with expiry info
 * @param account Account name
 * @param key Metadata key
 * @param value Buffer for value (must be at least 1024 bytes)
 * @param expires_out Output for expiry timestamp (can be NULL, 0 = no expiry)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_EXPIRED if expired
 */
int x3_lmdb_account_get_ex(const char *account, const char *key,
                           char *value, time_t *expires_out);

/**
 * Get account metadata value without decompressing (for compression passthrough)
 * @param account Account name
 * @param key Metadata key
 * @param raw_value Buffer for raw (possibly compressed) value
 * @param raw_len Output for actual data length
 * @param is_compressed Output flag: 1 if data is compressed, 0 if not
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_account_get_raw(const char *account, const char *key,
                            unsigned char *raw_value, size_t *raw_len,
                            int *is_compressed);

/**
 * Set account metadata value without compressing (for compression passthrough)
 * @param account Account name
 * @param key Metadata key
 * @param raw_value Raw (possibly compressed) value
 * @param raw_len Length of raw data
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_account_set_raw(const char *account, const char *key,
                            const unsigned char *raw_value, size_t raw_len);

/**
 * List all metadata for an account without decompressing (for compression passthrough)
 * @param account Account name
 * @param entries_out Output pointer for linked list (caller must free with x3_lmdb_free_raw_entries)
 * @return Number of entries found, LMDB_ERROR on failure
 */
int x3_lmdb_account_list_raw(const char *account, struct lmdb_raw_metadata_entry **entries_out);

/**
 * Free raw metadata entry list returned by list_raw functions
 * @param entries List to free
 */
void x3_lmdb_free_raw_entries(struct lmdb_raw_metadata_entry *entries);

/* ========== Channel Metadata ========== */

/**
 * Get channel metadata value
 * @param channel Channel name (with #)
 * @param key Metadata key
 * @param value Buffer for value (must be at least 1024 bytes)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_channel_get(const char *channel, const char *key, char *value);

/**
 * Set channel metadata value
 * @param channel Channel name (with #)
 * @param key Metadata key
 * @param value Value to set (NULL to delete)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_channel_set(const char *channel, const char *key, const char *value);

/**
 * Delete channel metadata value
 * @param channel Channel name (with #)
 * @param key Metadata key
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_channel_delete(const char *channel, const char *key);

/**
 * List all metadata for a channel
 * @param channel Channel name (with #)
 * @param entries_out Output pointer for linked list (caller must free with x3_lmdb_free_entries)
 * @return Number of entries found, LMDB_ERROR on failure
 */
int x3_lmdb_channel_list(const char *channel, struct lmdb_metadata_entry **entries_out);

/**
 * Clear all metadata for a channel
 * @param channel Channel name (with #)
 * @return Number of entries deleted, LMDB_ERROR on failure
 */
int x3_lmdb_channel_clear(const char *channel);

/**
 * Set channel metadata value with explicit expiry
 * @param channel Channel name (with #)
 * @param key Metadata key
 * @param value Value to set (NULL to delete)
 * @param expires Expiry timestamp (0 = no expiry)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_channel_set_ex(const char *channel, const char *key,
                           const char *value, time_t expires);

/**
 * Get channel metadata value with expiry info
 * @param channel Channel name (with #)
 * @param key Metadata key
 * @param value Buffer for value (must be at least 1024 bytes)
 * @param expires_out Output for expiry timestamp (can be NULL, 0 = no expiry)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_EXPIRED if expired
 */
int x3_lmdb_channel_get_ex(const char *channel, const char *key,
                           char *value, time_t *expires_out);

/**
 * Purge all expired metadata entries from accounts and channels
 * @return Number of entries deleted, LMDB_ERROR on failure
 */
int x3_lmdb_metadata_purge_expired(void);

/* ========== Channel Access (Keycloak Group Sync) ========== */

/**
 * Get channel access level for an account
 * @param channel Channel name (with #)
 * @param account Account name
 * @param access_out Output for access level
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_chanaccess_get(const char *channel, const char *account, unsigned short *access_out);

/**
 * Get channel access level for an account with timestamp
 * @param channel Channel name (with #)
 * @param account Account name
 * @param access_out Output for access level
 * @param timestamp_out Output for timestamp when entry was cached (can be NULL, 0 = legacy entry)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_chanaccess_get_ex(const char *channel, const char *account,
                               unsigned short *access_out, time_t *timestamp_out);

/**
 * Set channel access level for an account (uses current timestamp)
 * @param channel Channel name (with #)
 * @param account Account name
 * @param access Access level (0 to delete)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_chanaccess_set(const char *channel, const char *account, unsigned short access);

/**
 * Set channel access level for an account with explicit timestamp
 * @param channel Channel name (with #)
 * @param account Account name
 * @param access Access level (0 to delete)
 * @param timestamp Timestamp to store with entry
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_chanaccess_set_ex(const char *channel, const char *account,
                               unsigned short access, time_t timestamp);

/**
 * Delete channel access for an account
 * @param channel Channel name (with #)
 * @param account Account name
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_chanaccess_delete(const char *channel, const char *account);

/**
 * List all access entries for a channel
 * @param channel Channel name (with #)
 * @param entries_out Output pointer for linked list (caller must free)
 * @return Number of entries found, LMDB_ERROR on failure
 */
int x3_lmdb_chanaccess_list(const char *channel, struct lmdb_chanaccess_entry **entries_out);

/**
 * List all channel access entries for an account
 * @param account Account name
 * @param entries_out Output pointer for linked list (caller must free)
 * @return Number of entries found, LMDB_ERROR on failure
 */
int x3_lmdb_chanaccess_list_account(const char *account, struct lmdb_chanaccess_entry **entries_out);

/**
 * Clear all access entries for a channel
 * @param channel Channel name (with #)
 * @return Number of entries deleted, LMDB_ERROR on failure
 */
int x3_lmdb_chanaccess_clear(const char *channel);

/**
 * Free a linked list of channel access entries
 * @param entries Head of the list to free (can be NULL)
 */
void x3_lmdb_free_chanaccess_entries(struct lmdb_chanaccess_entry *entries);

/* ========== Activity Data (lastseen/last_present) ========== */

/* Key prefix for activity data */
#define LMDB_PREFIX_ACTIVITY "activity:"

/* Default TTL for activity data (30 days in seconds) */
#define LMDB_ACTIVITY_TTL_DAYS 30
#define LMDB_ACTIVITY_TTL_SECS (LMDB_ACTIVITY_TTL_DAYS * 86400)

/* ========== Fingerprint Data ========== */

/* Default TTL for fingerprint data (90 days in seconds) */
#define LMDB_FINGERPRINT_TTL_DAYS 90
#define LMDB_FINGERPRINT_TTL_SECS (LMDB_FINGERPRINT_TTL_DAYS * 86400)

/* Fingerprint entry structure */
struct lmdb_fingerprint_entry {
    char *fingerprint;
    char *account;
    time_t registered;
    time_t last_used;
    time_t expires;
    struct lmdb_fingerprint_entry *next;
};

/**
 * Get activity data for an account
 * @param account Account name
 * @param lastseen_out Output for lastseen timestamp (can be NULL)
 * @param last_present_out Output for last_present timestamp (can be NULL)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_EXPIRED if expired, LMDB_ERROR on failure
 */
int x3_lmdb_activity_get(const char *account, time_t *lastseen_out, time_t *last_present_out);

/**
 * Set activity data for an account (with automatic 30-day TTL)
 * @param account Account name
 * @param lastseen Lastseen timestamp (0 to preserve existing value)
 * @param last_present Last_present timestamp (0 to preserve existing value)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_activity_set(const char *account, time_t lastseen, time_t last_present);

/**
 * Refresh TTL on activity data without changing values
 * Called when account performs any action to keep data from expiring
 * @param account Account name
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if no entry exists, LMDB_ERROR on failure
 */
int x3_lmdb_activity_touch(const char *account);

/**
 * Delete activity data for an account
 * @param account Account name
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_activity_delete(const char *account);

/* ========== Fingerprint Storage ========== */

/**
 * Get fingerprint data by fingerprint
 * @param fingerprint SSL certificate fingerprint (with colons)
 * @param account_out Buffer for account name (must be at least 64 bytes, can be NULL)
 * @param registered_out Output for registration timestamp (can be NULL)
 * @param last_used_out Output for last-used timestamp (can be NULL)
 * @param expires_out Output for expiry timestamp (can be NULL)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_EXPIRED if expired, LMDB_ERROR on failure
 */
int x3_lmdb_fingerprint_get(const char *fingerprint, char *account_out,
                            time_t *registered_out, time_t *last_used_out,
                            time_t *expires_out);

/**
 * Set fingerprint data (with automatic 90-day TTL)
 * If fingerprint already exists, updates last_used and refreshes TTL
 * @param fingerprint SSL certificate fingerprint (with colons)
 * @param account Account name
 * @param registered Registration timestamp (0 to use current time for new entries)
 * @param last_used Last-used timestamp (0 to use current time)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_fingerprint_set(const char *fingerprint, const char *account,
                            time_t registered, time_t last_used);

/**
 * Refresh TTL on fingerprint and update last_used timestamp
 * Called when fingerprint is successfully used for SASL EXTERNAL auth
 * @param fingerprint SSL certificate fingerprint
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_fingerprint_touch(const char *fingerprint);

/**
 * Delete fingerprint data
 * @param fingerprint SSL certificate fingerprint
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_fingerprint_delete(const char *fingerprint);

/**
 * List all fingerprints for an account
 * @param account Account name
 * @param entries_out Output pointer for linked list (caller must free with x3_lmdb_free_fingerprint_entries)
 * @return Number of entries found, LMDB_ERROR on failure
 */
int x3_lmdb_fingerprint_list_account(const char *account, struct lmdb_fingerprint_entry **entries_out);

/**
 * Free a linked list of fingerprint entries
 * @param entries Head of the list to free (can be NULL)
 */
void x3_lmdb_free_fingerprint_entries(struct lmdb_fingerprint_entry *entries);

/* ========== Certificate Expiry ========== */

/**
 * Store certificate expiry timestamp for a fingerprint
 * @param fingerprint SSL certificate fingerprint
 * @param cert_expires Unix timestamp when certificate expires
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_certexp_set(const char *fingerprint, time_t cert_expires);

/**
 * Get certificate expiry timestamp for a fingerprint
 * @param fingerprint SSL certificate fingerprint
 * @param cert_expires_out Output for expiry timestamp
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_certexp_get(const char *fingerprint, time_t *cert_expires_out);

/**
 * Delete certificate expiry record for a fingerprint
 * @param fingerprint SSL certificate fingerprint
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_certexp_delete(const char *fingerprint);

/* ========== Generic Key-Value Operations ========== */

/**
 * Generic get operation
 * @param db Database name
 * @param key Full key (including any prefixes)
 * @param value Buffer for value
 * @param value_size Size of value buffer
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_get(const char *db, const char *key, char *value, size_t value_size);

/**
 * Generic set operation
 * @param db Database name
 * @param key Full key (including any prefixes)
 * @param value Value to set (NULL to delete)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_set(const char *db, const char *key, const char *value);

/**
 * Generic delete operation
 * @param db Database name
 * @param key Full key (including any prefixes)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_delete(const char *db, const char *key);

/* ========== Utility Functions ========== */

/**
 * Free a linked list of metadata entries
 * @param entries Head of the list to free (can be NULL)
 */
void x3_lmdb_free_entries(struct lmdb_metadata_entry *entries);

/**
 * Sync the database to disk
 * @param force Force synchronous flush
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_sync(int force);

/**
 * Get database statistics
 * @param db Database name (NULL for environment stats)
 * @param entries_out Number of entries in database
 * @param size_out Size of database in bytes
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_stats(const char *db, size_t *entries_out, size_t *size_out);

/* ========== Snapshot/Backup ========== */

/* Default snapshot interval (1 hour in seconds) */
#define LMDB_SNAPSHOT_INTERVAL_DEFAULT 3600

/* Default retention count (keep last 24 snapshots) */
#define LMDB_SNAPSHOT_RETENTION_DEFAULT 24

/* Snapshot statistics */
struct lmdb_snapshot_stats {
    time_t last_snapshot;
    time_t last_duration_ms;
    size_t last_size_bytes;
    unsigned int snapshots_retained;
    char last_path[256];
};

/**
 * Create a snapshot (hot backup) of the LMDB database
 * @param backup_path Path to backup directory (will be created if needed)
 * @param compact Use MDB_CP_COMPACT flag to remove free pages (slower but smaller)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_snapshot(const char *backup_path, int compact);

/**
 * Create a snapshot with automatic timestamped directory
 * Creates backup at: <base_path>/lmdb-YYYYMMDDHHMM/
 * @param base_path Base directory for snapshots
 * @param compact Use compaction
 * @param path_out Output buffer for actual path (must be at least 256 bytes, can be NULL)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_snapshot_auto(const char *base_path, int compact, char *path_out);

/**
 * Get last snapshot statistics
 * @return Pointer to static stats structure
 */
const struct lmdb_snapshot_stats *x3_lmdb_get_snapshot_stats(void);

/**
 * Set snapshot interval (0 to disable automatic snapshots)
 * @param interval_secs Interval in seconds (0 to disable)
 */
void x3_lmdb_set_snapshot_interval(unsigned int interval_secs);

/**
 * Set snapshot retention count
 * @param count Number of snapshots to retain (0 = unlimited)
 */
void x3_lmdb_set_snapshot_retention(unsigned int count);

/**
 * Cleanup old snapshots beyond retention count
 * @param base_path Base directory containing snapshots
 * @return Number of snapshots deleted
 */
int x3_lmdb_cleanup_old_snapshots(const char *base_path);

/* ========== JSON Export ========== */

/**
 * Export all LMDB data to a JSON file
 * @param json_path Path to output JSON file
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_export_json(const char *json_path);

/**
 * Export LMDB data to JSON with automatic timestamped filename
 * Creates file at: <base_path>/lmdb-export-YYYYMMDDHHMM.json
 * @param base_path Directory for export file
 * @param path_out Output buffer for actual path (must be at least 256 bytes, can be NULL)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_export_json_auto(const char *base_path, char *path_out);

/* ========== TTL Purge Job ========== */

/* Default purge interval (1 hour in seconds) */
#define LMDB_PURGE_INTERVAL_DEFAULT 3600

/* Purge job statistics */
struct lmdb_purge_stats {
    unsigned long activity_purged;
    unsigned long fingerprint_purged;
    unsigned long metadata_purged;
    unsigned long channel_purged;
    unsigned long total_purged;
    time_t last_run;
    time_t duration_ms;
};

/**
 * Run TTL purge job to clean expired entries from all LMDB databases
 * @param stats_out Optional output for purge statistics (can be NULL)
 * @return Total number of entries purged
 */
int x3_lmdb_purge_expired(struct lmdb_purge_stats *stats_out);

/**
 * Get last purge job statistics
 * @return Pointer to static stats structure (valid until next purge)
 */
const struct lmdb_purge_stats *x3_lmdb_get_purge_stats(void);

/**
 * Set purge job interval (0 to disable automatic purge)
 * @param interval_secs Interval in seconds (0 to disable)
 */
void x3_lmdb_set_purge_interval(unsigned int interval_secs);

/* ========== Session Token API ========== */

/* Session token TTL (24 hours) */
#define SESSION_TOKEN_TTL (24 * 3600)

/* Session token ID length (before base64 encoding) */
#define SESSION_TOKEN_ID_LEN 24

/* Session token prefix for detection in passwords */
#define SESSION_TOKEN_PREFIX "x3tok:"

/**
 * Generate a new session token for an authenticated user
 * @param username Account name to issue token for
 * @param token_out Buffer for the generated token (at least 64 bytes)
 * @param token_size Size of token_out buffer
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_session_create(const char *username, char *token_out, size_t token_size);

/**
 * Validate a session token
 * @param token Token to validate (full token including "x3tok:" prefix)
 * @param username_out Buffer for username (at least 64 bytes, can be NULL)
 * @param username_size Size of username_out buffer
 * @return LMDB_SUCCESS if valid, LMDB_NOT_FOUND if not found/expired, LMDB_ERROR on failure
 */
int x3_lmdb_session_validate(const char *token, char *username_out, size_t username_size);

/**
 * Delete/revoke a specific session token
 * @param token Token to revoke (full token including "x3tok:" prefix)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_session_revoke(const char *token);

/**
 * Revoke all session tokens for a user by incrementing session version
 * @param username Account name
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_session_revoke_all(const char *username);

/**
 * Get current session version for a user
 * @param username Account name
 * @param version_out Output for current version number
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if no version set, LMDB_ERROR on failure
 */
int x3_lmdb_session_get_version(const char *username, unsigned int *version_out);

/**
 * Check if a token looks like a session token (starts with x3tok:)
 * @param password Password/token string to check
 * @return 1 if it's a session token, 0 otherwise
 */
int x3_lmdb_is_session_token(const char *password);

/* ========== SCRAM Session Token API ========== */

/* SCRAM hash algorithm types */
enum scram_hash_type {
    SCRAM_HASH_SHA1 = 1,      /* SCRAM-SHA-1 (RFC 5802) - 20 byte output */
    SCRAM_HASH_SHA256 = 2,    /* SCRAM-SHA-256 (RFC 7677) - 32 byte output */
    SCRAM_HASH_SHA512 = 3     /* SCRAM-SHA-512 - 64 byte output */
};

/* SCRAM iteration count (RFC 7677 recommends at least 4096) */
#define SCRAM_ITERATION_COUNT 4096

/* SCRAM salt length in bytes */
#define SCRAM_SALT_LEN 16

/* Hash output lengths */
#define SCRAM_SHA1_LEN 20
#define SCRAM_SHA256_LEN 32
#define SCRAM_SHA512_LEN 64
#define SCRAM_MAX_HASH_LEN 64  /* Maximum of all hash types (SHA-512) */

/* SCRAM token prefix */
#define SCRAM_TOKEN_PREFIX "x3scram:"

/* SCRAM credential structure */
struct scram_credential {
    unsigned char salt[SCRAM_SALT_LEN];              /* Random salt */
    unsigned char stored_key[SCRAM_MAX_HASH_LEN];    /* H(ClientKey) */
    unsigned char server_key[SCRAM_MAX_HASH_LEN];    /* ServerKey */
    unsigned int iteration;                           /* Iteration count */
    enum scram_hash_type hash_type;                   /* Which hash algorithm */
    size_t hash_len;                                  /* Hash output length */
    char username[64];                                /* Associated account */
    time_t expiry;                                    /* When credential expires */
};

/* SCRAM session state for multi-step auth */
struct scram_session {
    char client_nonce[48];          /* r= from client-first */
    char server_nonce[48];          /* Server-generated nonce */
    char combined_nonce[96];        /* client_nonce + server_nonce */
    char salt_b64[32];              /* Base64-encoded salt */
    unsigned int iteration;         /* Iteration count */
    enum scram_hash_type hash_type; /* Which hash algorithm */
    char auth_message[512];         /* For computing signatures */
    size_t auth_message_len;        /* Current auth_message length */
    struct scram_credential cred;   /* Retrieved credential */
    int step;                       /* Current step (1=client-first, 2=client-final) */
};

/**
 * Create SCRAM credential for a session token with specified hash type
 * @param token_id Token ID (the part after x3tok:)
 * @param username Account name
 * @param password The session token value (will be used as SCRAM password)
 * @param hash_type SCRAM hash algorithm (SCRAM_HASH_SHA1, SCRAM_HASH_SHA256, SCRAM_HASH_SHA512)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_scram_create_ex(const char *token_id, const char *username,
                             const char *password, enum scram_hash_type hash_type);

/**
 * Create SCRAM-SHA-256 credential for a session token (legacy wrapper)
 * @param token_id Token ID (the part after x3tok:)
 * @param username Account name
 * @param password The session token value (will be used as SCRAM password)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_scram_create(const char *token_id, const char *username, const char *password);

/**
 * Get SCRAM credential for a token with specified hash type
 * @param token_id Token ID to look up
 * @param hash_type SCRAM hash algorithm
 * @param cred_out Output credential structure
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_scram_get_ex(const char *token_id, enum scram_hash_type hash_type,
                          struct scram_credential *cred_out);

/**
 * Get SCRAM credential for a token (legacy SHA-256 wrapper)
 * @param token_id Token ID to look up
 * @param cred_out Output credential structure
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_scram_get(const char *token_id, struct scram_credential *cred_out);

/**
 * Delete SCRAM credential for a specific hash type
 * @param token_id Token ID to delete
 * @param hash_type SCRAM hash algorithm
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_scram_delete_ex(const char *token_id, enum scram_hash_type hash_type);

/**
 * Delete all SCRAM credentials for a token (all hash types)
 * @param token_id Token ID to delete
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_scram_delete(const char *token_id);

/**
 * Revoke all SCRAM credentials for a user
 * This is called when session version is incremented
 * @param username Account name
 * @return Number of credentials deleted, or -1 on error
 */
int x3_lmdb_scram_revoke_all(const char *username);

/**
 * Check if password looks like a SCRAM token (starts with x3scram:)
 * @param password Password string to check
 * @return 1 if it's a SCRAM token, 0 otherwise
 */
int x3_lmdb_is_scram_token(const char *password);

/* ========== Account Password SCRAM API ========== */

/**
 * Create SCRAM credentials for an account password (all hash types)
 * This should be called whenever a password is set/changed.
 * @param account Account name
 * @param password The plaintext password
 * @return Number of credentials created (0-3), -1 on error
 */
int x3_lmdb_scram_acct_create_all(const char *account, const char *password);

/**
 * Create SCRAM credential for an account password with specified hash type
 * @param account Account name
 * @param password The plaintext password
 * @param hash_type SCRAM hash algorithm
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_scram_acct_create(const char *account, const char *password,
                               enum scram_hash_type hash_type);

/**
 * Get SCRAM credential for an account with specified hash type
 * @param account Account name to look up
 * @param hash_type SCRAM hash algorithm
 * @param cred_out Output credential structure
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_scram_acct_get(const char *account, enum scram_hash_type hash_type,
                            struct scram_credential *cred_out);

/**
 * Delete all SCRAM credentials for an account (all hash types)
 * @param account Account name
 * @return Number of credentials deleted, -1 on error
 */
int x3_lmdb_scram_acct_delete_all(const char *account);

/**
 * Derive SCRAM keys from password and salt (generic for any hash type)
 * @param hash_type Hash algorithm (SCRAM_HASH_SHA1, SCRAM_HASH_SHA256, SCRAM_HASH_SHA512)
 * @param password Password to derive from
 * @param salt Salt bytes
 * @param salt_len Salt length
 * @param iteration Iteration count
 * @param stored_key_out Output for StoredKey (size depends on hash type)
 * @param server_key_out Output for ServerKey (size depends on hash type)
 * @return 0 on success, -1 on failure
 */
int scram_derive_keys(enum scram_hash_type hash_type,
                      const char *password,
                      const unsigned char *salt, size_t salt_len,
                      unsigned int iteration,
                      unsigned char *stored_key_out,
                      unsigned char *server_key_out);

/**
 * Compute SCRAM client signature (generic for any hash type)
 * @param hash_type Hash algorithm
 * @param stored_key The StoredKey
 * @param auth_message The AuthMessage string
 * @param auth_message_len Length of AuthMessage
 * @param client_sig_out Output for ClientSignature
 * @return 0 on success, -1 on failure
 */
int scram_client_signature(enum scram_hash_type hash_type,
                           const unsigned char *stored_key,
                           const char *auth_message, size_t auth_message_len,
                           unsigned char *client_sig_out);

/**
 * Compute SCRAM server signature (generic for any hash type)
 * @param hash_type Hash algorithm
 * @param server_key The ServerKey
 * @param auth_message The AuthMessage string
 * @param auth_message_len Length of AuthMessage
 * @param server_sig_out Output for ServerSignature
 * @return 0 on success, -1 on failure
 */
int scram_server_signature(enum scram_hash_type hash_type,
                           const unsigned char *server_key,
                           const char *auth_message, size_t auth_message_len,
                           unsigned char *server_sig_out);

/**
 * Verify SCRAM client proof (generic for any hash type)
 * @param hash_type Hash algorithm
 * @param stored_key The StoredKey
 * @param auth_message The AuthMessage string
 * @param auth_message_len Length of AuthMessage
 * @param client_proof Base64-encoded client proof from client-final
 * @return 1 if valid, 0 if invalid, -1 on error
 */
int scram_verify_proof(enum scram_hash_type hash_type,
                       const unsigned char *stored_key,
                       const char *auth_message, size_t auth_message_len,
                       const char *client_proof);

/* Legacy SHA-256 specific wrappers (for backward compatibility) */

/**
 * Derive SCRAM-SHA-256 keys from password and salt
 * @param password Password to derive from
 * @param salt Salt bytes
 * @param salt_len Salt length
 * @param iteration Iteration count
 * @param stored_key_out Output for StoredKey (32 bytes)
 * @param server_key_out Output for ServerKey (32 bytes)
 * @return 0 on success, -1 on failure
 */
int scram_sha256_derive_keys(const char *password,
                             const unsigned char *salt, size_t salt_len,
                             unsigned int iteration,
                             unsigned char *stored_key_out,
                             unsigned char *server_key_out);

/**
 * Compute SCRAM-SHA-256 client signature
 * @param stored_key The StoredKey (32 bytes)
 * @param auth_message The AuthMessage string
 * @param auth_message_len Length of AuthMessage
 * @param client_sig_out Output for ClientSignature (32 bytes)
 * @return 0 on success, -1 on failure
 */
int scram_sha256_client_signature(const unsigned char *stored_key,
                                  const char *auth_message, size_t auth_message_len,
                                  unsigned char *client_sig_out);

/**
 * Compute SCRAM-SHA-256 server signature
 * @param server_key The ServerKey (32 bytes)
 * @param auth_message The AuthMessage string
 * @param auth_message_len Length of AuthMessage
 * @param server_sig_out Output for ServerSignature (32 bytes)
 * @return 0 on success, -1 on failure
 */
int scram_sha256_server_signature(const unsigned char *server_key,
                                  const char *auth_message, size_t auth_message_len,
                                  unsigned char *server_sig_out);

/**
 * Verify SCRAM-SHA-256 client proof
 * @param stored_key The StoredKey (32 bytes)
 * @param auth_message The AuthMessage string
 * @param auth_message_len Length of AuthMessage
 * @param client_proof Base64-encoded client proof from client-final
 * @return 1 if valid, 0 if invalid, -1 on error
 */
int scram_sha256_verify_proof(const unsigned char *stored_key,
                              const char *auth_message, size_t auth_message_len,
                              const char *client_proof);

/* ========== Prefix Iteration ========== */

/* Callback type for prefix iteration */
typedef int (*lmdb_prefix_callback_t)(const char *key, const char *value, void *ctx);

/**
 * Iterate over all keys with a given prefix
 * @param db Database name
 * @param prefix Key prefix to match
 * @param callback Function to call for each matching key/value
 * @param ctx User context passed to callback
 * @return Number of entries iterated, or negative on error
 *
 * Callback should return 0 to continue iteration, non-zero to stop.
 */
int x3_lmdb_prefix_iterate(const char *db, const char *prefix,
                           lmdb_prefix_callback_t callback, void *ctx);

/**
 * Delete all keys with a given prefix
 * @param db Database name
 * @param prefix Key prefix to match
 * @return Number of entries deleted, or negative on error
 */
int x3_lmdb_prefix_delete_all(const char *db, const char *prefix);

/**
 * Count all keys with a given prefix
 * @param db Database name
 * @param prefix Key prefix to match
 * @return Number of entries, or negative on error
 */
int x3_lmdb_prefix_count(const char *db, const char *prefix);

/* ========== Core Account Data (SAXDB-optional) ========== */

/**
 * Store account handle data as JSON
 * @param handle Account handle name
 * @param json_data JSON string containing account data
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_handle_set(const char *handle, const char *json_data);

/**
 * Get account handle data as JSON
 * @param handle Account handle name
 * @param json_out Output buffer for JSON string (must be at least 8192 bytes)
 * @param json_size Size of output buffer
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_handle_get(const char *handle, char *json_out, size_t json_size);

/**
 * Delete account handle data
 * @param handle Account handle name
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_handle_delete(const char *handle);

/**
 * Check if account handle exists
 * @param handle Account handle name
 * @return 1 if exists, 0 if not, negative on error
 */
int x3_lmdb_handle_exists(const char *handle);

/**
 * Register a nick to a handle
 * @param nick Nick name
 * @param handle Account handle
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_nick_register(const char *nick, const char *handle);

/**
 * Get handle for a registered nick
 * @param nick Nick name
 * @param handle_out Output buffer for handle (must be at least 64 bytes)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_nick_get_handle(const char *nick, char *handle_out);

/**
 * Unregister a nick
 * @param nick Nick name
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_nick_unregister(const char *nick);

/* ========== Account Masks ========== */

/**
 * Add a mask to an account
 * @param handle Account handle
 * @param mask Hostmask string
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_mask_add(const char *handle, const char *mask);

/**
 * Delete all masks for an account
 * @param handle Account handle
 * @return Number of masks deleted, LMDB_ERROR on failure
 */
int x3_lmdb_mask_clear(const char *handle);

/**
 * List all masks for an account
 * @param handle Account handle
 * @param masks_out Output array of mask strings
 * @param count_out Number of masks returned
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_mask_list(const char *handle, char ***masks_out, unsigned int *count_out);

/**
 * Free mask list returned by x3_lmdb_mask_list
 * @param masks Array of mask strings
 * @param count Number of masks
 */
void x3_lmdb_free_mask_list(char **masks, unsigned int count);

/* ========== Account Ignores ========== */

/**
 * Add an ignore to an account
 * @param handle Account handle
 * @param ignore Ignore pattern string
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_ignore_add(const char *handle, const char *ignore);

/**
 * Delete all ignores for an account
 * @param handle Account handle
 * @return Number of ignores deleted, LMDB_ERROR on failure
 */
int x3_lmdb_ignore_clear(const char *handle);

/**
 * List all ignores for an account
 * @param handle Account handle
 * @param ignores_out Output array of ignore strings
 * @param count_out Number of ignores returned
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_ignore_list(const char *handle, char ***ignores_out, unsigned int *count_out);

/* ========== Account Cookies ========== */

/**
 * Store a cookie for an account
 * @param handle Account handle
 * @param cookie_type Cookie type string (ACTIVATION, PASSWORD_CHANGE, etc.)
 * @param cookie_value Cookie value
 * @param cookie_data Additional data (can be NULL)
 * @param expires Expiry timestamp
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_cookie_set(const char *handle, const char *cookie_type,
                       const char *cookie_value, const char *cookie_data,
                       time_t expires);

/**
 * Get cookie for an account
 * @param handle Account handle
 * @param type_out Output for cookie type
 * @param type_size Size of type_out buffer
 * @param cookie_out Output for cookie value
 * @param cookie_size Size of cookie_out buffer
 * @param data_out Output for cookie data (can be NULL)
 * @param data_size Size of data_out buffer
 * @param expires_out Output for expiry timestamp (can be NULL)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_cookie_get(const char *handle, char *type_out, size_t type_size,
                       char *cookie_out, size_t cookie_size,
                       char *data_out, size_t data_size,
                       time_t *expires_out);

/**
 * Delete cookie for an account
 * @param handle Account handle
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_cookie_delete(const char *handle);

/* ========== Core Channel Data (SAXDB-optional) ========== */

/**
 * Store channel registration data
 * @param channel Channel name (with #)
 * @param json_data JSON-encoded channel data
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_chanreg_set(const char *channel, const char *json_data);

/**
 * Get channel registration data
 * @param channel Channel name (with #)
 * @param json_out Buffer for JSON data
 * @param json_size Size of buffer
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_chanreg_get(const char *channel, char *json_out, size_t json_size);

/**
 * Delete channel registration data
 * @param channel Channel name (with #)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_chanreg_delete(const char *channel);

/**
 * Check if channel registration exists
 * @param channel Channel name (with #)
 * @return 1 if exists, 0 if not
 */
int x3_lmdb_chanreg_exists(const char *channel);

/**
 * Store channel user (access list entry)
 * @param channel Channel name (with #)
 * @param handle Account handle
 * @param json_data JSON-encoded user data (access, flags, seen, info)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_chanuser_reg_set(const char *channel, const char *handle, const char *json_data);

/**
 * Get channel user data
 * @param channel Channel name (with #)
 * @param handle Account handle
 * @param json_out Buffer for JSON data
 * @param json_size Size of buffer
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_chanuser_reg_get(const char *channel, const char *handle, char *json_out, size_t json_size);

/**
 * Delete channel user
 * @param channel Channel name (with #)
 * @param handle Account handle
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_chanuser_reg_delete(const char *channel, const char *handle);

/**
 * Clear all users for a channel
 * @param channel Channel name (with #)
 * @return Number of users deleted, LMDB_ERROR on failure
 */
int x3_lmdb_chanuser_reg_clear(const char *channel);

/**
 * Add channel ban
 * @param channel Channel name (with #)
 * @param json_data JSON-encoded ban data (mask, owner, reason, set_time, expires)
 * @return Index of ban added, LMDB_ERROR on failure
 */
int x3_lmdb_chanban_add(const char *channel, const char *json_data);

/**
 * Clear all bans for a channel
 * @param channel Channel name (with #)
 * @return Number of bans deleted, LMDB_ERROR on failure
 */
int x3_lmdb_chanban_clear(const char *channel);

/**
 * List all bans for a channel
 * @param channel Channel name (with #)
 * @param json_out Array of JSON strings (caller must free each and the array)
 * @param count_out Output for number of bans
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_chanban_list(const char *channel, char ***json_out, unsigned int *count_out);

/**
 * Free ban list returned by x3_lmdb_chanban_list
 */
void x3_lmdb_free_chanban_list(char **bans, unsigned int count);

/* ========== OpServ Data (SAXDB-optional) ========== */

/**
 * Store trusted host
 * @param ipaddr IP address/mask
 * @param json_data JSON-encoded trusted host data (issuer, reason, limit, issued, expires)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_trusted_set(const char *ipaddr, const char *json_data);

/**
 * Get trusted host data
 * @param ipaddr IP address/mask
 * @param json_out Buffer for JSON data
 * @param json_size Size of buffer
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_trusted_get(const char *ipaddr, char *json_out, size_t json_size);

/**
 * Delete trusted host
 * @param ipaddr IP address/mask
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_trusted_delete(const char *ipaddr);

/**
 * Store gag entry
 * @param mask Gag mask
 * @param json_data JSON-encoded gag data (owner, reason, expires)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_gag_set(const char *mask, const char *json_data);

/**
 * Get gag entry
 * @param mask Gag mask
 * @param json_out Buffer for JSON data
 * @param json_size Size of buffer
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_gag_get(const char *mask, char *json_out, size_t json_size);

/**
 * Delete gag entry
 * @param mask Gag mask
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_gag_delete(const char *mask);

/**
 * Store alert
 * @param name Alert name
 * @param json_data JSON-encoded alert data (discrim, owner, reaction, last, expire)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_alert_set(const char *name, const char *json_data);

/**
 * Get alert
 * @param name Alert name
 * @param json_out Buffer for JSON data
 * @param json_size Size of buffer
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_alert_get(const char *name, char *json_out, size_t json_size);

/**
 * Delete alert
 * @param name Alert name
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_alert_delete(const char *name);

/* ========== Global Messages (SAXDB-optional) ========== */

/**
 * Store global message
 * @param id Message ID (as string)
 * @param json_data JSON-encoded message data (flags, posted, duration, from, message)
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_global_set(const char *id, const char *json_data);

/**
 * Get global message
 * @param id Message ID (as string)
 * @param json_out Buffer for JSON data
 * @param json_size Size of buffer
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_global_get(const char *id, char *json_out, size_t json_size);

/**
 * Delete global message
 * @param id Message ID (as string)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_global_delete(const char *id);

/**
 * Clear all global messages
 * @return Number of messages deleted, LMDB_ERROR on failure
 */
int x3_lmdb_global_clear(void);

/* ========== SAXDB Configuration ========== */

/**
 * Check if SAXDB is enabled
 * @return 1 if enabled (default), 0 if disabled
 */
int x3_lmdb_saxdb_enabled(void);

/**
 * Set SAXDB enabled flag (called from config reader)
 * @param enabled 1 to enable, 0 to disable
 */
void x3_lmdb_set_saxdb_enabled(int enabled);

/* ========== Module Registration ========== */

/**
 * Initialize the LMDB module (called from x3 startup)
 */
void init_x3_lmdb(void);

#else /* !WITH_LMDB */

/* Stub functions when LMDB is not available */
#define x3_lmdb_init(p, s)              (0)
#define x3_lmdb_shutdown()              do {} while(0)
#define x3_lmdb_is_available()          (0)
#define x3_lmdb_account_get(a, k, v)    (-2)
#define x3_lmdb_account_set(a, k, v)    (-1)
#define x3_lmdb_account_delete(a, k)    (-2)
#define x3_lmdb_account_list(a, e)      (-1)
#define x3_lmdb_account_clear(a)        (-1)
#define x3_lmdb_account_set_ex(a, k, v, e) (-1)
#define x3_lmdb_account_get_ex(a, k, v, e) (-2)
#define x3_lmdb_account_get_raw(a, k, v, l, c) (-2)
#define x3_lmdb_account_set_raw(a, k, v, l) (-1)
#define x3_lmdb_account_list_raw(a, e)  (-1)
#define x3_lmdb_free_raw_entries(e)     do {} while(0)
#define x3_lmdb_channel_get(c, k, v)    (-2)
#define x3_lmdb_channel_set(c, k, v)    (-1)
#define x3_lmdb_channel_delete(c, k)    (-2)
#define x3_lmdb_channel_list(c, e)      (-1)
#define x3_lmdb_channel_clear(c)        (-1)
#define x3_lmdb_channel_set_ex(c, k, v, e) (-1)
#define x3_lmdb_channel_get_ex(c, k, v, e) (-2)
#define x3_lmdb_metadata_purge_expired() (0)
#define x3_lmdb_chanaccess_get(c, a, o) (-2)
#define x3_lmdb_chanaccess_get_ex(c, a, o, t) (-2)
#define x3_lmdb_chanaccess_set(c, a, l) (-1)
#define x3_lmdb_chanaccess_set_ex(c, a, l, t) (-1)
#define x3_lmdb_chanaccess_delete(c, a) (-2)
#define x3_lmdb_chanaccess_list(c, e)   (-1)
#define x3_lmdb_chanaccess_list_account(a, e) (-1)
#define x3_lmdb_chanaccess_clear(c)     (-1)
#define x3_lmdb_free_chanaccess_entries(e) do {} while(0)
#define x3_lmdb_activity_get(a, l, p)   (-2)
#define x3_lmdb_activity_set(a, l, p)   (-1)
#define x3_lmdb_activity_touch(a)       (-2)
#define x3_lmdb_activity_delete(a)      (-2)
#define x3_lmdb_fingerprint_get(f, a, r, u, e) (-2)
#define x3_lmdb_fingerprint_set(f, a, r, u) (-1)
#define x3_lmdb_fingerprint_touch(f)    (-2)
#define x3_lmdb_fingerprint_delete(f)   (-2)
#define x3_lmdb_fingerprint_list_account(a, e) (-1)
#define x3_lmdb_free_fingerprint_entries(e) do {} while(0)
#define x3_lmdb_free_entries(e)         do {} while(0)
#define x3_lmdb_sync(f)                 (0)
#define x3_lmdb_stats(d, e, s)          (-1)
#define x3_lmdb_purge_expired(s)        (0)
#define x3_lmdb_get_purge_stats()       ((const struct lmdb_purge_stats *)NULL)
#define x3_lmdb_set_purge_interval(i)   do {} while(0)
#define x3_lmdb_snapshot(p, c)          (-1)
#define x3_lmdb_snapshot_auto(p, c, o)  (-1)
#define x3_lmdb_get_snapshot_stats()    ((const struct lmdb_snapshot_stats *)NULL)
#define x3_lmdb_set_snapshot_interval(i) do {} while(0)
#define x3_lmdb_set_snapshot_retention(c) do {} while(0)
#define x3_lmdb_cleanup_old_snapshots(p) (0)
#define x3_lmdb_export_json(p)          (-1)
#define x3_lmdb_export_json_auto(p, o)  (-1)
#define x3_lmdb_session_create(u, t, s) (-1)
#define x3_lmdb_session_validate(t, u, s) (-2)
#define x3_lmdb_session_revoke(t)       (-2)
#define x3_lmdb_session_revoke_all(u)   (-1)
#define x3_lmdb_session_get_version(u, v) (-2)
#define x3_lmdb_is_session_token(p)     (0)
#define x3_lmdb_scram_create_ex(t, u, p, h) (-1)
#define x3_lmdb_scram_create(t, u, p)   (-1)
#define x3_lmdb_scram_get_ex(t, h, c)   (-2)
#define x3_lmdb_scram_get(t, c)         (-2)
#define x3_lmdb_scram_delete_ex(t, h)   (-2)
#define x3_lmdb_scram_delete(t)         (-2)
#define x3_lmdb_scram_revoke_all(u)     (-1)
#define x3_lmdb_is_scram_token(p)       (0)
#define x3_lmdb_scram_acct_create_all(a, p) (-1)
#define x3_lmdb_scram_acct_create(a, p, h) (-1)
#define x3_lmdb_scram_acct_get(a, h, c) (-2)
#define x3_lmdb_scram_acct_delete_all(a) (-1)
#define scram_derive_keys(h, p, s, l, i, sk, svk) (-1)
#define scram_client_signature(h, sk, m, l, o) (-1)
#define scram_server_signature(h, sk, m, l, o) (-1)
#define scram_verify_proof(h, sk, m, l, p) (-1)
#define scram_sha256_derive_keys(p, s, l, i, sk, svk) (-1)
#define scram_sha256_client_signature(sk, m, l, o) (-1)
#define scram_sha256_server_signature(sk, m, l, o) (-1)
#define scram_sha256_verify_proof(sk, m, l, p) (-1)
#define x3_lmdb_prefix_iterate(d, p, c, x) (-1)
#define x3_lmdb_prefix_delete_all(d, p) (-1)
#define x3_lmdb_prefix_count(d, p)      (-1)
#define x3_lmdb_handle_set(h, j)        (-1)
#define x3_lmdb_handle_get(h, j, s)     (-2)
#define x3_lmdb_handle_delete(h)        (-2)
#define x3_lmdb_handle_exists(h)        (0)
#define x3_lmdb_nick_register(n, h)     (-1)
#define x3_lmdb_nick_get_handle(n, h)   (-2)
#define x3_lmdb_nick_unregister(n)      (-2)
#define x3_lmdb_mask_add(h, m)          (-1)
#define x3_lmdb_mask_clear(h)           (-1)
#define x3_lmdb_mask_list(h, m, c)      (-1)
#define x3_lmdb_free_mask_list(m, c)    do {} while(0)
#define x3_lmdb_ignore_add(h, i)        (-1)
#define x3_lmdb_ignore_clear(h)         (-1)
#define x3_lmdb_ignore_list(h, i, c)    (-1)
#define x3_lmdb_cookie_set(h, t, v, d, e) (-1)
#define x3_lmdb_cookie_get(h, t, ts, c, cs, d, ds, e) (-2)
#define x3_lmdb_cookie_delete(h)        (-2)
#define x3_lmdb_chanreg_set(c, j)       (-1)
#define x3_lmdb_chanreg_get(c, j, s)    (-2)
#define x3_lmdb_chanreg_delete(c)       (-2)
#define x3_lmdb_chanreg_exists(c)       (0)
#define x3_lmdb_chanuser_reg_set(c, h, j) (-1)
#define x3_lmdb_chanuser_reg_get(c, h, j, s) (-2)
#define x3_lmdb_chanuser_reg_delete(c, h) (-2)
#define x3_lmdb_chanuser_reg_clear(c)   (-1)
#define x3_lmdb_chanban_add(c, j)       (-1)
#define x3_lmdb_chanban_clear(c)        (-1)
#define x3_lmdb_chanban_list(c, j, n)   (-1)
#define x3_lmdb_free_chanban_list(b, c) do {} while(0)
#define x3_lmdb_trusted_set(i, j)       (-1)
#define x3_lmdb_trusted_get(i, j, s)    (-2)
#define x3_lmdb_trusted_delete(i)       (-2)
#define x3_lmdb_gag_set(m, j)           (-1)
#define x3_lmdb_gag_get(m, j, s)        (-2)
#define x3_lmdb_gag_delete(m)           (-2)
#define x3_lmdb_alert_set(n, j)         (-1)
#define x3_lmdb_alert_get(n, j, s)      (-2)
#define x3_lmdb_alert_delete(n)         (-2)
#define x3_lmdb_global_set(i, j)        (-1)
#define x3_lmdb_global_get(i, j, s)     (-2)
#define x3_lmdb_global_delete(i)        (-2)
#define x3_lmdb_global_clear()          (-1)
#define x3_lmdb_saxdb_enabled()         (1)
#define x3_lmdb_set_saxdb_enabled(e)    do {} while(0)
#define init_x3_lmdb()                  do {} while(0)

#endif /* WITH_LMDB */

#endif /* X3_LMDB_H */
