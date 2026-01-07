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
#include <stdint.h>

/* Error codes - always defined so code compiles without LMDB */
enum lmdb_error {
    LMDB_SUCCESS = 0,
    LMDB_ERROR = -1,
    LMDB_NOT_FOUND = -2,
    LMDB_FULL = -3,
    LMDB_EXPIRED = -4   /* Entry found but expired (auto-deleted) */
};

/* Channel sync metadata structure - always defined for use in code */
struct lmdb_chansync_meta {
    uint64_t membership_hash;     /* Hash of last known membership (for incremental sync) */
    time_t last_sync;             /* When this channel was last synced */
    int consecutive_failures;     /* For exponential backoff */
    time_t next_allowed_sync;     /* Don't retry before this time */
    int last_entry_count;         /* Number of entries in last sync */
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

/**
 * Delete all metadata entries for a given account
 * Used for immediate cache invalidation when user attributes change in Keycloak.
 * @param account Account name to purge metadata for
 * @return Number of entries deleted, LMDB_ERROR on failure
 */
int x3_lmdb_metadata_delete_by_user(const char *account);

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

/* ========== Channel Sync Metadata (for Keycloak sync) ========== */

/* Key prefix for channel sync metadata */
#define LMDB_PREFIX_CHANSYNC "kcsyncmeta:"

/* Note: struct lmdb_chansync_meta is defined at the top of this header,
 * outside #ifdef WITH_LMDB, so code can use the struct even without LMDB */

/**
 * Get channel sync metadata
 * @param channel Channel name (with #)
 * @param meta_out Output structure
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_chansync_get(const char *channel, struct lmdb_chansync_meta *meta_out);

/**
 * Set channel sync metadata
 * @param channel Channel name (with #)
 * @param meta Metadata to store
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_chansync_set(const char *channel, const struct lmdb_chansync_meta *meta);

/**
 * Delete channel sync metadata
 * @param channel Channel name (with #)
 * @return LMDB_SUCCESS on success, LMDB_NOT_FOUND if not found, LMDB_ERROR on failure
 */
int x3_lmdb_chansync_delete(const char *channel);

/**
 * Record a sync failure for a channel (increments counter, sets backoff)
 * @param channel Channel name (with #)
 * @return New consecutive failure count, or -1 on error
 */
int x3_lmdb_chansync_record_failure(const char *channel);

/**
 * Record a successful sync for a channel (resets failure counter)
 * @param channel Channel name (with #)
 * @param membership_hash Hash of current membership
 * @param entry_count Number of entries synced
 * @return LMDB_SUCCESS on success, LMDB_ERROR on failure
 */
int x3_lmdb_chansync_record_success(const char *channel, uint64_t membership_hash, int entry_count);

/**
 * Check if a channel is in backoff period
 * @param channel Channel name (with #)
 * @return 1 if in backoff, 0 if ok to sync, -1 on error
 */
int x3_lmdb_chansync_in_backoff(const char *channel);

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
#define x3_lmdb_metadata_delete_by_user(a) (0)
#define x3_lmdb_chanaccess_get(c, a, o) (-2)
#define x3_lmdb_chanaccess_get_ex(c, a, o, t) (-2)
#define x3_lmdb_chanaccess_set(c, a, l) (-1)
#define x3_lmdb_chanaccess_set_ex(c, a, l, t) (-1)
#define x3_lmdb_chanaccess_delete(c, a) (-2)
#define x3_lmdb_chanaccess_list(c, e)   (-1)
#define x3_lmdb_chanaccess_list_account(a, e) (-1)
#define x3_lmdb_chanaccess_clear(c)     (-1)
#define x3_lmdb_free_chanaccess_entries(e) do {} while(0)
#define x3_lmdb_chansync_get(c, m)      (-2)
#define x3_lmdb_chansync_set(c, m)      (-1)
#define x3_lmdb_chansync_delete(c)      (-2)
#define x3_lmdb_chansync_record_failure(c) (-1)
#define x3_lmdb_chansync_record_success(c, h, e) (-1)
#define x3_lmdb_chansync_in_backoff(c)  (0)
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
#define init_x3_lmdb()                  do {} while(0)

#endif /* WITH_LMDB */

#endif /* X3_LMDB_H */
