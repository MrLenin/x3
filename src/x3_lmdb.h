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
#define LMDB_PREFIX_AUTHFAIL "authfail:"  /* Failed auth attempts cache (hash → timestamp) */
#define LMDB_PREFIX_FPFAIL "fpfail:"  /* Failed fingerprint lookups cache (fingerprint → timestamp) */

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
#define init_x3_lmdb()                  do {} while(0)

#endif /* WITH_LMDB */

#endif /* X3_LMDB_H */
