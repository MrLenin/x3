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

#ifdef WITH_LMDB

#include <lmdb.h>
#include <stddef.h>

/* Error codes */
enum lmdb_error {
    LMDB_SUCCESS = 0,
    LMDB_ERROR = -1,
    LMDB_NOT_FOUND = -2,
    LMDB_FULL = -3
};

/* Database names */
#define LMDB_DB_ACCOUNTS    "accounts"
#define LMDB_DB_CHANNELS    "channels"
#define LMDB_DB_METADATA    "metadata"

/* Key prefixes */
#define LMDB_PREFIX_ACCOUNT  "acct:"
#define LMDB_PREFIX_CHANNEL  "chan:"
#define LMDB_PREFIX_META     "meta:"

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
#define x3_lmdb_channel_get(c, k, v)    (-2)
#define x3_lmdb_channel_set(c, k, v)    (-1)
#define x3_lmdb_channel_delete(c, k)    (-2)
#define x3_lmdb_channel_list(c, e)      (-1)
#define x3_lmdb_channel_clear(c)        (-1)
#define x3_lmdb_free_entries(e)         do {} while(0)
#define x3_lmdb_sync(f)                 (0)
#define x3_lmdb_stats(d, e, s)          (-1)
#define init_x3_lmdb()                  do {} while(0)

#endif /* WITH_LMDB */

#endif /* X3_LMDB_H */
