/*
 * X3 - LMDB Wrapper Module Implementation
 * Copyright (C) 2024 AfterNET Development Team
 *
 * Provides LMDB-based persistent storage for X3 metadata and account data.
 */

#include "config.h"

#ifdef WITH_LMDB

#include "x3_lmdb.h"
#include "x3_compress.h"
#include "common.h"
#include "conf.h"
#include "log.h"
#include "proto.h"
#include "timeq.h"

#include <lmdb.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

/* LMDB Environment */
static MDB_env *lmdb_env = NULL;
static MDB_dbi dbi_accounts = 0;
static MDB_dbi dbi_channels = 0;
static MDB_dbi dbi_metadata = 0;
static int lmdb_initialized = 0;

/* Configuration */
static char lmdb_path[MAXLEN];
static size_t lmdb_mapsize = 100 * 1024 * 1024; /* 100MB default */

/* Maximum value size (increased for compression support) */
#define LMDB_MAX_VALUE_SIZE 8192

/* Key buffer size */
#define LMDB_KEY_BUFFER_SIZE 512

/**
 * Open a named database within the environment
 */
static int open_database(MDB_txn *txn, const char *name, MDB_dbi *dbi)
{
    int rc = mdb_dbi_open(txn, name, MDB_CREATE, dbi);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to open database '%s': %s",
                   name, mdb_strerror(rc));
        return LMDB_ERROR;
    }
    return LMDB_SUCCESS;
}

/* ========== Initialization ========== */

int x3_lmdb_init(const char *dbpath, size_t mapsize)
{
    MDB_txn *txn;
    int rc;
    struct stat st;

    if (lmdb_initialized) {
        return LMDB_SUCCESS;
    }

    /* Store configuration */
    strncpy(lmdb_path, dbpath, sizeof(lmdb_path) - 1);
    lmdb_path[sizeof(lmdb_path) - 1] = '\0';

    if (mapsize > 0) {
        lmdb_mapsize = mapsize;
    }

    /* Create directory if it doesn't exist */
    if (stat(lmdb_path, &st) != 0) {
        if (mkdir(lmdb_path, 0755) != 0 && errno != EEXIST) {
            log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to create directory '%s': %s",
                       lmdb_path, strerror(errno));
            return LMDB_ERROR;
        }
    }

    /* Create the LMDB environment */
    rc = mdb_env_create(&lmdb_env);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to create environment: %s",
                   mdb_strerror(rc));
        return LMDB_ERROR;
    }

    /* Set maximum number of named databases */
    rc = mdb_env_set_maxdbs(lmdb_env, 4);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to set maxdbs: %s",
                   mdb_strerror(rc));
        mdb_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    /* Set the map size */
    rc = mdb_env_set_mapsize(lmdb_env, lmdb_mapsize);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to set mapsize: %s",
                   mdb_strerror(rc));
        mdb_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    /* Open the environment */
    rc = mdb_env_open(lmdb_env, lmdb_path, 0, 0644);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to open environment at '%s': %s",
                   lmdb_path, mdb_strerror(rc));
        mdb_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    /* Open databases in a write transaction */
    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to begin transaction: %s",
                   mdb_strerror(rc));
        mdb_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    if (open_database(txn, LMDB_DB_ACCOUNTS, &dbi_accounts) != LMDB_SUCCESS ||
        open_database(txn, LMDB_DB_CHANNELS, &dbi_channels) != LMDB_SUCCESS ||
        open_database(txn, LMDB_DB_METADATA, &dbi_metadata) != LMDB_SUCCESS) {
        mdb_txn_abort(txn);
        mdb_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to commit transaction: %s",
                   mdb_strerror(rc));
        mdb_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    lmdb_initialized = 1;
    log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Initialized at '%s' with %luMB map",
               lmdb_path, (unsigned long)(lmdb_mapsize / (1024 * 1024)));

    return LMDB_SUCCESS;
}

void x3_lmdb_shutdown(void)
{
    if (!lmdb_initialized || !lmdb_env) {
        return;
    }

    mdb_dbi_close(lmdb_env, dbi_accounts);
    mdb_dbi_close(lmdb_env, dbi_channels);
    mdb_dbi_close(lmdb_env, dbi_metadata);
    mdb_env_close(lmdb_env);

    lmdb_env = NULL;
    lmdb_initialized = 0;

    log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Shutdown complete");
}

int x3_lmdb_is_available(void)
{
    return lmdb_initialized && lmdb_env != NULL;
}

/* ========== Account Metadata ========== */

int x3_lmdb_account_get(const char *account, const char *key, char *value)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !account || !key || !value) {
        return LMDB_ERROR;
    }

    /* Build composite key: "account\0key" */
    snprintf(keybuf, sizeof(keybuf), "%s", account);
    size_t account_len = strlen(account);
    keybuf[account_len] = '\0';
    strncpy(keybuf + account_len + 1, key, sizeof(keybuf) - account_len - 2);

    mkey.mv_size = account_len + 1 + strlen(key) + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_get(txn, dbi_accounts, &mkey, &mdata);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Decompress if needed, then copy value */
#ifdef WITH_ZSTD
    {
        unsigned char decompressed[LMDB_MAX_VALUE_SIZE];
        size_t decompressed_len;

        if (x3_decompress(mdata.mv_data, mdata.mv_size,
                          decompressed, sizeof(decompressed) - 1, &decompressed_len) >= 0) {
            memcpy(value, decompressed, decompressed_len);
            value[decompressed_len] = '\0';
        } else {
            return LMDB_ERROR;
        }
    }
#else
    /* Copy value, ensuring null termination */
    size_t copylen = mdata.mv_size < LMDB_MAX_VALUE_SIZE ? mdata.mv_size : LMDB_MAX_VALUE_SIZE - 1;
    memcpy(value, mdata.mv_data, copylen);
    value[copylen] = '\0';
#endif

    return LMDB_SUCCESS;
}

int x3_lmdb_account_set(const char *account, const char *key, const char *value)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !account || !key) {
        return LMDB_ERROR;
    }

    /* Build composite key: "account\0key" */
    snprintf(keybuf, sizeof(keybuf), "%s", account);
    size_t account_len = strlen(account);
    keybuf[account_len] = '\0';
    strncpy(keybuf + account_len + 1, key, sizeof(keybuf) - account_len - 2);

    mkey.mv_size = account_len + 1 + strlen(key) + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    if (value) {
#ifdef WITH_ZSTD
        unsigned char compressed[LMDB_MAX_VALUE_SIZE];
        size_t compressed_len;
        size_t value_len = strlen(value) + 1;

        if (x3_compress((const unsigned char *)value, value_len,
                        compressed, sizeof(compressed), &compressed_len) >= 0) {
            mdata.mv_size = compressed_len;
            mdata.mv_data = compressed;
        } else {
            mdata.mv_size = value_len;
            mdata.mv_data = (void *)value;
        }
#else
        mdata.mv_size = strlen(value) + 1;
        mdata.mv_data = (void *)value;
#endif
        rc = mdb_put(txn, dbi_accounts, &mkey, &mdata, 0);
    } else {
        rc = mdb_del(txn, dbi_accounts, &mkey, NULL);
        if (rc == MDB_NOTFOUND) {
            rc = 0; /* Deleting non-existent key is not an error */
        }
    }

    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_account_delete(const char *account, const char *key)
{
    return x3_lmdb_account_set(account, key, NULL);
}

int x3_lmdb_account_get_raw(const char *account, const char *key,
                            unsigned char *raw_value, size_t *raw_len,
                            int *is_compressed)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !account || !key || !raw_value || !raw_len || !is_compressed) {
        return LMDB_ERROR;
    }

    /* Build composite key: "account\0key" */
    snprintf(keybuf, sizeof(keybuf), "%s", account);
    size_t account_len = strlen(account);
    keybuf[account_len] = '\0';
    strncpy(keybuf + account_len + 1, key, sizeof(keybuf) - account_len - 2);

    mkey.mv_size = account_len + 1 + strlen(key) + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_get(txn, dbi_accounts, &mkey, &mdata);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Return raw data without decompression */
    if (mdata.mv_size > LMDB_MAX_VALUE_SIZE) {
        return LMDB_ERROR;
    }

    memcpy(raw_value, mdata.mv_data, mdata.mv_size);
    *raw_len = mdata.mv_size;

    /* Check if data is compressed (has magic byte) */
#ifdef WITH_ZSTD
    *is_compressed = x3_is_compressed(mdata.mv_data, mdata.mv_size);
#else
    *is_compressed = 0;
#endif

    return LMDB_SUCCESS;
}

int x3_lmdb_account_set_raw(const char *account, const char *key,
                            const unsigned char *raw_value, size_t raw_len)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !account || !key || !raw_value || raw_len == 0) {
        return LMDB_ERROR;
    }

    /* Build composite key: "account\0key" */
    snprintf(keybuf, sizeof(keybuf), "%s", account);
    size_t account_len = strlen(account);
    keybuf[account_len] = '\0';
    strncpy(keybuf + account_len + 1, key, sizeof(keybuf) - account_len - 2);

    mkey.mv_size = account_len + 1 + strlen(key) + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Store raw value without compression (it's already compressed or we want it as-is) */
    mdata.mv_size = raw_len;
    mdata.mv_data = (void *)raw_value;

    rc = mdb_put(txn, dbi_accounts, &mkey, &mdata, 0);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_account_list(const char *account, struct lmdb_metadata_entry **entries_out)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    char prefix[LMDB_KEY_BUFFER_SIZE];
    struct lmdb_metadata_entry *head = NULL, *tail = NULL;
    int count = 0;
    int rc;

    if (!x3_lmdb_is_available() || !account || !entries_out) {
        return LMDB_ERROR;
    }

    *entries_out = NULL;

    /* Build prefix: "account\0" */
    size_t prefix_len = strlen(account) + 1;
    snprintf(prefix, sizeof(prefix), "%s", account);
    prefix[prefix_len - 1] = '\0';

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_cursor_open(txn, dbi_accounts, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Position cursor at prefix */
    mkey.mv_size = prefix_len;
    mkey.mv_data = prefix;

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_SET_RANGE);
    while (rc == 0) {
        /* Check if key still starts with our prefix */
        if (mkey.mv_size < prefix_len ||
            memcmp(mkey.mv_data, prefix, prefix_len - 1) != 0) {
            break;
        }

        /* Extract the key part after "account\0" */
        const char *keystart = (const char *)mkey.mv_data + prefix_len;
        size_t keylen = mkey.mv_size - prefix_len;

        /* Create entry */
        struct lmdb_metadata_entry *entry = malloc(sizeof(*entry));
        if (!entry) {
            break;
        }

        entry->key = strndup(keystart, keylen);
        entry->value = strndup(mdata.mv_data, mdata.mv_size);
        entry->next = NULL;

        if (tail) {
            tail->next = entry;
        } else {
            head = entry;
        }
        tail = entry;
        count++;

        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
    }

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    *entries_out = head;
    return count;
}

int x3_lmdb_account_clear(const char *account)
{
    struct lmdb_metadata_entry *entries, *entry;
    int count;

    count = x3_lmdb_account_list(account, &entries);
    if (count <= 0) {
        return count;
    }

    for (entry = entries; entry; entry = entry->next) {
        x3_lmdb_account_delete(account, entry->key);
    }

    x3_lmdb_free_entries(entries);
    return count;
}

int x3_lmdb_account_list_raw(const char *account, struct lmdb_raw_metadata_entry **entries_out)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    char prefix[LMDB_KEY_BUFFER_SIZE];
    struct lmdb_raw_metadata_entry *head = NULL, *tail = NULL;
    int count = 0;
    int rc;

    if (!x3_lmdb_is_available() || !account || !entries_out) {
        return LMDB_ERROR;
    }

    *entries_out = NULL;

    /* Build prefix: "account\0" */
    size_t prefix_len = strlen(account) + 1;
    snprintf(prefix, sizeof(prefix), "%s", account);
    prefix[prefix_len - 1] = '\0';

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_cursor_open(txn, dbi_accounts, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Position cursor at prefix */
    mkey.mv_size = prefix_len;
    mkey.mv_data = prefix;

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_SET_RANGE);
    while (rc == 0) {
        /* Check if key still starts with our prefix */
        if (mkey.mv_size < prefix_len ||
            memcmp(mkey.mv_data, prefix, prefix_len - 1) != 0) {
            break;
        }

        /* Extract the key part after "account\0" */
        const char *keystart = (const char *)mkey.mv_data + prefix_len;
        size_t keylen = mkey.mv_size - prefix_len;

        /* Create entry with raw data */
        struct lmdb_raw_metadata_entry *entry = malloc(sizeof(*entry));
        if (!entry) {
            break;
        }

        entry->key = strndup(keystart, keylen);
        entry->raw_len = mdata.mv_size;
        entry->raw_value = malloc(mdata.mv_size);
        if (!entry->raw_value) {
            free(entry->key);
            free(entry);
            break;
        }
        memcpy(entry->raw_value, mdata.mv_data, mdata.mv_size);

        /* Check if data is compressed (ZSTD magic bytes) */
#ifdef WITH_ZSTD
        entry->is_compressed = x3_is_compressed(entry->raw_value, entry->raw_len);
#else
        entry->is_compressed = 0;
#endif
        entry->next = NULL;

        if (tail) {
            tail->next = entry;
        } else {
            head = entry;
        }
        tail = entry;
        count++;

        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
    }

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    *entries_out = head;
    return count;
}

void x3_lmdb_free_raw_entries(struct lmdb_raw_metadata_entry *entries)
{
    struct lmdb_raw_metadata_entry *entry, *next;

    for (entry = entries; entry; entry = next) {
        next = entry->next;
        free(entry->key);
        free(entry->raw_value);
        free(entry);
    }
}

/* ========== Channel Metadata ========== */

int x3_lmdb_channel_get(const char *channel, const char *key, char *value)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !channel || !key || !value) {
        return LMDB_ERROR;
    }

    /* Build composite key: "channel\0key" */
    snprintf(keybuf, sizeof(keybuf), "%s", channel);
    size_t channel_len = strlen(channel);
    keybuf[channel_len] = '\0';
    strncpy(keybuf + channel_len + 1, key, sizeof(keybuf) - channel_len - 2);

    mkey.mv_size = channel_len + 1 + strlen(key) + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_get(txn, dbi_channels, &mkey, &mdata);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Decompress if needed, then copy value */
#ifdef WITH_ZSTD
    {
        unsigned char decompressed[LMDB_MAX_VALUE_SIZE];
        size_t decompressed_len;

        if (x3_decompress(mdata.mv_data, mdata.mv_size,
                          decompressed, sizeof(decompressed) - 1, &decompressed_len) >= 0) {
            memcpy(value, decompressed, decompressed_len);
            value[decompressed_len] = '\0';
        } else {
            return LMDB_ERROR;
        }
    }
#else
    size_t copylen = mdata.mv_size < LMDB_MAX_VALUE_SIZE ? mdata.mv_size : LMDB_MAX_VALUE_SIZE - 1;
    memcpy(value, mdata.mv_data, copylen);
    value[copylen] = '\0';
#endif

    return LMDB_SUCCESS;
}

int x3_lmdb_channel_set(const char *channel, const char *key, const char *value)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !channel || !key) {
        return LMDB_ERROR;
    }

    /* Build composite key: "channel\0key" */
    snprintf(keybuf, sizeof(keybuf), "%s", channel);
    size_t channel_len = strlen(channel);
    keybuf[channel_len] = '\0';
    strncpy(keybuf + channel_len + 1, key, sizeof(keybuf) - channel_len - 2);

    mkey.mv_size = channel_len + 1 + strlen(key) + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    if (value) {
#ifdef WITH_ZSTD
        unsigned char compressed[LMDB_MAX_VALUE_SIZE];
        size_t compressed_len;
        size_t value_len = strlen(value) + 1;

        if (x3_compress((const unsigned char *)value, value_len,
                        compressed, sizeof(compressed), &compressed_len) >= 0) {
            mdata.mv_size = compressed_len;
            mdata.mv_data = compressed;
        } else {
            mdata.mv_size = value_len;
            mdata.mv_data = (void *)value;
        }
#else
        mdata.mv_size = strlen(value) + 1;
        mdata.mv_data = (void *)value;
#endif
        rc = mdb_put(txn, dbi_channels, &mkey, &mdata, 0);
    } else {
        rc = mdb_del(txn, dbi_channels, &mkey, NULL);
        if (rc == MDB_NOTFOUND) {
            rc = 0;
        }
    }

    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_channel_delete(const char *channel, const char *key)
{
    return x3_lmdb_channel_set(channel, key, NULL);
}

int x3_lmdb_channel_list(const char *channel, struct lmdb_metadata_entry **entries_out)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    char prefix[LMDB_KEY_BUFFER_SIZE];
    struct lmdb_metadata_entry *head = NULL, *tail = NULL;
    int count = 0;
    int rc;

    if (!x3_lmdb_is_available() || !channel || !entries_out) {
        return LMDB_ERROR;
    }

    *entries_out = NULL;

    size_t prefix_len = strlen(channel) + 1;
    snprintf(prefix, sizeof(prefix), "%s", channel);
    prefix[prefix_len - 1] = '\0';

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_cursor_open(txn, dbi_channels, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    mkey.mv_size = prefix_len;
    mkey.mv_data = prefix;

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_SET_RANGE);
    while (rc == 0) {
        if (mkey.mv_size < prefix_len ||
            memcmp(mkey.mv_data, prefix, prefix_len - 1) != 0) {
            break;
        }

        const char *keystart = (const char *)mkey.mv_data + prefix_len;
        size_t keylen = mkey.mv_size - prefix_len;

        struct lmdb_metadata_entry *entry = malloc(sizeof(*entry));
        if (!entry) {
            break;
        }

        entry->key = strndup(keystart, keylen);
        entry->value = strndup(mdata.mv_data, mdata.mv_size);
        entry->next = NULL;

        if (tail) {
            tail->next = entry;
        } else {
            head = entry;
        }
        tail = entry;
        count++;

        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
    }

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    *entries_out = head;
    return count;
}

int x3_lmdb_channel_clear(const char *channel)
{
    struct lmdb_metadata_entry *entries, *entry;
    int count;

    count = x3_lmdb_channel_list(channel, &entries);
    if (count <= 0) {
        return count;
    }

    for (entry = entries; entry; entry = entry->next) {
        x3_lmdb_channel_delete(channel, entry->key);
    }

    x3_lmdb_free_entries(entries);
    return count;
}

/* ========== TTL Helpers ========== */

/**
 * Encode a value with optional TTL prefix.
 * Format: [T:timestamp:][P:]value
 * @param buf Output buffer
 * @param bufsize Size of output buffer
 * @param value Original value (may include P: prefix)
 * @param expires Expiry timestamp (0 = no expiry)
 * @return Length of encoded string, or -1 on error
 */
static int encode_ttl_value(char *buf, size_t bufsize, const char *value, time_t expires)
{
    if (!buf || bufsize == 0) {
        return -1;
    }

    if (expires > 0) {
        /* Format: T:<timestamp>:<value> */
        int len = snprintf(buf, bufsize, "T:%ld:%s", (long)expires, value ? value : "");
        if (len < 0 || (size_t)len >= bufsize) {
            return -1;
        }
        return len;
    } else {
        /* No TTL, just copy value as-is */
        if (value) {
            size_t len = strlen(value);
            if (len >= bufsize) {
                return -1;
            }
            memcpy(buf, value, len + 1);
            return (int)len;
        } else {
            buf[0] = '\0';
            return 0;
        }
    }
}

/**
 * Decode a value that may have TTL prefix.
 * @param stored Stored value from LMDB
 * @param value_out Buffer for extracted value (without T: prefix)
 * @param value_size Size of value_out buffer
 * @param expires_out Output for expiry timestamp (can be NULL, 0 = no expiry)
 * @return 0 on success, -1 on error
 */
static int decode_ttl_value(const char *stored, char *value_out, size_t value_size, time_t *expires_out)
{
    if (!stored || !value_out || value_size == 0) {
        return -1;
    }

    if (expires_out) {
        *expires_out = 0;
    }

    /* Check for T: prefix */
    if (stored[0] == 'T' && stored[1] == ':') {
        /* Parse timestamp */
        const char *ts_start = stored + 2;
        char *colon = strchr(ts_start, ':');
        if (colon) {
            long ts = strtol(ts_start, NULL, 10);
            if (expires_out) {
                *expires_out = (time_t)ts;
            }
            /* Copy the value after the second colon */
            const char *value_start = colon + 1;
            size_t len = strlen(value_start);
            if (len >= value_size) {
                len = value_size - 1;
            }
            memcpy(value_out, value_start, len);
            value_out[len] = '\0';
            return 0;
        }
    }

    /* No T: prefix - copy as-is */
    size_t len = strlen(stored);
    if (len >= value_size) {
        len = value_size - 1;
    }
    memcpy(value_out, stored, len);
    value_out[len] = '\0';
    return 0;
}

/**
 * Check if a stored value is expired.
 * @param stored Stored value from LMDB
 * @return 1 if expired, 0 if not expired or no TTL
 */
static int is_value_expired(const char *stored)
{
    time_t expires = 0;
    char dummy[16];

    if (decode_ttl_value(stored, dummy, sizeof(dummy), &expires) != 0) {
        return 0;
    }

    if (expires > 0 && expires <= time(NULL)) {
        return 1;
    }

    return 0;
}

/* ========== Account Metadata with TTL ========== */

int x3_lmdb_account_set_ex(const char *account, const char *key,
                           const char *value, time_t expires)
{
    char encoded[LMDB_MAX_VALUE_SIZE];

    if (!account || !key) {
        return LMDB_ERROR;
    }

    if (value) {
        if (encode_ttl_value(encoded, sizeof(encoded), value, expires) < 0) {
            return LMDB_ERROR;
        }
        return x3_lmdb_account_set(account, key, encoded);
    } else {
        return x3_lmdb_account_set(account, key, NULL);
    }
}

int x3_lmdb_account_get_ex(const char *account, const char *key,
                           char *value, time_t *expires_out)
{
    char stored[LMDB_MAX_VALUE_SIZE];
    int rc;

    if (!account || !key || !value) {
        return LMDB_ERROR;
    }

    rc = x3_lmdb_account_get(account, key, stored);
    if (rc != LMDB_SUCCESS) {
        return rc;
    }

    /* Check if expired */
    if (is_value_expired(stored)) {
        /* Auto-delete expired entry */
        x3_lmdb_account_delete(account, key);
        return LMDB_EXPIRED;
    }

    /* Decode the value */
    if (decode_ttl_value(stored, value, LMDB_MAX_VALUE_SIZE, expires_out) != 0) {
        return LMDB_ERROR;
    }

    return LMDB_SUCCESS;
}

/* ========== Channel Metadata with TTL ========== */

int x3_lmdb_channel_set_ex(const char *channel, const char *key,
                           const char *value, time_t expires)
{
    char encoded[LMDB_MAX_VALUE_SIZE];

    if (!channel || !key) {
        return LMDB_ERROR;
    }

    if (value) {
        if (encode_ttl_value(encoded, sizeof(encoded), value, expires) < 0) {
            return LMDB_ERROR;
        }
        return x3_lmdb_channel_set(channel, key, encoded);
    } else {
        return x3_lmdb_channel_set(channel, key, NULL);
    }
}

int x3_lmdb_channel_get_ex(const char *channel, const char *key,
                           char *value, time_t *expires_out)
{
    char stored[LMDB_MAX_VALUE_SIZE];
    int rc;

    if (!channel || !key || !value) {
        return LMDB_ERROR;
    }

    rc = x3_lmdb_channel_get(channel, key, stored);
    if (rc != LMDB_SUCCESS) {
        return rc;
    }

    /* Check if expired */
    if (is_value_expired(stored)) {
        /* Auto-delete expired entry */
        x3_lmdb_channel_delete(channel, key);
        return LMDB_EXPIRED;
    }

    /* Decode the value */
    if (decode_ttl_value(stored, value, LMDB_MAX_VALUE_SIZE, expires_out) != 0) {
        return LMDB_ERROR;
    }

    return LMDB_SUCCESS;
}

/* ========== Purge Expired Entries ========== */

/**
 * Helper to parse composite key "target\0key" and propagate deletion to IRCd.
 * @param key_data Pointer to key data
 * @param key_size Size of key data
 */
static void propagate_metadata_deletion(const void *key_data, size_t key_size)
{
    const char *data = (const char *)key_data;
    const char *target;
    const char *meta_key;
    size_t i;

    /* Find the NUL separator between target and metadata key */
    for (i = 0; i < key_size; i++) {
        if (data[i] == '\0') {
            break;
        }
    }

    if (i >= key_size - 1) {
        /* No separator found or no key after separator */
        return;
    }

    target = data;                /* Points to start (target name) */
    meta_key = data + i + 1;      /* Points to after NUL (metadata key) */

    /* Propagate deletion to IRCd - NULL value signals deletion */
    irc_metadata(target, meta_key, NULL, 0);

    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Propagated expired metadata deletion: %s/%s",
               target, meta_key);
}

int x3_lmdb_metadata_purge_expired(void)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    int count = 0;
    int propagated = 0;
    int rc;

    if (!x3_lmdb_is_available()) {
        return LMDB_ERROR;
    }

    /* Purge accounts database */
    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_cursor_open(txn, dbi_accounts, &cursor);
    if (rc == 0) {
        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_FIRST);
        while (rc == 0) {
            const char *stored = (const char *)mdata.mv_data;
            if (is_value_expired(stored)) {
                /* Propagate deletion to IRCd before removing from LMDB */
                propagate_metadata_deletion(mkey.mv_data, mkey.mv_size);
                propagated++;
                mdb_cursor_del(cursor, 0);
                count++;
            }
            rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
        }
        mdb_cursor_close(cursor);
    }

    /* Purge channels database */
    rc = mdb_cursor_open(txn, dbi_channels, &cursor);
    if (rc == 0) {
        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_FIRST);
        while (rc == 0) {
            const char *stored = (const char *)mdata.mv_data;
            if (is_value_expired(stored)) {
                /* Propagate deletion to IRCd before removing from LMDB */
                propagate_metadata_deletion(mkey.mv_data, mkey.mv_size);
                propagated++;
                mdb_cursor_del(cursor, 0);
                count++;
            }
            rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
        }
        mdb_cursor_close(cursor);
    }

    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    if (count > 0) {
        log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Purged %d expired metadata entries (%d propagated to IRCd)",
                   count, propagated);
    }

    return count;
}

/* ========== Utility Functions ========== */

void x3_lmdb_free_entries(struct lmdb_metadata_entry *entries)
{
    struct lmdb_metadata_entry *entry, *next;

    for (entry = entries; entry; entry = next) {
        next = entry->next;
        free(entry->key);
        free(entry->value);
        free(entry);
    }
}

int x3_lmdb_sync(int force)
{
    int rc;

    if (!x3_lmdb_is_available()) {
        return LMDB_ERROR;
    }

    rc = mdb_env_sync(lmdb_env, force);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

/* ========== Generic Key-Value Operations ========== */

/**
 * Helper to resolve database name to dbi handle
 */
static int resolve_dbi(const char *db, MDB_dbi *dbi_out)
{
    if (!db || !dbi_out) {
        return LMDB_ERROR;
    }

    if (strcmp(db, LMDB_DB_ACCOUNTS) == 0) {
        *dbi_out = dbi_accounts;
    } else if (strcmp(db, LMDB_DB_CHANNELS) == 0) {
        *dbi_out = dbi_channels;
    } else if (strcmp(db, LMDB_DB_METADATA) == 0) {
        *dbi_out = dbi_metadata;
    } else {
        return LMDB_ERROR;
    }
    return LMDB_SUCCESS;
}

int x3_lmdb_get(const char *db, const char *key, char *value, size_t value_size)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    MDB_dbi dbi;
    int rc;

    if (!x3_lmdb_is_available() || !db || !key || !value || value_size == 0) {
        return LMDB_ERROR;
    }

    if (resolve_dbi(db, &dbi) != LMDB_SUCCESS) {
        return LMDB_ERROR;
    }

    mkey.mv_size = strlen(key) + 1;
    mkey.mv_data = (void *)key;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_get(txn, dbi, &mkey, &mdata);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Copy value, ensuring null termination */
    size_t copy_len = mdata.mv_size < value_size ? mdata.mv_size : value_size - 1;
    memcpy(value, mdata.mv_data, copy_len);
    value[copy_len] = '\0';

    return LMDB_SUCCESS;
}

int x3_lmdb_set(const char *db, const char *key, const char *value)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    MDB_dbi dbi;
    int rc;

    if (!x3_lmdb_is_available() || !db || !key) {
        return LMDB_ERROR;
    }

    if (resolve_dbi(db, &dbi) != LMDB_SUCCESS) {
        return LMDB_ERROR;
    }

    /* NULL value means delete */
    if (!value) {
        return x3_lmdb_delete(db, key);
    }

    mkey.mv_size = strlen(key) + 1;
    mkey.mv_data = (void *)key;
    mdata.mv_size = strlen(value) + 1;
    mdata.mv_data = (void *)value;

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_put(txn, dbi, &mkey, &mdata, 0);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_delete(const char *db, const char *key)
{
    MDB_txn *txn;
    MDB_val mkey;
    MDB_dbi dbi;
    int rc;

    if (!x3_lmdb_is_available() || !db || !key) {
        return LMDB_ERROR;
    }

    if (resolve_dbi(db, &dbi) != LMDB_SUCCESS) {
        return LMDB_ERROR;
    }

    mkey.mv_size = strlen(key) + 1;
    mkey.mv_data = (void *)key;

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_del(txn, dbi, &mkey, NULL);
    if (rc == MDB_NOTFOUND) {
        mdb_txn_abort(txn);
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_stats(const char *db, size_t *entries_out, size_t *size_out)
{
    MDB_txn *txn;
    MDB_stat stat;
    MDB_dbi dbi;
    int rc;

    if (!x3_lmdb_is_available()) {
        return LMDB_ERROR;
    }

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    if (db == NULL) {
        /* Environment stats */
        MDB_envinfo info;
        rc = mdb_env_info(lmdb_env, &info);
        if (rc == 0) {
            rc = mdb_env_stat(lmdb_env, &stat);
        }
        mdb_txn_abort(txn);

        if (rc != 0) {
            return LMDB_ERROR;
        }

        if (entries_out) {
            *entries_out = stat.ms_entries;
        }
        if (size_out) {
            *size_out = info.me_mapsize;
        }
    } else {
        /* Specific database stats */
        if (strcmp(db, LMDB_DB_ACCOUNTS) == 0) {
            dbi = dbi_accounts;
        } else if (strcmp(db, LMDB_DB_CHANNELS) == 0) {
            dbi = dbi_channels;
        } else if (strcmp(db, LMDB_DB_METADATA) == 0) {
            dbi = dbi_metadata;
        } else {
            mdb_txn_abort(txn);
            return LMDB_ERROR;
        }

        rc = mdb_stat(txn, dbi, &stat);
        mdb_txn_abort(txn);

        if (rc != 0) {
            return LMDB_ERROR;
        }

        if (entries_out) {
            *entries_out = stat.ms_entries;
        }
        if (size_out) {
            *size_out = stat.ms_psize * (stat.ms_branch_pages + stat.ms_leaf_pages + stat.ms_overflow_pages);
        }
    }

    return LMDB_SUCCESS;
}

/* ========== Channel Access (Keycloak Group Sync) ========== */

int x3_lmdb_chanaccess_get(const char *channel, const char *account, unsigned short *access_out)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !channel || !account || !access_out) {
        return LMDB_ERROR;
    }

    /* Build composite key: "chanaccess:<channel>\0<account>" */
    size_t prefix_len = strlen(LMDB_PREFIX_CHANACCESS);
    size_t channel_len = strlen(channel);
    size_t account_len = strlen(account);

    if (prefix_len + channel_len + 1 + account_len + 1 > sizeof(keybuf)) {
        return LMDB_ERROR;
    }

    memcpy(keybuf, LMDB_PREFIX_CHANACCESS, prefix_len);
    memcpy(keybuf + prefix_len, channel, channel_len);
    keybuf[prefix_len + channel_len] = '\0';
    memcpy(keybuf + prefix_len + channel_len + 1, account, account_len + 1);

    mkey.mv_size = prefix_len + channel_len + 1 + account_len + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_get(txn, dbi_metadata, &mkey, &mdata);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Parse access level from stored value (format: "access" or "access:timestamp") */
    *access_out = (unsigned short)strtol((const char *)mdata.mv_data, NULL, 10);
    return LMDB_SUCCESS;
}

int x3_lmdb_chanaccess_get_ex(const char *channel, const char *account,
                               unsigned short *access_out, time_t *timestamp_out)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    char *colon;
    int rc;

    if (!x3_lmdb_is_available() || !channel || !account || !access_out) {
        return LMDB_ERROR;
    }

    /* Build composite key: "chanaccess:<channel>\0<account>" */
    size_t prefix_len = strlen(LMDB_PREFIX_CHANACCESS);
    size_t channel_len = strlen(channel);
    size_t account_len = strlen(account);

    if (prefix_len + channel_len + 1 + account_len + 1 > sizeof(keybuf)) {
        return LMDB_ERROR;
    }

    memcpy(keybuf, LMDB_PREFIX_CHANACCESS, prefix_len);
    memcpy(keybuf + prefix_len, channel, channel_len);
    keybuf[prefix_len + channel_len] = '\0';
    memcpy(keybuf + prefix_len + channel_len + 1, account, account_len + 1);

    mkey.mv_size = prefix_len + channel_len + 1 + account_len + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_get(txn, dbi_metadata, &mkey, &mdata);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Parse format: "access" or "access:timestamp" */
    *access_out = (unsigned short)strtol((const char *)mdata.mv_data, NULL, 10);

    if (timestamp_out) {
        colon = strchr((const char *)mdata.mv_data, ':');
        if (colon) {
            *timestamp_out = (time_t)strtol(colon + 1, NULL, 10);
        } else {
            *timestamp_out = 0;  /* No timestamp - old format entry */
        }
    }

    return LMDB_SUCCESS;
}

int x3_lmdb_chanaccess_set(const char *channel, const char *account, unsigned short access)
{
    /* Default: store with current timestamp */
    return x3_lmdb_chanaccess_set_ex(channel, account, access, time(NULL));
}

int x3_lmdb_chanaccess_set_ex(const char *channel, const char *account,
                               unsigned short access, time_t timestamp)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    char valuebuf[32];  /* Increased size for "access:timestamp" format */
    int rc;

    if (!x3_lmdb_is_available() || !channel || !account) {
        return LMDB_ERROR;
    }

    /* Build composite key: "chanaccess:<channel>\0<account>" */
    size_t prefix_len = strlen(LMDB_PREFIX_CHANACCESS);
    size_t channel_len = strlen(channel);
    size_t account_len = strlen(account);

    if (prefix_len + channel_len + 1 + account_len + 1 > sizeof(keybuf)) {
        return LMDB_ERROR;
    }

    memcpy(keybuf, LMDB_PREFIX_CHANACCESS, prefix_len);
    memcpy(keybuf + prefix_len, channel, channel_len);
    keybuf[prefix_len + channel_len] = '\0';
    memcpy(keybuf + prefix_len + channel_len + 1, account, account_len + 1);

    mkey.mv_size = prefix_len + channel_len + 1 + account_len + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    if (access > 0) {
        /* Store as "access:timestamp" */
        snprintf(valuebuf, sizeof(valuebuf), "%u:%ld", access, (long)timestamp);
        mdata.mv_size = strlen(valuebuf) + 1;
        mdata.mv_data = valuebuf;
        rc = mdb_put(txn, dbi_metadata, &mkey, &mdata, 0);
    } else {
        /* Access 0 means delete */
        rc = mdb_del(txn, dbi_metadata, &mkey, NULL);
        if (rc == MDB_NOTFOUND) {
            rc = 0;
        }
    }

    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_chanaccess_delete(const char *channel, const char *account)
{
    return x3_lmdb_chanaccess_set(channel, account, 0);
}

int x3_lmdb_chanaccess_list(const char *channel, struct lmdb_chanaccess_entry **entries_out)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    char prefix[LMDB_KEY_BUFFER_SIZE];
    struct lmdb_chanaccess_entry *head = NULL, *tail = NULL;
    int count = 0;
    int rc;

    if (!x3_lmdb_is_available() || !channel || !entries_out) {
        return LMDB_ERROR;
    }

    *entries_out = NULL;

    /* Build prefix: "chanaccess:<channel>\0" */
    size_t chanaccess_len = strlen(LMDB_PREFIX_CHANACCESS);
    size_t channel_len = strlen(channel);
    size_t prefix_len = chanaccess_len + channel_len + 1;

    if (prefix_len > sizeof(prefix)) {
        return LMDB_ERROR;
    }

    memcpy(prefix, LMDB_PREFIX_CHANACCESS, chanaccess_len);
    memcpy(prefix + chanaccess_len, channel, channel_len);
    prefix[chanaccess_len + channel_len] = '\0';

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_cursor_open(txn, dbi_metadata, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    mkey.mv_size = prefix_len;
    mkey.mv_data = prefix;

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_SET_RANGE);
    while (rc == 0) {
        /* Check if key still starts with our prefix */
        if (mkey.mv_size < prefix_len ||
            memcmp(mkey.mv_data, prefix, prefix_len) != 0) {
            break;
        }

        /* Extract the account part after "chanaccess:<channel>\0" */
        const char *accountstart = (const char *)mkey.mv_data + prefix_len;
        size_t accountlen = mkey.mv_size - prefix_len - 1; /* -1 for null terminator */

        /* Create entry */
        struct lmdb_chanaccess_entry *entry = malloc(sizeof(*entry));
        if (!entry) {
            break;
        }

        entry->channel = strdup(channel);
        entry->account = strndup(accountstart, accountlen);
        entry->access = (unsigned short)atoi((const char *)mdata.mv_data);
        entry->next = NULL;

        if (tail) {
            tail->next = entry;
        } else {
            head = entry;
        }
        tail = entry;
        count++;

        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
    }

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    *entries_out = head;
    return count;
}

int x3_lmdb_chanaccess_list_account(const char *account, struct lmdb_chanaccess_entry **entries_out)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    struct lmdb_chanaccess_entry *head = NULL, *tail = NULL;
    int count = 0;
    int rc;
    size_t chanaccess_len = strlen(LMDB_PREFIX_CHANACCESS);

    if (!x3_lmdb_is_available() || !account || !entries_out) {
        return LMDB_ERROR;
    }

    *entries_out = NULL;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_cursor_open(txn, dbi_metadata, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Scan all chanaccess entries looking for matching account
     * Key format: "chanaccess:<channel>\0<account>\0"
     */
    mkey.mv_size = chanaccess_len;
    mkey.mv_data = (void *)LMDB_PREFIX_CHANACCESS;

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_SET_RANGE);
    while (rc == 0) {
        /* Check if key starts with "chanaccess:" prefix */
        if (mkey.mv_size < chanaccess_len ||
            memcmp(mkey.mv_data, LMDB_PREFIX_CHANACCESS, chanaccess_len) != 0) {
            break;
        }

        /* Parse key: find the null separating channel from account */
        const char *keydata = (const char *)mkey.mv_data;
        const char *channel_start = keydata + chanaccess_len;
        const char *null_pos = memchr(channel_start, '\0', mkey.mv_size - chanaccess_len);

        if (null_pos && null_pos < keydata + mkey.mv_size - 1) {
            const char *account_start = null_pos + 1;
            size_t channel_len_found = null_pos - channel_start;

            /* Check if account matches */
            if (strcmp(account_start, account) == 0) {
                struct lmdb_chanaccess_entry *entry = malloc(sizeof(*entry));
                if (!entry) {
                    break;
                }

                entry->channel = strndup(channel_start, channel_len_found);
                entry->account = strdup(account);
                entry->access = (unsigned short)atoi((const char *)mdata.mv_data);
                entry->next = NULL;

                if (tail) {
                    tail->next = entry;
                } else {
                    head = entry;
                }
                tail = entry;
                count++;
            }
        }

        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
    }

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    *entries_out = head;
    return count;
}

int x3_lmdb_chanaccess_clear(const char *channel)
{
    struct lmdb_chanaccess_entry *entries, *entry;
    int count;

    count = x3_lmdb_chanaccess_list(channel, &entries);
    if (count <= 0) {
        return count;
    }

    for (entry = entries; entry; entry = entry->next) {
        x3_lmdb_chanaccess_delete(channel, entry->account);
    }

    x3_lmdb_free_chanaccess_entries(entries);
    return count;
}

void x3_lmdb_free_chanaccess_entries(struct lmdb_chanaccess_entry *entries)
{
    struct lmdb_chanaccess_entry *entry, *next;

    for (entry = entries; entry; entry = next) {
        next = entry->next;
        free(entry->channel);
        free(entry->account);
        free(entry);
    }
}

/* ========== Activity Data (lastseen/last_present) ========== */

int x3_lmdb_activity_get(const char *account, time_t *lastseen_out, time_t *last_present_out)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;
    time_t expires = 0;

    if (!x3_lmdb_is_available() || !account) {
        return LMDB_ERROR;
    }

    /* Build key: "activity:<account>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_ACTIVITY, account);

    mkey.mv_size = strlen(keybuf) + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_get(txn, dbi_metadata, &mkey, &mdata);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Parse stored value - format: "T:<expiry>:<lastseen>:<last_present>" or "<lastseen>:<last_present>" */
    const char *stored = (const char *)mdata.mv_data;
    const char *data_start = stored;

    /* Check for TTL prefix */
    if (stored[0] == 'T' && stored[1] == ':') {
        const char *ts_end = strchr(stored + 2, ':');
        if (ts_end) {
            expires = (time_t)strtol(stored + 2, NULL, 10);
            data_start = ts_end + 1;

            /* Check if expired */
            if (expires > 0 && expires <= time(NULL)) {
                /* Auto-delete expired entry */
                x3_lmdb_activity_delete(account);
                return LMDB_EXPIRED;
            }
        }
    }

    /* Parse lastseen:last_present */
    if (lastseen_out) {
        *lastseen_out = (time_t)strtol(data_start, NULL, 10);
    }
    if (last_present_out) {
        const char *colon = strchr(data_start, ':');
        if (colon) {
            *last_present_out = (time_t)strtol(colon + 1, NULL, 10);
        } else {
            *last_present_out = 0;
        }
    }

    return LMDB_SUCCESS;
}

int x3_lmdb_activity_set(const char *account, time_t lastseen, time_t last_present)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    char valuebuf[128];
    time_t existing_lastseen = 0, existing_last_present = 0;
    time_t expires;
    int rc;

    if (!x3_lmdb_is_available() || !account) {
        return LMDB_ERROR;
    }

    /* If either timestamp is 0, try to preserve existing value */
    if (lastseen == 0 || last_present == 0) {
        if (x3_lmdb_activity_get(account, &existing_lastseen, &existing_last_present) == LMDB_SUCCESS) {
            if (lastseen == 0) {
                lastseen = existing_lastseen;
            }
            if (last_present == 0) {
                last_present = existing_last_present;
            }
        }
    }

    /* Build key: "activity:<account>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_ACTIVITY, account);

    mkey.mv_size = strlen(keybuf) + 1;
    mkey.mv_data = keybuf;

    /* Calculate expiry (30 days from now) */
    expires = time(NULL) + LMDB_ACTIVITY_TTL_SECS;

    /* Build value: "T:<expiry>:<lastseen>:<last_present>" */
    snprintf(valuebuf, sizeof(valuebuf), "T:%ld:%ld:%ld",
             (long)expires, (long)lastseen, (long)last_present);

    mdata.mv_size = strlen(valuebuf) + 1;
    mdata.mv_data = valuebuf;

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_put(txn, dbi_metadata, &mkey, &mdata, 0);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    if (rc == 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Set activity for %s: lastseen=%ld, last_present=%ld, expires=%ld",
                   account, (long)lastseen, (long)last_present, (long)expires);
    }

    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_activity_touch(const char *account)
{
    time_t lastseen = 0, last_present = 0;
    int rc;

    if (!x3_lmdb_is_available() || !account) {
        return LMDB_ERROR;
    }

    /* Get current values */
    rc = x3_lmdb_activity_get(account, &lastseen, &last_present);
    if (rc != LMDB_SUCCESS) {
        return rc;  /* Entry doesn't exist or other error */
    }

    /* Re-set with same values - this refreshes the TTL */
    return x3_lmdb_activity_set(account, lastseen, last_present);
}

int x3_lmdb_activity_delete(const char *account)
{
    MDB_txn *txn;
    MDB_val mkey;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !account) {
        return LMDB_ERROR;
    }

    /* Build key: "activity:<account>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_ACTIVITY, account);

    mkey.mv_size = strlen(keybuf) + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_del(txn, dbi_metadata, &mkey, NULL);
    if (rc == MDB_NOTFOUND) {
        mdb_txn_abort(txn);
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

/* ========== Fingerprint Storage ========== */

int x3_lmdb_fingerprint_get(const char *fingerprint, char *account_out,
                            time_t *registered_out, time_t *last_used_out,
                            time_t *expires_out)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;
    time_t expires = 0;

    if (!x3_lmdb_is_available() || !fingerprint) {
        return LMDB_ERROR;
    }

    /* Build key: "fp:<fingerprint>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_FINGERPRINT, fingerprint);

    mkey.mv_size = strlen(keybuf) + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_get(txn, dbi_metadata, &mkey, &mdata);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Parse stored value - format: "T:<expiry>:<account>:<registered>:<last_used>" */
    const char *stored = (const char *)mdata.mv_data;
    const char *data_start = stored;

    /* Check for TTL prefix */
    if (stored[0] == 'T' && stored[1] == ':') {
        const char *ts_end = strchr(stored + 2, ':');
        if (ts_end) {
            expires = (time_t)strtol(stored + 2, NULL, 10);
            data_start = ts_end + 1;

            /* Check if expired */
            if (expires > 0 && expires <= time(NULL)) {
                /* Auto-delete expired entry */
                x3_lmdb_fingerprint_delete(fingerprint);
                return LMDB_EXPIRED;
            }
        }
    }

    /* Parse account:registered:last_used */
    const char *colon1 = strchr(data_start, ':');
    const char *colon2 = colon1 ? strchr(colon1 + 1, ':') : NULL;

    if (account_out) {
        if (colon1) {
            size_t len = colon1 - data_start;
            if (len > 63) len = 63;
            memcpy(account_out, data_start, len);
            account_out[len] = '\0';
        } else {
            /* Legacy format: just username */
            strncpy(account_out, data_start, 63);
            account_out[63] = '\0';
        }
    }

    if (registered_out) {
        *registered_out = colon1 ? (time_t)strtol(colon1 + 1, NULL, 10) : 0;
    }

    if (last_used_out) {
        *last_used_out = colon2 ? (time_t)strtol(colon2 + 1, NULL, 10) : 0;
    }

    if (expires_out) {
        *expires_out = expires;
    }

    return LMDB_SUCCESS;
}

int x3_lmdb_fingerprint_set(const char *fingerprint, const char *account,
                            time_t registered, time_t last_used)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    char valuebuf[256];
    time_t existing_registered = 0;
    time_t expires;
    int rc;
    time_t now_time = time(NULL);

    if (!x3_lmdb_is_available() || !fingerprint || !account) {
        return LMDB_ERROR;
    }

    /* If registered is 0, try to preserve existing value or use now */
    if (registered == 0) {
        if (x3_lmdb_fingerprint_get(fingerprint, NULL, &existing_registered, NULL, NULL) == LMDB_SUCCESS) {
            registered = existing_registered;
        } else {
            registered = now_time;
        }
    }

    /* If last_used is 0, use current time */
    if (last_used == 0) {
        last_used = now_time;
    }

    /* Build key: "fp:<fingerprint>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_FINGERPRINT, fingerprint);

    mkey.mv_size = strlen(keybuf) + 1;
    mkey.mv_data = keybuf;

    /* Calculate expiry (90 days from now) */
    expires = now_time + LMDB_FINGERPRINT_TTL_SECS;

    /* Build value: "T:<expiry>:<account>:<registered>:<last_used>" */
    snprintf(valuebuf, sizeof(valuebuf), "T:%ld:%s:%ld:%ld",
             (long)expires, account, (long)registered, (long)last_used);

    mdata.mv_size = strlen(valuebuf) + 1;
    mdata.mv_data = valuebuf;

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_put(txn, dbi_metadata, &mkey, &mdata, 0);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    if (rc == 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Set fingerprint %s -> %s (reg=%ld, used=%ld, exp=%ld)",
                   fingerprint, account, (long)registered, (long)last_used, (long)expires);
    }

    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_fingerprint_touch(const char *fingerprint)
{
    char account[64];
    time_t registered = 0;
    time_t now_time = time(NULL);
    int rc;

    if (!x3_lmdb_is_available() || !fingerprint) {
        return LMDB_ERROR;
    }

    /* Get current values */
    rc = x3_lmdb_fingerprint_get(fingerprint, account, &registered, NULL, NULL);
    if (rc != LMDB_SUCCESS) {
        return rc;  /* Entry doesn't exist or other error */
    }

    /* Re-set with updated last_used - this refreshes the TTL */
    return x3_lmdb_fingerprint_set(fingerprint, account, registered, now_time);
}

int x3_lmdb_fingerprint_delete(const char *fingerprint)
{
    MDB_txn *txn;
    MDB_val mkey;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !fingerprint) {
        return LMDB_ERROR;
    }

    /* Build key: "fp:<fingerprint>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_FINGERPRINT, fingerprint);

    mkey.mv_size = strlen(keybuf) + 1;
    mkey.mv_data = keybuf;

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_del(txn, dbi_metadata, &mkey, NULL);
    if (rc == MDB_NOTFOUND) {
        mdb_txn_abort(txn);
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    if (rc == 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Deleted fingerprint %s", fingerprint);
    }
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_fingerprint_list_account(const char *account, struct lmdb_fingerprint_entry **entries_out)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    struct lmdb_fingerprint_entry *head = NULL, *tail = NULL, *entry;
    int rc, count = 0;
    const char *prefix = LMDB_PREFIX_FINGERPRINT;
    size_t prefix_len = strlen(prefix);

    if (!x3_lmdb_is_available() || !account || !entries_out) {
        return LMDB_ERROR;
    }

    *entries_out = NULL;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdb_cursor_open(txn, dbi_metadata, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Iterate all fp: entries and filter by account */
    mkey.mv_size = prefix_len;
    mkey.mv_data = (void *)prefix;

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_SET_RANGE);
    while (rc == 0) {
        const char *key = (const char *)mkey.mv_data;

        /* Check if we're still in fp: prefix */
        if (strncmp(key, prefix, prefix_len) != 0) {
            break;
        }

        /* Parse value to check account */
        const char *stored = (const char *)mdata.mv_data;
        const char *data_start = stored;
        time_t expires = 0, registered = 0, last_used = 0;

        /* Check for TTL prefix */
        if (stored[0] == 'T' && stored[1] == ':') {
            const char *ts_end = strchr(stored + 2, ':');
            if (ts_end) {
                expires = (time_t)strtol(stored + 2, NULL, 10);
                data_start = ts_end + 1;

                /* Skip expired entries */
                if (expires > 0 && expires <= time(NULL)) {
                    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
                    continue;
                }
            }
        }

        /* Parse account:registered:last_used */
        const char *colon1 = strchr(data_start, ':');
        const char *colon2 = colon1 ? strchr(colon1 + 1, ':') : NULL;

        char entry_account[64];
        if (colon1) {
            size_t len = colon1 - data_start;
            if (len > 63) len = 63;
            memcpy(entry_account, data_start, len);
            entry_account[len] = '\0';
            registered = (time_t)strtol(colon1 + 1, NULL, 10);
            if (colon2) {
                last_used = (time_t)strtol(colon2 + 1, NULL, 10);
            }
        } else {
            /* Legacy format */
            strncpy(entry_account, data_start, 63);
            entry_account[63] = '\0';
        }

        /* Check if this fingerprint belongs to the requested account */
        if (strcasecmp(entry_account, account) == 0) {
            entry = malloc(sizeof(*entry));
            if (entry) {
                entry->fingerprint = strdup(key + prefix_len);
                entry->account = strdup(entry_account);
                entry->registered = registered;
                entry->last_used = last_used;
                entry->expires = expires;
                entry->next = NULL;

                if (tail) {
                    tail->next = entry;
                    tail = entry;
                } else {
                    head = tail = entry;
                }
                count++;
            }
        }

        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
    }

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    *entries_out = head;
    return count;
}

void x3_lmdb_free_fingerprint_entries(struct lmdb_fingerprint_entry *entries)
{
    struct lmdb_fingerprint_entry *entry, *next;

    for (entry = entries; entry; entry = next) {
        next = entry->next;
        free(entry->fingerprint);
        free(entry->account);
        free(entry);
    }
}

/* ========== Snapshot/Backup ========== */

#include <dirent.h>
#include <unistd.h>

/* Static storage for snapshot statistics */
static struct lmdb_snapshot_stats snapshot_stats = {0};
static unsigned int snapshot_interval = 0; /* Disabled by default */
static unsigned int snapshot_retention = LMDB_SNAPSHOT_RETENTION_DEFAULT;
static char snapshot_base_path[MAXLEN] = "";

/**
 * Forward declaration for snapshot callback
 */
static void lmdb_snapshot_callback(void *data);

int x3_lmdb_snapshot(const char *backup_path, int compact)
{
    int rc;
    unsigned int flags = compact ? MDB_CP_COMPACT : 0;
    time_t start_time, end_time;
    struct stat st;

    if (!lmdb_initialized || !lmdb_env) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Snapshot failed: LMDB not initialized");
        return LMDB_ERROR;
    }

    if (!backup_path || backup_path[0] == '\0') {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Snapshot failed: Invalid backup path");
        return LMDB_ERROR;
    }

    /* Create backup directory if it doesn't exist */
    if (stat(backup_path, &st) != 0) {
        if (mkdir(backup_path, 0755) != 0 && errno != EEXIST) {
            log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Snapshot failed: Cannot create directory '%s': %s",
                       backup_path, strerror(errno));
            return LMDB_ERROR;
        }
    }

    start_time = time(NULL);

    /* Perform the hot backup using mdb_env_copy2 */
    rc = mdb_env_copy2(lmdb_env, backup_path, flags);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Snapshot failed: %s", mdb_strerror(rc));
        return LMDB_ERROR;
    }

    end_time = time(NULL);

    /* Get size of backup */
    {
        char data_path[MAXLEN];
        snprintf(data_path, sizeof(data_path), "%s/data.mdb", backup_path);
        if (stat(data_path, &st) == 0) {
            snapshot_stats.last_size_bytes = st.st_size;
        }
    }

    /* Update statistics */
    snapshot_stats.last_snapshot = start_time;
    snapshot_stats.last_duration_ms = (end_time - start_time) * 1000;
    strncpy(snapshot_stats.last_path, backup_path, sizeof(snapshot_stats.last_path) - 1);
    snapshot_stats.last_path[sizeof(snapshot_stats.last_path) - 1] = '\0';

    log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Snapshot created at '%s' (%lu bytes, %lu ms, compact=%d)",
               backup_path, (unsigned long)snapshot_stats.last_size_bytes,
               (unsigned long)snapshot_stats.last_duration_ms, compact);

    return LMDB_SUCCESS;
}

int x3_lmdb_snapshot_auto(const char *base_path, int compact, char *path_out)
{
    char snapshot_path[MAXLEN];
    struct tm *tm_info;
    time_t now_time;
    int rc;

    if (!base_path || base_path[0] == '\0') {
        return LMDB_ERROR;
    }

    /* Create base directory if needed */
    {
        struct stat st;
        if (stat(base_path, &st) != 0) {
            if (mkdir(base_path, 0755) != 0 && errno != EEXIST) {
                log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Cannot create base path '%s': %s",
                           base_path, strerror(errno));
                return LMDB_ERROR;
            }
        }
    }

    /* Generate timestamped directory name */
    now_time = time(NULL);
    tm_info = localtime(&now_time);
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/lmdb-%04d%02d%02d%02d%02d",
             base_path,
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min);

    rc = x3_lmdb_snapshot(snapshot_path, compact);

    if (rc == LMDB_SUCCESS && path_out) {
        strncpy(path_out, snapshot_path, 255);
        path_out[255] = '\0';
    }

    /* Cleanup old snapshots if retention is set */
    if (rc == LMDB_SUCCESS && snapshot_retention > 0) {
        x3_lmdb_cleanup_old_snapshots(base_path);
    }

    return rc;
}

const struct lmdb_snapshot_stats *x3_lmdb_get_snapshot_stats(void)
{
    return &snapshot_stats;
}

void x3_lmdb_set_snapshot_interval(unsigned int interval_secs)
{
    unsigned int old_interval = snapshot_interval;
    snapshot_interval = interval_secs;

    if (lmdb_initialized) {
        /* Cancel any existing scheduled snapshot */
        timeq_del(0, lmdb_snapshot_callback, NULL, TIMEQ_IGNORE_WHEN);

        if (interval_secs > 0 && snapshot_base_path[0] != '\0') {
            timeq_add(now + interval_secs, lmdb_snapshot_callback, NULL);
            log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Snapshot job scheduled every %u seconds",
                       interval_secs);
        } else if (old_interval > 0) {
            log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Snapshot job disabled (was %u seconds)",
                       old_interval);
        }
    }
}

void x3_lmdb_set_snapshot_retention(unsigned int count)
{
    snapshot_retention = count;
    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Snapshot retention set to %u", count);
}

/**
 * Compare function for sorting snapshot directories by name (oldest first)
 */
static int snapshot_name_cmp(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

int x3_lmdb_cleanup_old_snapshots(const char *base_path)
{
    DIR *dir;
    struct dirent *entry;
    char **snapshots = NULL;
    unsigned int snapshot_count = 0;
    unsigned int capacity = 64;
    unsigned int i, deleted = 0;

    if (!base_path || snapshot_retention == 0) {
        return 0;
    }

    dir = opendir(base_path);
    if (!dir) {
        return 0;
    }

    /* Allocate array for snapshot names */
    snapshots = malloc(capacity * sizeof(char *));
    if (!snapshots) {
        closedir(dir);
        return 0;
    }

    /* Find all snapshot directories matching pattern lmdb-YYYYMMDDHHMM */
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "lmdb-", 5) == 0 && strlen(entry->d_name) == 17) {
            /* Check if it looks like a valid timestamp */
            int valid = 1;
            for (i = 5; i < 17 && valid; i++) {
                if (entry->d_name[i] < '0' || entry->d_name[i] > '9') {
                    valid = 0;
                }
            }
            if (valid) {
                if (snapshot_count >= capacity) {
                    capacity *= 2;
                    snapshots = realloc(snapshots, capacity * sizeof(char *));
                    if (!snapshots) {
                        closedir(dir);
                        return 0;
                    }
                }
                snapshots[snapshot_count++] = strdup(entry->d_name);
            }
        }
    }
    closedir(dir);

    /* Sort snapshots by name (oldest first since name is timestamped) */
    if (snapshot_count > 0) {
        qsort(snapshots, snapshot_count, sizeof(char *), snapshot_name_cmp);
    }

    /* Delete oldest snapshots beyond retention count */
    while (snapshot_count > snapshot_retention) {
        char full_path[MAXLEN];
        char data_file[MAXLEN];
        char lock_file[MAXLEN];

        snprintf(full_path, sizeof(full_path), "%s/%s", base_path, snapshots[0]);
        snprintf(data_file, sizeof(data_file), "%s/data.mdb", full_path);
        snprintf(lock_file, sizeof(lock_file), "%s/lock.mdb", full_path);

        /* Remove files in the snapshot directory */
        unlink(data_file);
        unlink(lock_file);

        /* Remove the directory */
        if (rmdir(full_path) == 0) {
            log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Deleted old snapshot: %s", snapshots[0]);
            deleted++;
        }

        free(snapshots[0]);
        /* Shift remaining entries */
        for (i = 1; i < snapshot_count; i++) {
            snapshots[i - 1] = snapshots[i];
        }
        snapshot_count--;
    }

    /* Update stats */
    snapshot_stats.snapshots_retained = snapshot_count;

    /* Free remaining snapshot names */
    for (i = 0; i < snapshot_count; i++) {
        free(snapshots[i]);
    }
    free(snapshots);

    if (deleted > 0) {
        log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Cleaned up %u old snapshots, %u retained",
                   deleted, snapshot_count);
    }

    return deleted;
}

/**
 * Timeq callback for scheduled snapshot
 */
static void lmdb_snapshot_callback(UNUSED_ARG(void *data))
{
    char path_out[256];

    if (snapshot_base_path[0] != '\0') {
        x3_lmdb_snapshot_auto(snapshot_base_path, 1, path_out);
    }

    /* Reschedule if interval is non-zero */
    if (snapshot_interval > 0) {
        timeq_add(now + snapshot_interval, lmdb_snapshot_callback, NULL);
    }
}

/* ========== JSON Export ========== */

/**
 * Write JSON-escaped string to file
 */
static void json_write_escaped_string(FILE *fp, const char *str)
{
    fputc('"', fp);
    while (*str) {
        switch (*str) {
            case '"': fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\b': fputs("\\b", fp); break;
            case '\f': fputs("\\f", fp); break;
            case '\n': fputs("\\n", fp); break;
            case '\r': fputs("\\r", fp); break;
            case '\t': fputs("\\t", fp); break;
            default:
                if ((unsigned char)*str < 0x20) {
                    fprintf(fp, "\\u%04x", (unsigned char)*str);
                } else {
                    fputc(*str, fp);
                }
        }
        str++;
    }
    fputc('"', fp);
}

/**
 * Export a single database to JSON object in file
 */
static int json_export_db(FILE *fp, MDB_dbi dbi, const char *db_name, int *first)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    int rc;
    int entry_count = 0;

    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return 0;
    }

    rc = mdb_cursor_open(txn, dbi, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return 0;
    }

    /* Start database object */
    if (!*first) {
        fprintf(fp, ",\n");
    }
    *first = 0;
    fprintf(fp, "    \"%s\": {\n", db_name);

    int first_entry = 1;
    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_FIRST);
    while (rc == 0) {
        char key_str[LMDB_KEY_BUFFER_SIZE];
        char value_str[LMDB_MAX_VALUE_SIZE];

        /* Convert key to printable string (handle embedded nulls) */
        size_t key_len = mkey.mv_size < sizeof(key_str) - 1 ? mkey.mv_size : sizeof(key_str) - 1;
        memcpy(key_str, mkey.mv_data, key_len);
        key_str[key_len] = '\0';

        /* Replace embedded nulls with '|' for composite keys */
        for (size_t i = 0; i < key_len; i++) {
            if (key_str[i] == '\0') key_str[i] = '|';
        }

        /* Decompress and decode value if needed */
#ifdef WITH_ZSTD
        if (x3_is_compressed(mdata.mv_data, mdata.mv_size)) {
            unsigned char decompressed[LMDB_MAX_VALUE_SIZE];
            size_t decompressed_len;
            if (x3_decompress(mdata.mv_data, mdata.mv_size,
                              decompressed, sizeof(decompressed) - 1, &decompressed_len) >= 0) {
                memcpy(value_str, decompressed, decompressed_len);
                value_str[decompressed_len] = '\0';
            } else {
                snprintf(value_str, sizeof(value_str), "<compressed:%zu bytes>", mdata.mv_size);
            }
        } else
#endif
        {
            size_t val_len = mdata.mv_size < sizeof(value_str) - 1 ? mdata.mv_size : sizeof(value_str) - 1;
            memcpy(value_str, mdata.mv_data, val_len);
            value_str[val_len] = '\0';
        }

        /* Write entry */
        if (!first_entry) {
            fprintf(fp, ",\n");
        }
        first_entry = 0;
        fprintf(fp, "      ");
        json_write_escaped_string(fp, key_str);
        fprintf(fp, ": ");
        json_write_escaped_string(fp, value_str);
        entry_count++;

        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
    }

    fprintf(fp, "\n    }");

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    return entry_count;
}

int x3_lmdb_export_json(const char *json_path)
{
    FILE *fp;
    time_t now_time;
    struct tm *tm_info;
    int first = 1;
    int total_entries = 0;

    if (!lmdb_initialized || !lmdb_env) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: JSON export failed: LMDB not initialized");
        return LMDB_ERROR;
    }

    if (!json_path || json_path[0] == '\0') {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: JSON export failed: Invalid path");
        return LMDB_ERROR;
    }

    fp = fopen(json_path, "w");
    if (!fp) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: JSON export failed: Cannot open '%s': %s",
                   json_path, strerror(errno));
        return LMDB_ERROR;
    }

    /* Write JSON header */
    now_time = time(NULL);
    tm_info = localtime(&now_time);

    fprintf(fp, "{\n");
    fprintf(fp, "  \"_metadata\": {\n");
    fprintf(fp, "    \"export_time\": \"%04d-%02d-%02dT%02d:%02d:%02d\",\n",
            tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
            tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    fprintf(fp, "    \"source\": \"x3_lmdb\",\n");
    fprintf(fp, "    \"path\": \"%s\"\n", lmdb_path);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"databases\": {\n");

    /* Export each database */
    total_entries += json_export_db(fp, dbi_accounts, "accounts", &first);
    total_entries += json_export_db(fp, dbi_channels, "channels", &first);
    total_entries += json_export_db(fp, dbi_metadata, "metadata", &first);

    fprintf(fp, "\n  }\n");
    fprintf(fp, "}\n");

    fclose(fp);

    log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: JSON export to '%s' complete (%d entries)",
               json_path, total_entries);

    return LMDB_SUCCESS;
}

int x3_lmdb_export_json_auto(const char *base_path, char *path_out)
{
    char export_path[MAXLEN];
    struct tm *tm_info;
    time_t now_time;
    int rc;

    if (!base_path || base_path[0] == '\0') {
        return LMDB_ERROR;
    }

    /* Create base directory if needed */
    {
        struct stat st;
        if (stat(base_path, &st) != 0) {
            if (mkdir(base_path, 0755) != 0 && errno != EEXIST) {
                log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Cannot create base path '%s': %s",
                           base_path, strerror(errno));
                return LMDB_ERROR;
            }
        }
    }

    /* Generate timestamped filename */
    now_time = time(NULL);
    tm_info = localtime(&now_time);
    snprintf(export_path, sizeof(export_path), "%s/lmdb-export-%04d%02d%02d%02d%02d.json",
             base_path,
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min);

    rc = x3_lmdb_export_json(export_path);

    if (rc == LMDB_SUCCESS && path_out) {
        strncpy(path_out, export_path, 255);
        path_out[255] = '\0';
    }

    return rc;
}

/* ========== TTL Purge Job ========== */

/* Static storage for purge statistics */
static struct lmdb_purge_stats purge_stats = {0};
static unsigned int purge_interval = LMDB_PURGE_INTERVAL_DEFAULT;

/**
 * Helper to purge expired entries from account/channel metadata databases
 * Scans for entries with TTL prefix that have expired
 */
static unsigned long purge_metadata_db(MDB_dbi dbi, const char *db_name)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    unsigned long purged = 0;
    int rc;
    time_t now = time(NULL);
    char value_buf[LMDB_MAX_VALUE_SIZE];
    time_t expires;

    if (!lmdb_initialized) {
        return 0;
    }

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Purge %s: Failed to begin txn: %s",
                   db_name, mdb_strerror(rc));
        return 0;
    }

    rc = mdb_cursor_open(txn, dbi, &cursor);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Purge %s: Failed to open cursor: %s",
                   db_name, mdb_strerror(rc));
        mdb_txn_abort(txn);
        return 0;
    }

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_FIRST);
    while (rc == 0) {
        const char *stored = (const char *)mdata.mv_data;

        /* Check if entry has TTL prefix and is expired */
        if (stored[0] == 'T' && stored[1] == ':') {
            /* Parse expiration time */
            if (decode_ttl_value(stored, value_buf, sizeof(value_buf), &expires) == 0) {
                if (expires > 0 && expires <= now) {
                    /* Entry is expired, delete it */
                    rc = mdb_cursor_del(cursor, 0);
                    if (rc == 0) {
                        purged++;
                    }
                }
            }
        }

        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
    }

    mdb_cursor_close(cursor);

    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Purge %s: Failed to commit: %s",
                   db_name, mdb_strerror(rc));
        return 0;
    }

    if (purged > 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Purged %lu expired entries from %s",
                   purged, db_name);
    }

    return purged;
}

/**
 * Purge expired activity entries (30-day TTL)
 */
static unsigned long purge_activity_entries(void)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    unsigned long purged = 0;
    int rc;
    time_t now = time(NULL);
    const char *prefix = "activity:";
    size_t prefix_len = strlen(prefix);

    if (!lmdb_initialized) {
        return 0;
    }

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return 0;
    }

    rc = mdb_cursor_open(txn, dbi_metadata, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return 0;
    }

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_FIRST);
    while (rc == 0) {
        const char *key = (const char *)mkey.mv_data;

        /* Check if this is an activity entry */
        if (mkey.mv_size > prefix_len && strncmp(key, prefix, prefix_len) == 0) {
            const char *stored = (const char *)mdata.mv_data;

            /* Check for TTL prefix */
            if (stored[0] == 'T' && stored[1] == ':') {
                time_t expires = 0;
                char *colon = strchr(stored + 2, ':');
                if (colon) {
                    expires = (time_t)strtol(stored + 2, NULL, 10);
                    if (expires > 0 && expires <= now) {
                        rc = mdb_cursor_del(cursor, 0);
                        if (rc == 0) {
                            purged++;
                        }
                    }
                }
            }
        }

        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
    }

    mdb_cursor_close(cursor);
    mdb_txn_commit(txn);

    if (purged > 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Purged %lu expired activity entries", purged);
    }

    return purged;
}

/**
 * Purge expired fingerprint entries (90-day TTL)
 */
static unsigned long purge_fingerprint_entries(void)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val mkey, mdata;
    unsigned long purged = 0;
    int rc;
    time_t now = time(NULL);
    const char *prefix = "fp:";
    size_t prefix_len = strlen(prefix);

    if (!lmdb_initialized) {
        return 0;
    }

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return 0;
    }

    rc = mdb_cursor_open(txn, dbi_metadata, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return 0;
    }

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_FIRST);
    while (rc == 0) {
        const char *key = (const char *)mkey.mv_data;

        /* Check if this is a fingerprint entry */
        if (mkey.mv_size > prefix_len && strncmp(key, prefix, prefix_len) == 0) {
            const char *stored = (const char *)mdata.mv_data;

            /* Check for TTL prefix */
            if (stored[0] == 'T' && stored[1] == ':') {
                time_t expires = 0;
                char *colon = strchr(stored + 2, ':');
                if (colon) {
                    expires = (time_t)strtol(stored + 2, NULL, 10);
                    if (expires > 0 && expires <= now) {
                        rc = mdb_cursor_del(cursor, 0);
                        if (rc == 0) {
                            purged++;
                        }
                    }
                }
            }
        }

        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
    }

    mdb_cursor_close(cursor);
    mdb_txn_commit(txn);

    if (purged > 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Purged %lu expired fingerprint entries", purged);
    }

    return purged;
}

/**
 * Timeq callback for scheduled purge job
 */
static void lmdb_purge_callback(UNUSED_ARG(void *data))
{
    struct lmdb_purge_stats stats;

    x3_lmdb_purge_expired(&stats);

    /* Reschedule if interval is non-zero */
    if (purge_interval > 0) {
        timeq_add(now + purge_interval, lmdb_purge_callback, NULL);
    }
}

int x3_lmdb_purge_expired(struct lmdb_purge_stats *stats_out)
{
    struct lmdb_purge_stats stats = {0};
    time_t start_time, end_time;

    if (!lmdb_initialized) {
        if (stats_out) {
            memset(stats_out, 0, sizeof(*stats_out));
        }
        return 0;
    }

    start_time = time(NULL);

    /* Purge expired entries from each category */
    stats.activity_purged = purge_activity_entries();
    stats.fingerprint_purged = purge_fingerprint_entries();
    stats.metadata_purged = purge_metadata_db(dbi_accounts, "accounts");
    stats.channel_purged = purge_metadata_db(dbi_channels, "channels");

    stats.total_purged = stats.activity_purged + stats.fingerprint_purged +
                         stats.metadata_purged + stats.channel_purged;

    end_time = time(NULL);
    stats.last_run = start_time;
    stats.duration_ms = (end_time - start_time) * 1000;

    /* Store in static for later retrieval */
    memcpy(&purge_stats, &stats, sizeof(stats));

    if (stats.total_purged > 0) {
        log_module(MAIN_LOG, LOG_INFO,
                   "x3_lmdb: TTL purge complete: %lu activity, %lu fingerprints, %lu metadata, %lu channel (%lu total)",
                   stats.activity_purged, stats.fingerprint_purged,
                   stats.metadata_purged, stats.channel_purged, stats.total_purged);
    }

    if (stats_out) {
        memcpy(stats_out, &stats, sizeof(stats));
    }

    return (int)stats.total_purged;
}

const struct lmdb_purge_stats *x3_lmdb_get_purge_stats(void)
{
    return &purge_stats;
}

void x3_lmdb_set_purge_interval(unsigned int interval_secs)
{
    unsigned int old_interval = purge_interval;
    purge_interval = interval_secs;

    if (lmdb_initialized) {
        /* Cancel any existing scheduled purge */
        timeq_del(0, lmdb_purge_callback, NULL, TIMEQ_IGNORE_WHEN);

        /* Schedule new purge if interval is non-zero */
        if (interval_secs > 0) {
            timeq_add(now + interval_secs, lmdb_purge_callback, NULL);
            log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Purge job scheduled every %u seconds",
                       interval_secs);
        } else {
            log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Purge job disabled (was %u seconds)",
                       old_interval);
        }
    }
}

/* ========== Module Registration ========== */

static void lmdb_exit_handler(UNUSED_ARG(void *extra))
{
    /* Cancel any scheduled purge job */
    timeq_del(0, lmdb_purge_callback, NULL, TIMEQ_IGNORE_WHEN);

    /* Cancel any scheduled snapshot job */
    timeq_del(0, lmdb_snapshot_callback, NULL, TIMEQ_IGNORE_WHEN);

    x3_lmdb_shutdown();
}

void init_x3_lmdb(void)
{
    const char *dbpath;
    const char *purge_str;
    const char *snapshot_str;
    const char *retention_str;
    const char *snapshot_path_str;

    /* Get database path from configuration */
    dbpath = conf_get_data("services/x3/lmdb_path", RECDB_QSTRING);
    if (!dbpath) {
        dbpath = "x3data/lmdb";
    }

    if (x3_lmdb_init(dbpath, 0) == LMDB_SUCCESS) {
        log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Module initialized");
        reg_exit_func(lmdb_exit_handler, NULL);

        /* Configure purge interval from config (default 1 hour) */
        purge_str = conf_get_data("services/x3/lmdb_purge_interval", RECDB_QSTRING);
        if (purge_str) {
            purge_interval = (unsigned int)strtoul(purge_str, NULL, 10);
        }

        /* Schedule initial purge job (delayed by interval to let services settle) */
        if (purge_interval > 0) {
            timeq_add(now + purge_interval, lmdb_purge_callback, NULL);
            log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: TTL purge job scheduled every %u seconds",
                       purge_interval);
        }

        /* Configure snapshot settings */
        snapshot_path_str = conf_get_data("services/x3/lmdb_snapshot_path", RECDB_QSTRING);
        if (snapshot_path_str) {
            strncpy(snapshot_base_path, snapshot_path_str, sizeof(snapshot_base_path) - 1);
            snapshot_base_path[sizeof(snapshot_base_path) - 1] = '\0';
        } else {
            /* Default to x3data/backups */
            snprintf(snapshot_base_path, sizeof(snapshot_base_path), "x3data/backups");
        }

        snapshot_str = conf_get_data("services/x3/lmdb_snapshot_interval", RECDB_QSTRING);
        if (snapshot_str) {
            snapshot_interval = (unsigned int)strtoul(snapshot_str, NULL, 10);
        }

        retention_str = conf_get_data("services/x3/lmdb_snapshot_retention", RECDB_QSTRING);
        if (retention_str) {
            snapshot_retention = (unsigned int)strtoul(retention_str, NULL, 10);
        }

        /* Schedule initial snapshot job if interval is configured */
        if (snapshot_interval > 0 && snapshot_base_path[0] != '\0') {
            timeq_add(now + snapshot_interval, lmdb_snapshot_callback, NULL);
            log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Snapshot job scheduled every %u seconds to '%s' (retention: %u)",
                       snapshot_interval, snapshot_base_path, snapshot_retention);
        }
    } else {
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Module initialization failed, metadata persistence disabled");
    }
}

#endif /* WITH_LMDB */
