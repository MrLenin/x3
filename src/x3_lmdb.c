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

#ifdef WITH_SSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif

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

/* ========== Session Token API ========== */

/* Standard base64 alphabet for token encoding */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 encode without padding */
static int session_base64_encode(const unsigned char *input, int input_len, char *output, size_t output_size)
{
    int i, j;
    unsigned int triplet;

    /* Check output buffer size */
    int needed = ((input_len + 2) / 3) * 4 + 1;
    if ((size_t)needed > output_size) {
        return -1;
    }

    for (i = 0, j = 0; i < input_len; ) {
        triplet = (i < input_len ? input[i++] : 0) << 16;
        triplet |= (i < input_len ? input[i++] : 0) << 8;
        triplet |= (i < input_len ? input[i++] : 0);

        output[j++] = base64_chars[(triplet >> 18) & 0x3f];
        output[j++] = base64_chars[(triplet >> 12) & 0x3f];
        output[j++] = base64_chars[(triplet >> 6) & 0x3f];
        output[j++] = base64_chars[triplet & 0x3f];
    }

    /* Adjust for no padding */
    if (input_len % 3 == 1) j -= 2;
    else if (input_len % 3 == 2) j -= 1;

    output[j] = '\0';
    return j;
}

int x3_lmdb_is_session_token(const char *password)
{
    if (!password) return 0;
    return strncmp(password, SESSION_TOKEN_PREFIX, strlen(SESSION_TOKEN_PREFIX)) == 0;
}

int x3_lmdb_session_create(const char *username, char *token_out, size_t token_size)
{
    MDB_txn *txn;
    MDB_val key, data;
    unsigned char random_bytes[SESSION_TOKEN_ID_LEN];
    char token_id[64];
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    char lmdb_value[256];
    unsigned int version = 0;
    int rc;
    int i;

    if (!lmdb_initialized || !username || !token_out || token_size < 64) {
        return LMDB_ERROR;
    }

    /* Generate random bytes for token ID */
    /* Use /dev/urandom for cryptographic randomness */
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to open /dev/urandom");
        return LMDB_ERROR;
    }
    if (fread(random_bytes, 1, SESSION_TOKEN_ID_LEN, urandom) != SESSION_TOKEN_ID_LEN) {
        fclose(urandom);
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to read random bytes");
        return LMDB_ERROR;
    }
    fclose(urandom);

    /* Encode to base64 */
    if (session_base64_encode(random_bytes, SESSION_TOKEN_ID_LEN, token_id, sizeof(token_id)) < 0) {
        return LMDB_ERROR;
    }

    /* Get current session version for the user (if any) */
    x3_lmdb_session_get_version(username, &version);

    /* Build LMDB key: session:<token_id> */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%s", LMDB_PREFIX_SESSION, token_id);

    /* Build LMDB value: expiry:version:username */
    time_t expiry = now + SESSION_TOKEN_TTL;
    snprintf(lmdb_value, sizeof(lmdb_value), "%lu:%u:%s", (unsigned long)expiry, version, username);

    /* Start write transaction */
    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: session_create txn_begin failed: %s",
                   mdb_strerror(rc));
        return LMDB_ERROR;
    }

    /* Store the token */
    key.mv_size = strlen(lmdb_key);
    key.mv_data = lmdb_key;
    data.mv_size = strlen(lmdb_value) + 1;
    data.mv_data = lmdb_value;

    rc = mdb_put(txn, dbi_metadata, &key, &data, 0);
    if (rc != 0) {
        mdb_txn_abort(txn);
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: session_create mdb_put failed: %s",
                   mdb_strerror(rc));
        return LMDB_ERROR;
    }

    /* Commit transaction */
    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: session_create commit failed: %s",
                   mdb_strerror(rc));
        return LMDB_ERROR;
    }

    /* Build full token: x3tok:<token_id> */
    snprintf(token_out, token_size, "%s%s", SESSION_TOKEN_PREFIX, token_id);

    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Created session token for %s (expires %lu)",
               username, (unsigned long)expiry);

    return LMDB_SUCCESS;
}

int x3_lmdb_session_validate(const char *token, char *username_out, size_t username_size)
{
    MDB_txn *txn;
    MDB_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    const char *token_id;
    char *value_copy;
    char *expiry_str, *version_str, *username;
    time_t expiry;
    unsigned int stored_version, current_version = 0;
    int rc;

    if (!lmdb_initialized || !token) {
        return LMDB_ERROR;
    }

    /* Check token format */
    if (!x3_lmdb_is_session_token(token)) {
        return LMDB_NOT_FOUND;
    }

    /* Extract token ID (skip "x3tok:" prefix) */
    token_id = token + strlen(SESSION_TOKEN_PREFIX);
    if (!*token_id) {
        return LMDB_NOT_FOUND;
    }

    /* Build LMDB key */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%s", LMDB_PREFIX_SESSION, token_id);

    /* Start read transaction */
    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Look up token */
    key.mv_size = strlen(lmdb_key);
    key.mv_data = lmdb_key;

    rc = mdb_get(txn, dbi_metadata, &key, &data);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Parse value: expiry:version:username */
    value_copy = strndup(data.mv_data, data.mv_size);
    if (!value_copy) {
        return LMDB_ERROR;
    }

    expiry_str = value_copy;
    version_str = strchr(expiry_str, ':');
    if (!version_str) {
        free(value_copy);
        return LMDB_ERROR;
    }
    *version_str++ = '\0';

    username = strchr(version_str, ':');
    if (!username) {
        free(value_copy);
        return LMDB_ERROR;
    }
    *username++ = '\0';

    expiry = (time_t)strtoul(expiry_str, NULL, 10);
    stored_version = (unsigned int)strtoul(version_str, NULL, 10);

    /* Check if token has expired */
    if (now >= expiry) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Session token expired for %s", username);
        /* Delete expired token */
        x3_lmdb_session_revoke(token);
        free(value_copy);
        return LMDB_NOT_FOUND;
    }

    /* Check session version (for revoke-all support) */
    x3_lmdb_session_get_version(username, &current_version);
    if (stored_version < current_version) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Session token version mismatch for %s (%u < %u)",
                   username, stored_version, current_version);
        /* Delete revoked token */
        x3_lmdb_session_revoke(token);
        free(value_copy);
        return LMDB_NOT_FOUND;
    }

    /* Token is valid - copy username if requested */
    if (username_out && username_size > 0) {
        strncpy(username_out, username, username_size - 1);
        username_out[username_size - 1] = '\0';
    }

    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Session token validated for %s", username);

    free(value_copy);
    return LMDB_SUCCESS;
}

int x3_lmdb_session_revoke(const char *token)
{
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    const char *token_id;

    if (!lmdb_initialized || !token) {
        return LMDB_ERROR;
    }

    /* Check token format */
    if (!x3_lmdb_is_session_token(token)) {
        return LMDB_NOT_FOUND;
    }

    /* Extract token ID */
    token_id = token + strlen(SESSION_TOKEN_PREFIX);
    if (!*token_id) {
        return LMDB_NOT_FOUND;
    }

    /* Build LMDB key and delete */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%s", LMDB_PREFIX_SESSION, token_id);

    return x3_lmdb_delete(LMDB_DB_METADATA, lmdb_key);
}

int x3_lmdb_session_revoke_all(const char *username)
{
    MDB_txn *txn;
    MDB_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    char version_str[32];
    unsigned int version = 0;
    int rc;

    if (!lmdb_initialized || !username) {
        return LMDB_ERROR;
    }

    /* Get current version and increment */
    x3_lmdb_session_get_version(username, &version);
    version++;

    /* Build key: sessver:<username> */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%s", LMDB_PREFIX_SESSVER, username);
    snprintf(version_str, sizeof(version_str), "%u", version);

    /* Start write transaction */
    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Store new version */
    key.mv_size = strlen(lmdb_key);
    key.mv_data = lmdb_key;
    data.mv_size = strlen(version_str) + 1;
    data.mv_data = version_str;

    rc = mdb_put(txn, dbi_metadata, &key, &data, 0);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Revoked all sessions for %s (version now %u)",
               username, version);

    return LMDB_SUCCESS;
}

int x3_lmdb_session_get_version(const char *username, unsigned int *version_out)
{
    MDB_txn *txn;
    MDB_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!lmdb_initialized || !username || !version_out) {
        return LMDB_ERROR;
    }

    /* Build key: sessver:<username> */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%s", LMDB_PREFIX_SESSVER, username);

    /* Start read transaction */
    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        *version_out = 0;
        return LMDB_ERROR;
    }

    key.mv_size = strlen(lmdb_key);
    key.mv_data = lmdb_key;

    rc = mdb_get(txn, dbi_metadata, &key, &data);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        *version_out = 0;
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        *version_out = 0;
        return LMDB_ERROR;
    }

    *version_out = (unsigned int)strtoul(data.mv_data, NULL, 10);
    return LMDB_SUCCESS;
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

/* ========== SCRAM-SHA-256 Implementation ========== */

/* LMDB prefix for SCRAM credentials */
#define LMDB_PREFIX_SCRAM "scram:"

int x3_lmdb_is_scram_token(const char *password)
{
    if (!password) return 0;
    return (strncmp(password, SCRAM_TOKEN_PREFIX, strlen(SCRAM_TOKEN_PREFIX)) == 0);
}

#ifdef WITH_SSL

/**
 * Base64 encode for SCRAM
 */
static int scram_base64_encode(const unsigned char *input, size_t input_len,
                               char *output, size_t output_size)
{
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j;
    size_t needed = ((input_len + 2) / 3) * 4 + 1;

    if (output_size < needed) return -1;

    for (i = 0, j = 0; i < input_len; ) {
        unsigned int a = i < input_len ? input[i++] : 0;
        unsigned int b = i < input_len ? input[i++] : 0;
        unsigned int c = i < input_len ? input[i++] : 0;
        unsigned int triple = (a << 16) | (b << 8) | c;

        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = (i > input_len + 1) ? '=' : base64_chars[(triple >> 6) & 0x3F];
        output[j++] = (i > input_len) ? '=' : base64_chars[triple & 0x3F];
    }
    output[j] = '\0';
    return (int)j;
}

/**
 * Base64 decode for SCRAM
 */
static int scram_base64_decode(const char *input, unsigned char *output, size_t output_size)
{
    static const unsigned char base64_index[256] = {
        ['A'] = 0, ['B'] = 1, ['C'] = 2, ['D'] = 3, ['E'] = 4, ['F'] = 5,
        ['G'] = 6, ['H'] = 7, ['I'] = 8, ['J'] = 9, ['K'] = 10, ['L'] = 11,
        ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
        ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
        ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
        ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
        ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
        ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
        ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
        ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
        ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63
    };
    size_t input_len = strlen(input);
    size_t i, j;
    size_t padding = 0;

    if (input_len % 4 != 0) return -1;

    if (input_len >= 1 && input[input_len - 1] == '=') padding++;
    if (input_len >= 2 && input[input_len - 2] == '=') padding++;

    size_t output_len = (input_len / 4) * 3 - padding;
    if (output_size < output_len) return -1;

    for (i = 0, j = 0; i < input_len; i += 4) {
        unsigned int a = base64_index[(unsigned char)input[i]];
        unsigned int b = base64_index[(unsigned char)input[i + 1]];
        unsigned int c = base64_index[(unsigned char)input[i + 2]];
        unsigned int d = base64_index[(unsigned char)input[i + 3]];
        unsigned int triple = (a << 18) | (b << 12) | (c << 6) | d;

        if (j < output_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < output_len) output[j++] = triple & 0xFF;
    }
    return (int)output_len;
}

/* Get OpenSSL digest function for SCRAM hash type */
static const EVP_MD *scram_get_evp_md(enum scram_hash_type hash_type)
{
    switch (hash_type) {
    case SCRAM_HASH_SHA1:
        return EVP_sha1();
    case SCRAM_HASH_SHA256:
        return EVP_sha256();
    case SCRAM_HASH_SHA512:
        return EVP_sha512();
    default:
        return NULL;
    }
}

/* Get hash length for SCRAM hash type */
static size_t scram_get_hash_len(enum scram_hash_type hash_type)
{
    switch (hash_type) {
    case SCRAM_HASH_SHA1:
        return SCRAM_SHA1_LEN;
    case SCRAM_HASH_SHA256:
        return SCRAM_SHA256_LEN;
    case SCRAM_HASH_SHA512:
        return SCRAM_SHA512_LEN;
    default:
        return 0;
    }
}

/* Generic SCRAM key derivation for any hash type */
int scram_derive_keys(enum scram_hash_type hash_type,
                      const char *password,
                      const unsigned char *salt, size_t salt_len,
                      unsigned int iteration,
                      unsigned char *stored_key_out,
                      unsigned char *server_key_out)
{
    const EVP_MD *md = scram_get_evp_md(hash_type);
    size_t hash_len = scram_get_hash_len(hash_type);
    unsigned char salted_password[SCRAM_MAX_HASH_LEN];
    unsigned char client_key[SCRAM_MAX_HASH_LEN];
    unsigned int hmac_len;

    if (!md || hash_len == 0) {
        return -1;
    }

    /* SaltedPassword = PBKDF2(password, salt, iteration, dkLen) */
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, salt_len,
                          iteration, md,
                          hash_len, salted_password)) {
        return -1;
    }

    /* ClientKey = HMAC(SaltedPassword, "Client Key") */
    if (!HMAC(md, salted_password, hash_len,
              (unsigned char *)"Client Key", 10,
              client_key, &hmac_len)) {
        return -1;
    }

    /* StoredKey = Hash(ClientKey) */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (!EVP_DigestInit_ex(ctx, md, NULL) ||
        !EVP_DigestUpdate(ctx, client_key, hash_len) ||
        !EVP_DigestFinal_ex(ctx, stored_key_out, NULL)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    /* ServerKey = HMAC(SaltedPassword, "Server Key") */
    if (!HMAC(md, salted_password, hash_len,
              (unsigned char *)"Server Key", 10,
              server_key_out, &hmac_len)) {
        return -1;
    }

    return 0;
}

/* Generic SCRAM client signature */
int scram_client_signature(enum scram_hash_type hash_type,
                           const unsigned char *stored_key,
                           const char *auth_message, size_t auth_message_len,
                           unsigned char *client_sig_out)
{
    const EVP_MD *md = scram_get_evp_md(hash_type);
    size_t hash_len = scram_get_hash_len(hash_type);
    unsigned int hmac_len;

    if (!md || hash_len == 0) {
        return -1;
    }

    /* ClientSignature = HMAC(StoredKey, AuthMessage) */
    if (!HMAC(md, stored_key, hash_len,
              (unsigned char *)auth_message, auth_message_len,
              client_sig_out, &hmac_len)) {
        return -1;
    }
    return 0;
}

/* Generic SCRAM server signature */
int scram_server_signature(enum scram_hash_type hash_type,
                           const unsigned char *server_key,
                           const char *auth_message, size_t auth_message_len,
                           unsigned char *server_sig_out)
{
    const EVP_MD *md = scram_get_evp_md(hash_type);
    size_t hash_len = scram_get_hash_len(hash_type);
    unsigned int hmac_len;

    if (!md || hash_len == 0) {
        return -1;
    }

    /* ServerSignature = HMAC(ServerKey, AuthMessage) */
    if (!HMAC(md, server_key, hash_len,
              (unsigned char *)auth_message, auth_message_len,
              server_sig_out, &hmac_len)) {
        return -1;
    }
    return 0;
}

/* Generic SCRAM proof verification */
int scram_verify_proof(enum scram_hash_type hash_type,
                       const unsigned char *stored_key,
                       const char *auth_message, size_t auth_message_len,
                       const char *client_proof_b64)
{
    const EVP_MD *md = scram_get_evp_md(hash_type);
    size_t hash_len = scram_get_hash_len(hash_type);
    unsigned char client_proof[SCRAM_MAX_HASH_LEN];
    unsigned char client_signature[SCRAM_MAX_HASH_LEN];
    unsigned char recovered_client_key[SCRAM_MAX_HASH_LEN];
    unsigned char computed_stored_key[SCRAM_MAX_HASH_LEN];
    int proof_len;
    size_t i;

    if (!md || hash_len == 0) {
        return -1;
    }

    /* Decode client proof from base64 */
    proof_len = scram_base64_decode(client_proof_b64, client_proof, sizeof(client_proof));
    if ((size_t)proof_len != hash_len) {
        return -1;
    }

    /* Compute ClientSignature = HMAC(StoredKey, AuthMessage) */
    if (scram_client_signature(hash_type, stored_key, auth_message, auth_message_len,
                               client_signature) != 0) {
        return -1;
    }

    /* Recover ClientKey = ClientProof XOR ClientSignature */
    for (i = 0; i < hash_len; i++) {
        recovered_client_key[i] = client_proof[i] ^ client_signature[i];
    }

    /* Verify: Hash(RecoveredClientKey) == StoredKey */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (!EVP_DigestInit_ex(ctx, md, NULL) ||
        !EVP_DigestUpdate(ctx, recovered_client_key, hash_len) ||
        !EVP_DigestFinal_ex(ctx, computed_stored_key, NULL)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    /* Constant-time comparison */
    int result = 1;
    for (i = 0; i < hash_len; i++) {
        if (computed_stored_key[i] != stored_key[i]) {
            result = 0;
        }
    }

    return result;
}

/* Legacy SHA-256 specific wrappers for backward compatibility */
int scram_sha256_derive_keys(const char *password,
                             const unsigned char *salt, size_t salt_len,
                             unsigned int iteration,
                             unsigned char *stored_key_out,
                             unsigned char *server_key_out)
{
    unsigned char salted_password[SCRAM_SHA256_LEN];
    unsigned char client_key[SCRAM_SHA256_LEN];
    unsigned int hmac_len;

    /* SaltedPassword = PBKDF2(password, salt, iteration, dkLen=32) */
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, salt_len,
                          iteration, EVP_sha256(),
                          SCRAM_SHA256_LEN, salted_password)) {
        return -1;
    }

    /* ClientKey = HMAC(SaltedPassword, "Client Key") */
    if (!HMAC(EVP_sha256(), salted_password, SCRAM_SHA256_LEN,
              (unsigned char *)"Client Key", 10,
              client_key, &hmac_len)) {
        return -1;
    }

    /* StoredKey = SHA256(ClientKey) */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, client_key, SCRAM_SHA256_LEN) ||
        !EVP_DigestFinal_ex(ctx, stored_key_out, NULL)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    /* ServerKey = HMAC(SaltedPassword, "Server Key") */
    if (!HMAC(EVP_sha256(), salted_password, SCRAM_SHA256_LEN,
              (unsigned char *)"Server Key", 10,
              server_key_out, &hmac_len)) {
        return -1;
    }

    return 0;
}

int scram_sha256_client_signature(const unsigned char *stored_key,
                                  const char *auth_message, size_t auth_message_len,
                                  unsigned char *client_sig_out)
{
    unsigned int hmac_len;

    /* ClientSignature = HMAC(StoredKey, AuthMessage) */
    if (!HMAC(EVP_sha256(), stored_key, SCRAM_SHA256_LEN,
              (unsigned char *)auth_message, auth_message_len,
              client_sig_out, &hmac_len)) {
        return -1;
    }
    return 0;
}

int scram_sha256_server_signature(const unsigned char *server_key,
                                  const char *auth_message, size_t auth_message_len,
                                  unsigned char *server_sig_out)
{
    unsigned int hmac_len;

    /* ServerSignature = HMAC(ServerKey, AuthMessage) */
    if (!HMAC(EVP_sha256(), server_key, SCRAM_SHA256_LEN,
              (unsigned char *)auth_message, auth_message_len,
              server_sig_out, &hmac_len)) {
        return -1;
    }
    return 0;
}

int scram_sha256_verify_proof(const unsigned char *stored_key,
                              const char *auth_message, size_t auth_message_len,
                              const char *client_proof_b64)
{
    unsigned char client_proof[SCRAM_SHA256_LEN];
    unsigned char client_signature[SCRAM_SHA256_LEN];
    unsigned char recovered_client_key[SCRAM_SHA256_LEN];
    unsigned char computed_stored_key[SCRAM_SHA256_LEN];
    int proof_len;
    size_t i;

    /* Decode client proof from base64 */
    proof_len = scram_base64_decode(client_proof_b64, client_proof, sizeof(client_proof));
    if (proof_len != SCRAM_SHA256_LEN) {
        return -1;
    }

    /* Compute ClientSignature = HMAC(StoredKey, AuthMessage) */
    if (scram_sha256_client_signature(stored_key, auth_message, auth_message_len,
                                      client_signature) != 0) {
        return -1;
    }

    /* Recover ClientKey = ClientProof XOR ClientSignature */
    for (i = 0; i < SCRAM_SHA256_LEN; i++) {
        recovered_client_key[i] = client_proof[i] ^ client_signature[i];
    }

    /* Verify: SHA256(RecoveredClientKey) == StoredKey */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, recovered_client_key, SCRAM_SHA256_LEN) ||
        !EVP_DigestFinal_ex(ctx, computed_stored_key, NULL)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    /* Constant-time comparison */
    int result = 1;
    for (i = 0; i < SCRAM_SHA256_LEN; i++) {
        if (computed_stored_key[i] != stored_key[i]) {
            result = 0;
        }
    }

    return result;
}

int x3_lmdb_scram_create_ex(const char *token_id, const char *username,
                             const char *password, enum scram_hash_type hash_type)
{
    MDB_txn *txn;
    MDB_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    unsigned char salt[SCRAM_SALT_LEN];
    unsigned char stored_key[SCRAM_MAX_HASH_LEN];
    unsigned char server_key[SCRAM_MAX_HASH_LEN];
    char value_buf[768];  /* Larger for SHA-512 */
    char salt_hex[SCRAM_SALT_LEN * 2 + 1];
    char stored_key_hex[SCRAM_MAX_HASH_LEN * 2 + 1];
    char server_key_hex[SCRAM_MAX_HASH_LEN * 2 + 1];
    size_t hash_len;
    time_t expiry;
    int rc;
    size_t i;

    if (!lmdb_initialized || !token_id || !username || !password) {
        return LMDB_ERROR;
    }

    /* Get hash length for this type */
    switch (hash_type) {
    case SCRAM_HASH_SHA1:
        hash_len = SCRAM_SHA1_LEN;
        break;
    case SCRAM_HASH_SHA256:
        hash_len = SCRAM_SHA256_LEN;
        break;
    case SCRAM_HASH_SHA512:
        hash_len = SCRAM_SHA512_LEN;
        break;
    default:
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Invalid SCRAM hash type %d", hash_type);
        return LMDB_ERROR;
    }

    /* Generate random salt */
    if (RAND_bytes(salt, SCRAM_SALT_LEN) != 1) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to generate SCRAM salt");
        return LMDB_ERROR;
    }

    /* Derive SCRAM keys using the generic function */
    if (scram_derive_keys(hash_type, password, salt, SCRAM_SALT_LEN,
                          SCRAM_ITERATION_COUNT,
                          stored_key, server_key) != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to derive SCRAM keys");
        return LMDB_ERROR;
    }

    /* Convert to hex for storage */
    for (i = 0; i < SCRAM_SALT_LEN; i++) {
        sprintf(salt_hex + i * 2, "%02x", salt[i]);
    }
    for (i = 0; i < hash_len; i++) {
        sprintf(stored_key_hex + i * 2, "%02x", stored_key[i]);
        sprintf(server_key_hex + i * 2, "%02x", server_key[i]);
    }
    stored_key_hex[hash_len * 2] = '\0';
    server_key_hex[hash_len * 2] = '\0';

    /* Build LMDB key: scram:<hash_type>:<token_id> */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%d:%s", LMDB_PREFIX_SCRAM, (int)hash_type, token_id);

    /* Build value: expiry:hashtype:iteration:salt:storedkey:serverkey:username */
    expiry = now + SESSION_TOKEN_TTL;
    snprintf(value_buf, sizeof(value_buf), "%lu:%d:%u:%s:%s:%s:%s",
             (unsigned long)expiry, (int)hash_type, SCRAM_ITERATION_COUNT,
             salt_hex, stored_key_hex, server_key_hex, username);

    /* Start write transaction */
    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_create txn_begin failed: %s",
                   mdb_strerror(rc));
        return LMDB_ERROR;
    }

    /* Store the credential */
    key.mv_size = strlen(lmdb_key);
    key.mv_data = lmdb_key;
    data.mv_size = strlen(value_buf) + 1;
    data.mv_data = value_buf;

    rc = mdb_put(txn, dbi_metadata, &key, &data, 0);
    if (rc != 0) {
        mdb_txn_abort(txn);
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_create mdb_put failed: %s",
                   mdb_strerror(rc));
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_create commit failed: %s",
                   mdb_strerror(rc));
        return LMDB_ERROR;
    }

    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Created SCRAM-%s credential for %s (expires %lu)",
               hash_type == SCRAM_HASH_SHA1 ? "SHA-1" :
               hash_type == SCRAM_HASH_SHA256 ? "SHA-256" : "SHA-512",
               username, (unsigned long)expiry);

    return LMDB_SUCCESS;
}

/* Legacy wrapper for backward compatibility - creates SHA-256 credential */
int x3_lmdb_scram_create(const char *token_id, const char *username, const char *password)
{
    return x3_lmdb_scram_create_ex(token_id, username, password, SCRAM_HASH_SHA256);
}

/**
 * Helper to parse hex string to bytes
 */
static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
    size_t i;
    for (i = 0; i < out_len && hex[i * 2] && hex[i * 2 + 1]; i++) {
        char buf[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        out[i] = (unsigned char)strtoul(buf, NULL, 16);
    }
    return (i == out_len) ? 0 : -1;
}

int x3_lmdb_scram_get_ex(const char *token_id, enum scram_hash_type hash_type,
                          struct scram_credential *cred_out)
{
    MDB_txn *txn;
    MDB_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    char *value_copy;
    char *expiry_str, *field2, *iter_str, *salt_hex, *stored_key_hex, *server_key_hex, *username;
    unsigned long field2_val;
    int rc;

    if (!lmdb_initialized || !token_id || !cred_out) {
        return LMDB_ERROR;
    }

    /* Build LMDB key with hash type: scram:<hash_type>:<token_id> */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%d:%s", LMDB_PREFIX_SCRAM, (int)hash_type, token_id);

    /* Start read transaction */
    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    key.mv_size = strlen(lmdb_key);
    key.mv_data = lmdb_key;

    rc = mdb_get(txn, dbi_metadata, &key, &data);
    mdb_txn_abort(txn);

    if (rc == MDB_NOTFOUND) {
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        return LMDB_ERROR;
    }

    /*
     * Parse value - two formats:
     * Old: expiry:iteration:salt:storedkey:serverkey:username (6 fields)
     * New: expiry:hashtype:iteration:salt:storedkey:serverkey:username (7 fields)
     *
     * We detect by checking field2: if it's 1-3, it's hash_type; if >= 100, it's iteration
     */
    value_copy = strndup(data.mv_data, data.mv_size);
    if (!value_copy) {
        return LMDB_ERROR;
    }

    expiry_str = value_copy;
    field2 = strchr(expiry_str, ':');
    if (!field2) { free(value_copy); return LMDB_ERROR; }
    *field2++ = '\0';

    /* Parse field2 to determine format */
    field2_val = strtoul(field2, NULL, 10);

    if (field2_val >= 1 && field2_val <= 3) {
        /* New format: field2 is hash_type */
        cred_out->hash_type = (enum scram_hash_type)field2_val;

        iter_str = strchr(field2, ':');
        if (!iter_str) { free(value_copy); return LMDB_ERROR; }
        *iter_str++ = '\0';
    } else {
        /* Old format: field2 is iteration, assume SHA-256 */
        cred_out->hash_type = SCRAM_HASH_SHA256;
        iter_str = field2;
    }

    /* Set hash_len based on hash_type */
    switch (cred_out->hash_type) {
    case SCRAM_HASH_SHA1:
        cred_out->hash_len = SCRAM_SHA1_LEN;
        break;
    case SCRAM_HASH_SHA256:
        cred_out->hash_len = SCRAM_SHA256_LEN;
        break;
    case SCRAM_HASH_SHA512:
        cred_out->hash_len = SCRAM_SHA512_LEN;
        break;
    default:
        free(value_copy);
        return LMDB_ERROR;
    }

    salt_hex = strchr(iter_str, ':');
    if (!salt_hex) { free(value_copy); return LMDB_ERROR; }
    *salt_hex++ = '\0';

    stored_key_hex = strchr(salt_hex, ':');
    if (!stored_key_hex) { free(value_copy); return LMDB_ERROR; }
    *stored_key_hex++ = '\0';

    server_key_hex = strchr(stored_key_hex, ':');
    if (!server_key_hex) { free(value_copy); return LMDB_ERROR; }
    *server_key_hex++ = '\0';

    username = strchr(server_key_hex, ':');
    if (!username) { free(value_copy); return LMDB_ERROR; }
    *username++ = '\0';

    /* Parse fields */
    cred_out->expiry = (time_t)strtoul(expiry_str, NULL, 10);
    cred_out->iteration = (unsigned int)strtoul(iter_str, NULL, 10);

    /* Check expiry */
    if (now >= cred_out->expiry) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: SCRAM credential expired for %s", username);
        x3_lmdb_scram_delete(token_id);
        free(value_copy);
        return LMDB_NOT_FOUND;
    }

    /* Parse hex values based on hash length */
    if (hex_to_bytes(salt_hex, cred_out->salt, SCRAM_SALT_LEN) != 0 ||
        hex_to_bytes(stored_key_hex, cred_out->stored_key, cred_out->hash_len) != 0 ||
        hex_to_bytes(server_key_hex, cred_out->server_key, cred_out->hash_len) != 0) {
        free(value_copy);
        return LMDB_ERROR;
    }

    strncpy(cred_out->username, username, sizeof(cred_out->username) - 1);
    cred_out->username[sizeof(cred_out->username) - 1] = '\0';

    free(value_copy);
    return LMDB_SUCCESS;
}

/* Legacy wrapper - defaults to SHA-256 for backward compatibility */
int x3_lmdb_scram_get(const char *token_id, struct scram_credential *cred_out)
{
    return x3_lmdb_scram_get_ex(token_id, SCRAM_HASH_SHA256, cred_out);
}

/* Delete SCRAM credential for a specific hash type */
int x3_lmdb_scram_delete_ex(const char *token_id, enum scram_hash_type hash_type)
{
    MDB_txn *txn;
    MDB_val key;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!lmdb_initialized || !token_id) {
        return LMDB_ERROR;
    }

    snprintf(lmdb_key, sizeof(lmdb_key), "%s%d:%s", LMDB_PREFIX_SCRAM, (int)hash_type, token_id);

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    key.mv_size = strlen(lmdb_key);
    key.mv_data = lmdb_key;

    rc = mdb_del(txn, dbi_metadata, &key, NULL);
    if (rc == MDB_NOTFOUND) {
        mdb_txn_abort(txn);
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    return LMDB_SUCCESS;
}

/* Delete all SCRAM credentials for a token (all hash types) */
int x3_lmdb_scram_delete(const char *token_id)
{
    int deleted = 0;

    if (!lmdb_initialized || !token_id) {
        return LMDB_ERROR;
    }

    /* Delete credentials for all hash types */
    if (x3_lmdb_scram_delete_ex(token_id, SCRAM_HASH_SHA1) == LMDB_SUCCESS)
        deleted++;
    if (x3_lmdb_scram_delete_ex(token_id, SCRAM_HASH_SHA256) == LMDB_SUCCESS)
        deleted++;
    if (x3_lmdb_scram_delete_ex(token_id, SCRAM_HASH_SHA512) == LMDB_SUCCESS)
        deleted++;

    return deleted > 0 ? LMDB_SUCCESS : LMDB_NOT_FOUND;
}

/* Legacy delete for old key format (used during migration) */
static int x3_lmdb_scram_delete_legacy(const char *token_id)
{
    MDB_txn *txn;
    MDB_val key;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!lmdb_initialized || !token_id) {
        return LMDB_ERROR;
    }

    /* Old key format without hash type */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%s", LMDB_PREFIX_SCRAM, token_id);

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    key.mv_size = strlen(lmdb_key);
    key.mv_data = lmdb_key;

    rc = mdb_del(txn, dbi_metadata, &key, NULL);
    if (rc == MDB_NOTFOUND) {
        mdb_txn_abort(txn);
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    return LMDB_SUCCESS;
}

int x3_lmdb_scram_revoke_all(const char *username)
{
    MDB_txn *txn;
    MDB_cursor *cursor;
    MDB_val key, data;
    int rc, count = 0;
    char prefix[64];
    size_t prefix_len;

    if (!lmdb_initialized || !username) {
        return -1;
    }

    snprintf(prefix, sizeof(prefix), "%s", LMDB_PREFIX_SCRAM);
    prefix_len = strlen(prefix);

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return -1;
    }

    rc = mdb_cursor_open(txn, dbi_metadata, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return -1;
    }

    /* Iterate through all SCRAM entries */
    rc = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
    while (rc == 0) {
        if (key.mv_size > prefix_len &&
            memcmp(key.mv_data, prefix, prefix_len) == 0) {
            /* Check if this credential belongs to the user */
            char *value_copy = strndup(data.mv_data, data.mv_size);
            if (value_copy) {
                /* Parse to find username (last field) */
                char *p = value_copy;
                int colons = 0;
                while (*p && colons < 5) {
                    if (*p == ':') colons++;
                    p++;
                }
                if (colons == 5 && strcasecmp(p, username) == 0) {
                    mdb_cursor_del(cursor, 0);
                    count++;
                }
                free(value_copy);
            }
        }
        rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
    }

    mdb_cursor_close(cursor);
    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        return -1;
    }

    if (count > 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Revoked %d SCRAM credential(s) for %s",
                   count, username);
    }

    return count;
}

/* ========== Account Password SCRAM Implementation ========== */

/**
 * Create SCRAM credential for an account password with specified hash type.
 * Uses key format: scram_acct:<hash_type>:<account>
 * Value format: 0:<hash_type>:<iteration>:<salt_hex>:<storedkey_hex>:<serverkey_hex>:<account>
 * Note: expiry=0 means no expiry (password SCRAM credentials don't expire)
 */
int x3_lmdb_scram_acct_create(const char *account, const char *password,
                               enum scram_hash_type hash_type)
{
    MDB_txn *txn;
    MDB_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    unsigned char salt[SCRAM_SALT_LEN];
    unsigned char stored_key[SCRAM_MAX_HASH_LEN];
    unsigned char server_key[SCRAM_MAX_HASH_LEN];
    char value_buf[768];
    char salt_hex[SCRAM_SALT_LEN * 2 + 1];
    char stored_key_hex[SCRAM_MAX_HASH_LEN * 2 + 1];
    char server_key_hex[SCRAM_MAX_HASH_LEN * 2 + 1];
    size_t hash_len;
    int rc;
    size_t i;

    if (!lmdb_initialized || !account || !password) {
        return LMDB_ERROR;
    }

    /* Get hash length for this type */
    switch (hash_type) {
    case SCRAM_HASH_SHA1:
        hash_len = SCRAM_SHA1_LEN;
        break;
    case SCRAM_HASH_SHA256:
        hash_len = SCRAM_SHA256_LEN;
        break;
    case SCRAM_HASH_SHA512:
        hash_len = SCRAM_SHA512_LEN;
        break;
    default:
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Invalid SCRAM hash type %d", hash_type);
        return LMDB_ERROR;
    }

    /* Generate random salt */
    if (RAND_bytes(salt, SCRAM_SALT_LEN) != 1) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to generate SCRAM salt for account");
        return LMDB_ERROR;
    }

    /* Derive SCRAM keys */
    if (scram_derive_keys(hash_type, password, salt, SCRAM_SALT_LEN,
                          SCRAM_ITERATION_COUNT,
                          stored_key, server_key) != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to derive SCRAM keys for account");
        return LMDB_ERROR;
    }

    /* Convert to hex for storage */
    for (i = 0; i < SCRAM_SALT_LEN; i++) {
        sprintf(salt_hex + i * 2, "%02x", salt[i]);
    }
    for (i = 0; i < hash_len; i++) {
        sprintf(stored_key_hex + i * 2, "%02x", stored_key[i]);
        sprintf(server_key_hex + i * 2, "%02x", server_key[i]);
    }
    stored_key_hex[hash_len * 2] = '\0';
    server_key_hex[hash_len * 2] = '\0';

    /* Build LMDB key: scram_acct:<hash_type>:<account> (lowercase for consistency) */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%d:%s", LMDB_PREFIX_SCRAM_ACCT, (int)hash_type, account);

    /* Build value: 0:hashtype:iteration:salt:storedkey:serverkey:account
     * Note: expiry=0 means no expiry for password-based SCRAM */
    snprintf(value_buf, sizeof(value_buf), "0:%d:%u:%s:%s:%s:%s",
             (int)hash_type, SCRAM_ITERATION_COUNT,
             salt_hex, stored_key_hex, server_key_hex, account);

    /* Start write transaction */
    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_acct_create txn_begin failed: %s",
                   mdb_strerror(rc));
        return LMDB_ERROR;
    }

    /* Store the credential */
    key.mv_size = strlen(lmdb_key);
    key.mv_data = lmdb_key;
    data.mv_size = strlen(value_buf) + 1;
    data.mv_data = value_buf;

    rc = mdb_put(txn, dbi_metadata, &key, &data, 0);
    if (rc != 0) {
        mdb_txn_abort(txn);
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_acct_create mdb_put failed: %s",
                   mdb_strerror(rc));
        return LMDB_ERROR;
    }

    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_acct_create commit failed: %s",
                   mdb_strerror(rc));
        return LMDB_ERROR;
    }

    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Created SCRAM-%s credential for account %s",
               hash_type == SCRAM_HASH_SHA1 ? "SHA-1" :
               hash_type == SCRAM_HASH_SHA256 ? "SHA-256" : "SHA-512",
               account);

    return LMDB_SUCCESS;
}

/**
 * Create SCRAM credentials for an account password (all hash types).
 * This should be called whenever a password is set/changed.
 */
int x3_lmdb_scram_acct_create_all(const char *account, const char *password)
{
    int count = 0;

    if (!lmdb_initialized || !account || !password) {
        return -1;
    }

    /* Create credentials for all three SCRAM variants */
    if (x3_lmdb_scram_acct_create(account, password, SCRAM_HASH_SHA1) == LMDB_SUCCESS)
        count++;
    if (x3_lmdb_scram_acct_create(account, password, SCRAM_HASH_SHA256) == LMDB_SUCCESS)
        count++;
    if (x3_lmdb_scram_acct_create(account, password, SCRAM_HASH_SHA512) == LMDB_SUCCESS)
        count++;

    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Created %d SCRAM credentials for account %s",
               count, account);

    return count;
}

/**
 * Get SCRAM credential for an account with specified hash type.
 */
int x3_lmdb_scram_acct_get(const char *account, enum scram_hash_type hash_type,
                            struct scram_credential *cred_out)
{
    MDB_txn *txn;
    MDB_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    char *value_copy, *p, *fields[7];
    int field_count = 0;
    size_t hash_len;
    int rc, i;

    if (!lmdb_initialized || !account || !cred_out) {
        return LMDB_ERROR;
    }

    /* Get hash length for this type */
    switch (hash_type) {
    case SCRAM_HASH_SHA1:
        hash_len = SCRAM_SHA1_LEN;
        break;
    case SCRAM_HASH_SHA256:
        hash_len = SCRAM_SHA256_LEN;
        break;
    case SCRAM_HASH_SHA512:
        hash_len = SCRAM_SHA512_LEN;
        break;
    default:
        return LMDB_ERROR;
    }

    /* Build LMDB key: scram_acct:<hash_type>:<account> */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%d:%s", LMDB_PREFIX_SCRAM_ACCT, (int)hash_type, account);

    /* Start read transaction */
    rc = mdb_txn_begin(lmdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    key.mv_size = strlen(lmdb_key);
    key.mv_data = lmdb_key;

    rc = mdb_get(txn, dbi_metadata, &key, &data);
    if (rc == MDB_NOTFOUND) {
        mdb_txn_abort(txn);
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        mdb_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Parse value: 0:hashtype:iteration:salt:storedkey:serverkey:account */
    value_copy = strndup(data.mv_data, data.mv_size);
    mdb_txn_abort(txn);

    if (!value_copy) {
        return LMDB_ERROR;
    }

    /* Split by colons */
    p = value_copy;
    fields[field_count++] = p;
    while (*p && field_count < 7) {
        if (*p == ':') {
            *p = '\0';
            fields[field_count++] = p + 1;
        }
        p++;
    }

    if (field_count != 7) {
        free(value_copy);
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Invalid SCRAM acct format for %s", account);
        return LMDB_ERROR;
    }

    /* Parse fields */
    memset(cred_out, 0, sizeof(*cred_out));
    cred_out->expiry = (time_t)strtoul(fields[0], NULL, 10);  /* 0 = no expiry */
    cred_out->hash_type = (enum scram_hash_type)atoi(fields[1]);
    cred_out->iteration = (unsigned int)strtoul(fields[2], NULL, 10);
    cred_out->hash_len = hash_len;

    /* Verify hash type matches requested */
    if (cred_out->hash_type != hash_type) {
        free(value_copy);
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: SCRAM hash type mismatch for %s", account);
        return LMDB_ERROR;
    }

    /* Parse salt from hex */
    if (hex_to_bytes(fields[3], cred_out->salt, SCRAM_SALT_LEN) != SCRAM_SALT_LEN) {
        free(value_copy);
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Invalid SCRAM salt for %s", account);
        return LMDB_ERROR;
    }

    /* Parse stored_key from hex */
    if ((i = hex_to_bytes(fields[4], cred_out->stored_key, hash_len)) != (int)hash_len) {
        free(value_copy);
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Invalid SCRAM stored_key for %s", account);
        return LMDB_ERROR;
    }

    /* Parse server_key from hex */
    if ((i = hex_to_bytes(fields[5], cred_out->server_key, hash_len)) != (int)hash_len) {
        free(value_copy);
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Invalid SCRAM server_key for %s", account);
        return LMDB_ERROR;
    }

    /* Copy username */
    strncpy(cred_out->username, fields[6], sizeof(cred_out->username) - 1);
    cred_out->username[sizeof(cred_out->username) - 1] = '\0';

    free(value_copy);

    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Retrieved SCRAM-%s credential for account %s",
               hash_type == SCRAM_HASH_SHA1 ? "SHA-1" :
               hash_type == SCRAM_HASH_SHA256 ? "SHA-256" : "SHA-512",
               account);

    return LMDB_SUCCESS;
}

/**
 * Delete all SCRAM credentials for an account (all hash types).
 */
int x3_lmdb_scram_acct_delete_all(const char *account)
{
    MDB_txn *txn;
    MDB_val key;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    int rc, count = 0;
    enum scram_hash_type hash_types[] = { SCRAM_HASH_SHA1, SCRAM_HASH_SHA256, SCRAM_HASH_SHA512 };
    size_t i;

    if (!lmdb_initialized || !account) {
        return -1;
    }

    rc = mdb_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return -1;
    }

    /* Delete each hash type */
    for (i = 0; i < sizeof(hash_types) / sizeof(hash_types[0]); i++) {
        snprintf(lmdb_key, sizeof(lmdb_key), "%s%d:%s",
                 LMDB_PREFIX_SCRAM_ACCT, (int)hash_types[i], account);

        key.mv_size = strlen(lmdb_key);
        key.mv_data = lmdb_key;

        rc = mdb_del(txn, dbi_metadata, &key, NULL);
        if (rc == 0) {
            count++;
        }
    }

    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        return -1;
    }

    if (count > 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Deleted %d SCRAM credential(s) for account %s",
                   count, account);
    }

    return count;
}

#else /* !WITH_SSL */

/* Stub implementations when SSL is not available */

/* Generic SCRAM stubs */
int scram_derive_keys(enum scram_hash_type hash_type,
                      const char *password,
                      const unsigned char *salt, size_t salt_len,
                      unsigned int iteration,
                      unsigned char *stored_key_out,
                      unsigned char *server_key_out)
{
    (void)hash_type; (void)password; (void)salt; (void)salt_len;
    (void)iteration; (void)stored_key_out; (void)server_key_out;
    return -1;
}

int scram_client_signature(enum scram_hash_type hash_type,
                           const unsigned char *stored_key,
                           const char *auth_message, size_t auth_message_len,
                           unsigned char *client_sig_out)
{
    (void)hash_type; (void)stored_key; (void)auth_message;
    (void)auth_message_len; (void)client_sig_out;
    return -1;
}

int scram_server_signature(enum scram_hash_type hash_type,
                           const unsigned char *server_key,
                           const char *auth_message, size_t auth_message_len,
                           unsigned char *server_sig_out)
{
    (void)hash_type; (void)server_key; (void)auth_message;
    (void)auth_message_len; (void)server_sig_out;
    return -1;
}

int scram_verify_proof(enum scram_hash_type hash_type,
                       const unsigned char *stored_key,
                       const char *auth_message, size_t auth_message_len,
                       const char *client_proof)
{
    (void)hash_type; (void)stored_key; (void)auth_message;
    (void)auth_message_len; (void)client_proof;
    return -1;
}

/* Legacy SHA-256 specific stubs */
int scram_sha256_derive_keys(const char *password,
                             const unsigned char *salt, size_t salt_len,
                             unsigned int iteration,
                             unsigned char *stored_key_out,
                             unsigned char *server_key_out)
{
    (void)password; (void)salt; (void)salt_len; (void)iteration;
    (void)stored_key_out; (void)server_key_out;
    return -1;
}

int scram_sha256_client_signature(const unsigned char *stored_key,
                                  const char *auth_message, size_t auth_message_len,
                                  unsigned char *client_sig_out)
{
    (void)stored_key; (void)auth_message; (void)auth_message_len; (void)client_sig_out;
    return -1;
}

int scram_sha256_server_signature(const unsigned char *server_key,
                                  const char *auth_message, size_t auth_message_len,
                                  unsigned char *server_sig_out)
{
    (void)server_key; (void)auth_message; (void)auth_message_len; (void)server_sig_out;
    return -1;
}

int scram_sha256_verify_proof(const unsigned char *stored_key,
                              const char *auth_message, size_t auth_message_len,
                              const char *client_proof)
{
    (void)stored_key; (void)auth_message; (void)auth_message_len; (void)client_proof;
    return -1;
}

int x3_lmdb_scram_create_ex(const char *token_id, const char *username,
                             const char *password, enum scram_hash_type hash_type)
{
    (void)token_id; (void)username; (void)password; (void)hash_type;
    return LMDB_ERROR;
}

int x3_lmdb_scram_create(const char *token_id, const char *username, const char *password)
{
    (void)token_id; (void)username; (void)password;
    return LMDB_ERROR;
}

int x3_lmdb_scram_get_ex(const char *token_id, enum scram_hash_type hash_type,
                          struct scram_credential *cred_out)
{
    (void)token_id; (void)hash_type; (void)cred_out;
    return LMDB_NOT_FOUND;
}

int x3_lmdb_scram_get(const char *token_id, struct scram_credential *cred_out)
{
    (void)token_id; (void)cred_out;
    return LMDB_NOT_FOUND;
}

int x3_lmdb_scram_delete_ex(const char *token_id, enum scram_hash_type hash_type)
{
    (void)token_id; (void)hash_type;
    return LMDB_NOT_FOUND;
}

int x3_lmdb_scram_delete(const char *token_id)
{
    (void)token_id;
    return LMDB_NOT_FOUND;
}

int x3_lmdb_scram_revoke_all(const char *username)
{
    (void)username;
    return 0;
}

/* Account SCRAM stubs */
int x3_lmdb_scram_acct_create(const char *account, const char *password,
                               enum scram_hash_type hash_type)
{
    (void)account; (void)password; (void)hash_type;
    return LMDB_ERROR;
}

int x3_lmdb_scram_acct_create_all(const char *account, const char *password)
{
    (void)account; (void)password;
    return -1;
}

int x3_lmdb_scram_acct_get(const char *account, enum scram_hash_type hash_type,
                            struct scram_credential *cred_out)
{
    (void)account; (void)hash_type; (void)cred_out;
    return LMDB_NOT_FOUND;
}

int x3_lmdb_scram_acct_delete_all(const char *account)
{
    (void)account;
    return -1;
}

#endif /* WITH_SSL */

#endif /* WITH_LMDB */
