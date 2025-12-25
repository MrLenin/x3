/*
 * X3 - LMDB Wrapper Module Implementation
 * Copyright (C) 2024 AfterNET Development Team
 *
 * Provides LMDB-based persistent storage for X3 metadata and account data.
 */

#include "config.h"

#ifdef WITH_LMDB

#include "x3_lmdb.h"
#include "common.h"
#include "conf.h"
#include "log.h"

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

/* Maximum value size */
#define LMDB_MAX_VALUE_SIZE 4096

/* Key buffer size */
#define LMDB_KEY_BUFFER_SIZE 512

/**
 * Build a composite key from prefix and parts
 */
static void build_key(char *buf, size_t bufsize, const char *prefix,
                      const char *part1, const char *part2)
{
    if (part2) {
        snprintf(buf, bufsize, "%s%s\x00%s", prefix, part1, part2);
    } else {
        snprintf(buf, bufsize, "%s%s", prefix, part1);
    }
}

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

    /* Copy value, ensuring null termination */
    size_t copylen = mdata.mv_size < LMDB_MAX_VALUE_SIZE ? mdata.mv_size : LMDB_MAX_VALUE_SIZE - 1;
    memcpy(value, mdata.mv_data, copylen);
    value[copylen] = '\0';

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
        mdata.mv_size = strlen(value) + 1;
        mdata.mv_data = (void *)value;
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

    size_t copylen = mdata.mv_size < LMDB_MAX_VALUE_SIZE ? mdata.mv_size : LMDB_MAX_VALUE_SIZE - 1;
    memcpy(value, mdata.mv_data, copylen);
    value[copylen] = '\0';

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
        mdata.mv_size = strlen(value) + 1;
        mdata.mv_data = (void *)value;
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

    /* Parse access level from stored value */
    *access_out = (unsigned short)atoi((const char *)mdata.mv_data);
    return LMDB_SUCCESS;
}

int x3_lmdb_chanaccess_set(const char *channel, const char *account, unsigned short access)
{
    MDB_txn *txn;
    MDB_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    char valuebuf[16];
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
        snprintf(valuebuf, sizeof(valuebuf), "%u", access);
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

/* ========== Module Registration ========== */

static void lmdb_exit_handler(UNUSED_ARG(void *extra))
{
    x3_lmdb_shutdown();
}

void init_x3_lmdb(void)
{
    const char *dbpath;

    /* Get database path from configuration */
    dbpath = conf_get_data("services/x3/lmdb_path", RECDB_QSTRING);
    if (!dbpath) {
        dbpath = "x3data/lmdb";
    }

    if (x3_lmdb_init(dbpath, 0) == LMDB_SUCCESS) {
        log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Module initialized");
        reg_exit_func(lmdb_exit_handler, NULL);
    } else {
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Module initialization failed, metadata persistence disabled");
    }
}

#endif /* WITH_LMDB */
