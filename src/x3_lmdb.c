/*
 * X3 - LMDB Wrapper Module Implementation
 * Copyright (C) 2024 AfterNET Development Team
 *
 * Provides LMDB-based persistent storage for X3 metadata and account data.
 */

#include "config.h"

#ifdef WITH_MDBX

#include "x3_lmdb.h"
#include "x3_compress.h"
#include "common.h"
#include "conf.h"
#include "log.h"
#include "timeq.h"
#include "threadpool.h"
#include "base64.h"

#include <mdbx.h>
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
static MDBX_env *lmdb_env = NULL;
static MDBX_dbi dbi_accounts = 0;
static MDBX_dbi dbi_channels = 0;
static MDBX_dbi dbi_metadata = 0;
static int lmdb_initialized = 0;

/* Configuration */
static char lmdb_path[MAXLEN];
static size_t lmdb_mapsize = 100 * 1024 * 1024; /* 100MB default */
static unsigned int scram_iterations = SCRAM_ITERATION_COUNT_DEFAULT;

/* Sync configuration - MDBX_SAFE_NOSYNC mode for performance */
static int lmdb_nosync = 0;                    /* 0 = sync on commit, 1 = periodic sync only */
static unsigned int lmdb_sync_interval = 10;   /* seconds between syncs when nosync enabled */

/* Auto-growth configuration */
static int lmdb_autogrow = 1;                  /* 1 = auto-grow enabled (default), 0 = fixed size */
static intptr_t lmdb_growth_step = 16 * 1024 * 1024; /* 16MB default growth step */

/* NORDAHEAD configuration - disable OS readahead for random-access pattern */
static int lmdb_nordahead = 1;                 /* 1 = disable readahead (default for random access) */

/* Purge batch size - limit how long write transactions are held during purge */
static unsigned int lmdb_purge_batch_size = 100;

/* B-tree traversal cache for hot lookups */
#define LMDB_CACHE_SLOTS_DEFAULT 128
static MDBX_cache_entry_t *lmdb_cache = NULL;
static uint32_t *lmdb_cache_hash = NULL;
static unsigned int lmdb_cache_slots = 0;

/* Cache statistics */
static unsigned long lmdb_cache_hits = 0;
static unsigned long lmdb_cache_misses = 0;

/** FNV-1a 32-bit hash for cache slot selection */
static uint32_t lmdb_cache_fnv1a(const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h ? h : 1; /* avoid 0 so we can distinguish from empty */
}

/** Cached mdbx_get — falls back to mdbx_get when cache is disabled.
 * Returns the same error code as mdbx_get(). */
static int lmdb_cached_get(MDBX_txn *txn, MDBX_dbi dbi, MDBX_val *key, MDBX_val *data)
{
    if (lmdb_cache) {
        uint32_t h = lmdb_cache_fnv1a(key->iov_base, key->iov_len);
        unsigned int slot = h & (lmdb_cache_slots - 1);
        if (lmdb_cache_hash[slot] != h) {
            mdbx_cache_init(&lmdb_cache[slot]);
            lmdb_cache_hash[slot] = h;
        }
        MDBX_cache_result_t cr = mdbx_cache_get_SingleThreaded(txn, dbi, key, data, &lmdb_cache[slot]);
        if (cr.status >= MDBX_CACHE_HIT)
            lmdb_cache_hits++;
        else
            lmdb_cache_misses++;
        return cr.errcode;
    }
    return mdbx_get(txn, dbi, key, data);
}

/* Get/set SCRAM iteration count */
unsigned int x3_lmdb_get_scram_iterations(void)
{
    return scram_iterations;
}

void x3_lmdb_set_scram_iterations(unsigned int iterations)
{
    if (iterations < SCRAM_ITERATION_COUNT_MIN) {
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: scram_iterations %u below minimum %u, using minimum",
                   iterations, SCRAM_ITERATION_COUNT_MIN);
        iterations = SCRAM_ITERATION_COUNT_MIN;
    }
    scram_iterations = iterations;
    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: SCRAM iterations set to %u", scram_iterations);
}

/* Get/set LMDB nosync mode */
int x3_lmdb_get_nosync(void)
{
    return lmdb_nosync;
}

void x3_lmdb_set_nosync(int nosync)
{
    lmdb_nosync = nosync ? 1 : 0;
    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: nosync mode %s",
               lmdb_nosync ? "enabled (periodic sync)" : "disabled (sync on commit)");
}

/* Get/set LMDB sync interval (only used when nosync enabled) */
unsigned int x3_lmdb_get_sync_interval(void)
{
    return lmdb_sync_interval;
}

void x3_lmdb_set_sync_interval(unsigned int interval)
{
    if (interval < 1) interval = 1;
    if (interval > 300) interval = 300;  /* Max 5 minutes */
    lmdb_sync_interval = interval;
    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: sync interval set to %u seconds", lmdb_sync_interval);
}

/* Periodic sync timer callback */
static void lmdb_periodic_sync_timer(UNUSED_ARG(void *data))
{
    if (lmdb_nosync && lmdb_initialized && lmdb_env) {
        int dead = 0;
        mdbx_env_sync_ex(lmdb_env, false, false);  /* Non-forced sync */
        /* Clean up stale reader slots to prevent GC blockage */
        mdbx_reader_check(lmdb_env, &dead);
        if (dead > 0)
            log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: cleared %d stale reader(s)", dead);
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: periodic sync completed");
    }

    /* Reschedule if still in nosync mode */
    if (lmdb_nosync && lmdb_initialized) {
        timeq_add(now + lmdb_sync_interval, lmdb_periodic_sync_timer, NULL);
    }
}

/* Maximum value size (increased for compression support) */
#define LMDB_MAX_VALUE_SIZE 8192

/* Key buffer size */
#define LMDB_KEY_BUFFER_SIZE 512

/**
 * Open a named database within the environment
 */
static int open_database(MDBX_txn *txn, const char *name, MDBX_dbi *dbi)
{
    int rc = mdbx_dbi_open(txn, name, MDBX_CREATE, dbi);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to open database '%s': %s",
                   name, mdbx_strerror(rc));
        return LMDB_ERROR;
    }
    return LMDB_SUCCESS;
}

/* ========== Initialization ========== */

int x3_lmdb_init(const char *dbpath, size_t mapsize)
{
    MDBX_txn *txn;
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
    rc = mdbx_env_create(&lmdb_env);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to create environment: %s",
                   mdbx_strerror(rc));
        return LMDB_ERROR;
    }

    /* Set maximum number of named databases */
    rc = mdbx_env_set_maxdbs(lmdb_env, 4);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to set maxdbs: %s",
                   mdbx_strerror(rc));
        mdbx_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    /* Set the database geometry */
    if (lmdb_autogrow) {
        rc = mdbx_env_set_geometry(lmdb_env, -1, -1, lmdb_mapsize,
                                   lmdb_growth_step, lmdb_growth_step, -1);
    } else {
        rc = mdbx_env_set_geometry(lmdb_env, lmdb_mapsize, lmdb_mapsize,
                                   lmdb_mapsize, 0, 0, -1);
    }
    if (rc != MDBX_SUCCESS) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to set geometry: %s",
                   mdbx_strerror(rc));
        mdbx_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    /* Open the environment
     * MDBX_SAFE_NOSYNC: Don't sync on commit - use periodic sync instead for performance.
     * This trades some durability for significantly reduced fdatasync overhead.
     */
    {
        unsigned int env_flags = 0;
        if (lmdb_nosync) {
            env_flags |= MDBX_SAFE_NOSYNC;
            log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Using MDBX_SAFE_NOSYNC mode with %u second sync interval",
                       lmdb_sync_interval);
        }
        if (lmdb_nordahead) {
            env_flags |= MDBX_NORDAHEAD;
            log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Using MDBX_NORDAHEAD for random-access pattern");
        }
        rc = mdbx_env_open(lmdb_env, lmdb_path, env_flags, 0644);
    }
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to open environment at '%s': %s",
                   lmdb_path, mdbx_strerror(rc));
        mdbx_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    /* Open databases in a write transaction */
    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to begin transaction: %s",
                   mdbx_strerror(rc));
        mdbx_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    if (open_database(txn, LMDB_DB_ACCOUNTS, &dbi_accounts) != LMDB_SUCCESS ||
        open_database(txn, LMDB_DB_CHANNELS, &dbi_channels) != LMDB_SUCCESS ||
        open_database(txn, LMDB_DB_METADATA, &dbi_metadata) != LMDB_SUCCESS) {
        mdbx_txn_abort(txn);
        mdbx_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Failed to commit transaction: %s",
                   mdbx_strerror(rc));
        mdbx_env_close(lmdb_env);
        lmdb_env = NULL;
        return LMDB_ERROR;
    }

    lmdb_initialized = 1;

    /* Initialize B-tree traversal cache */
    {
        const char *cache_str = conf_get_data("services/x3/lmdb_cache_slots", RECDB_QSTRING);
        unsigned int slots = LMDB_CACHE_SLOTS_DEFAULT;
        if (cache_str) {
            unsigned int val = (unsigned int)strtoul(cache_str, NULL, 10);
            slots = val; /* 0 = disabled */
        }
        if (slots > 0) {
            /* Round up to next power of 2 */
            unsigned int s = 1;
            while (s < slots) s <<= 1;
            lmdb_cache_slots = s;
            lmdb_cache = calloc(s, sizeof(MDBX_cache_entry_t));
            lmdb_cache_hash = calloc(s, sizeof(uint32_t));
            if (lmdb_cache && lmdb_cache_hash) {
                for (unsigned int i = 0; i < s; i++)
                    mdbx_cache_init(&lmdb_cache[i]);
                log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: B-tree cache initialized (%u slots)", s);
            } else {
                free(lmdb_cache);
                free(lmdb_cache_hash);
                lmdb_cache = NULL;
                lmdb_cache_hash = NULL;
                lmdb_cache_slots = 0;
                log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Failed to allocate B-tree cache");
            }
        }
    }

    log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Initialized at '%s' with %luMB map",
               lmdb_path, (unsigned long)(lmdb_mapsize / (1024 * 1024)));

    /* Pre-fault database pages into OS page cache for faster initial queries */
    rc = mdbx_env_warmup(lmdb_env, NULL, MDBX_warmup_default, 0);
    if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE)
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: mdbx_env_warmup failed: %s",
                   mdbx_strerror(rc));

    /* Start periodic sync timer if nosync mode enabled */
    if (lmdb_nosync) {
        timeq_add(now + lmdb_sync_interval, lmdb_periodic_sync_timer, NULL);
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Started periodic sync timer");
    }

    return LMDB_SUCCESS;
}

void x3_lmdb_shutdown(void)
{
    if (!lmdb_initialized || !lmdb_env) {
        return;
    }

    /* Sync before shutdown to ensure all data is persisted */
    if (lmdb_nosync) {
        log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Final sync before shutdown");
        mdbx_env_sync_ex(lmdb_env, true, false);  /* Force sync */
    }

    mdbx_dbi_close(lmdb_env, dbi_accounts);
    mdbx_dbi_close(lmdb_env, dbi_channels);
    mdbx_dbi_close(lmdb_env, dbi_metadata);
    mdbx_env_close(lmdb_env);

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
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = account_len + 1 + strlen(key) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = lmdb_cached_get(txn, dbi_accounts, &mkey, &mdata);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Decompress if needed, then copy value */
#ifdef WITH_ZSTD
    {
        unsigned char decompressed[LMDB_MAX_VALUE_SIZE];
        size_t decompressed_len;

        if (x3_decompress(mdata.iov_base, mdata.iov_len,
                          decompressed, sizeof(decompressed) - 1, &decompressed_len) >= 0) {
            memcpy(value, decompressed, decompressed_len);
            value[decompressed_len] = '\0';
        } else {
            return LMDB_ERROR;
        }
    }
#else
    /* Copy value, ensuring null termination */
    size_t copylen = mdata.iov_len < LMDB_MAX_VALUE_SIZE ? mdata.iov_len : LMDB_MAX_VALUE_SIZE - 1;
    memcpy(value, mdata.iov_base, copylen);
    value[copylen] = '\0';
#endif

    return LMDB_SUCCESS;
}

int x3_lmdb_account_set(const char *account, const char *key, const char *value)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = account_len + 1 + strlen(key) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
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
            mdata.iov_len = compressed_len;
            mdata.iov_base = compressed;
        } else {
            mdata.iov_len = value_len;
            mdata.iov_base = (void *)value;
        }
#else
        mdata.iov_len = strlen(value) + 1;
        mdata.iov_base = (void *)value;
#endif
        rc = mdbx_put(txn, dbi_accounts, &mkey, &mdata, 0);
    } else {
        rc = mdbx_del(txn, dbi_accounts, &mkey, NULL);
        if (rc == MDBX_NOTFOUND) {
            rc = 0; /* Deleting non-existent key is not an error */
        }
    }

    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
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
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = account_len + 1 + strlen(key) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = lmdb_cached_get(txn, dbi_accounts, &mkey, &mdata);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Return raw data without decompression */
    if (mdata.iov_len > LMDB_MAX_VALUE_SIZE) {
        return LMDB_ERROR;
    }

    memcpy(raw_value, mdata.iov_base, mdata.iov_len);
    *raw_len = mdata.iov_len;

    /* Check if data is compressed (has magic byte) */
#ifdef WITH_ZSTD
    *is_compressed = x3_is_compressed(mdata.iov_base, mdata.iov_len);
#else
    *is_compressed = 0;
#endif

    return LMDB_SUCCESS;
}

int x3_lmdb_account_set_raw(const char *account, const char *key,
                            const unsigned char *raw_value, size_t raw_len)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = account_len + 1 + strlen(key) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Store raw value without compression (it's already compressed or we want it as-is) */
    mdata.iov_len = raw_len;
    mdata.iov_base = (void *)raw_value;

    rc = mdbx_put(txn, dbi_accounts, &mkey, &mdata, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_account_list(const char *account, struct lmdb_metadata_entry **entries_out)
{
    MDBX_txn *txn;
    MDBX_cursor *cursor;
    MDBX_val mkey, mdata;
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

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_cursor_open(txn, dbi_accounts, &cursor);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Position cursor at prefix */
    mkey.iov_len = prefix_len;
    mkey.iov_base = prefix;

    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);
    while (rc == 0) {
        /* Check if key still starts with our prefix */
        if (mkey.iov_len < prefix_len ||
            memcmp(mkey.iov_base, prefix, prefix_len - 1) != 0) {
            break;
        }

        /* Extract the key part after "account\0" */
        const char *keystart = (const char *)mkey.iov_base + prefix_len;
        size_t keylen = mkey.iov_len - prefix_len;

        /* Create entry */
        struct lmdb_metadata_entry *entry = malloc(sizeof(*entry));
        if (!entry) {
            break;
        }

        entry->key = strndup(keystart, keylen);
        entry->value = strndup(mdata.iov_base, mdata.iov_len);
        entry->next = NULL;

        if (tail) {
            tail->next = entry;
        } else {
            head = entry;
        }
        tail = entry;
        count++;

        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
    mdbx_txn_abort(txn);

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
    MDBX_txn *txn;
    MDBX_cursor *cursor;
    MDBX_val mkey, mdata;
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

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_cursor_open(txn, dbi_accounts, &cursor);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Position cursor at prefix */
    mkey.iov_len = prefix_len;
    mkey.iov_base = prefix;

    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);
    while (rc == 0) {
        /* Check if key still starts with our prefix */
        if (mkey.iov_len < prefix_len ||
            memcmp(mkey.iov_base, prefix, prefix_len - 1) != 0) {
            break;
        }

        /* Extract the key part after "account\0" */
        const char *keystart = (const char *)mkey.iov_base + prefix_len;
        size_t keylen = mkey.iov_len - prefix_len;

        /* Create entry with raw data */
        struct lmdb_raw_metadata_entry *entry = malloc(sizeof(*entry));
        if (!entry) {
            break;
        }

        entry->key = strndup(keystart, keylen);
        entry->raw_len = mdata.iov_len;
        entry->raw_value = malloc(mdata.iov_len);
        if (!entry->raw_value) {
            free(entry->key);
            free(entry);
            break;
        }
        memcpy(entry->raw_value, mdata.iov_base, mdata.iov_len);

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

        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
    mdbx_txn_abort(txn);

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
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = channel_len + 1 + strlen(key) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = lmdb_cached_get(txn, dbi_channels, &mkey, &mdata);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Decompress if needed, then copy value */
#ifdef WITH_ZSTD
    {
        unsigned char decompressed[LMDB_MAX_VALUE_SIZE];
        size_t decompressed_len;

        if (x3_decompress(mdata.iov_base, mdata.iov_len,
                          decompressed, sizeof(decompressed) - 1, &decompressed_len) >= 0) {
            memcpy(value, decompressed, decompressed_len);
            value[decompressed_len] = '\0';
        } else {
            return LMDB_ERROR;
        }
    }
#else
    size_t copylen = mdata.iov_len < LMDB_MAX_VALUE_SIZE ? mdata.iov_len : LMDB_MAX_VALUE_SIZE - 1;
    memcpy(value, mdata.iov_base, copylen);
    value[copylen] = '\0';
#endif

    return LMDB_SUCCESS;
}

int x3_lmdb_channel_set(const char *channel, const char *key, const char *value)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = channel_len + 1 + strlen(key) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
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
            mdata.iov_len = compressed_len;
            mdata.iov_base = compressed;
        } else {
            mdata.iov_len = value_len;
            mdata.iov_base = (void *)value;
        }
#else
        mdata.iov_len = strlen(value) + 1;
        mdata.iov_base = (void *)value;
#endif
        rc = mdbx_put(txn, dbi_channels, &mkey, &mdata, 0);
    } else {
        rc = mdbx_del(txn, dbi_channels, &mkey, NULL);
        if (rc == MDBX_NOTFOUND) {
            rc = 0;
        }
    }

    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_channel_delete(const char *channel, const char *key)
{
    return x3_lmdb_channel_set(channel, key, NULL);
}

int x3_lmdb_channel_list(const char *channel, struct lmdb_metadata_entry **entries_out)
{
    MDBX_txn *txn;
    MDBX_cursor *cursor;
    MDBX_val mkey, mdata;
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

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_cursor_open(txn, dbi_channels, &cursor);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    mkey.iov_len = prefix_len;
    mkey.iov_base = prefix;

    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);
    while (rc == 0) {
        if (mkey.iov_len < prefix_len ||
            memcmp(mkey.iov_base, prefix, prefix_len - 1) != 0) {
            break;
        }

        const char *keystart = (const char *)mkey.iov_base + prefix_len;
        size_t keylen = mkey.iov_len - prefix_len;

        struct lmdb_metadata_entry *entry = malloc(sizeof(*entry));
        if (!entry) {
            break;
        }

        entry->key = strndup(keystart, keylen);
        entry->value = strndup(mdata.iov_base, mdata.iov_len);
        entry->next = NULL;

        if (tail) {
            tail->next = entry;
        } else {
            head = entry;
        }
        tail = entry;
        count++;

        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
    mdbx_txn_abort(txn);

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

int x3_lmdb_metadata_purge_expired(void)
{
    MDBX_txn *txn;
    MDBX_cursor *cursor;
    MDBX_val mkey, mdata;
    int count = 0;
    int rc;

    if (!x3_lmdb_is_available()) {
        return LMDB_ERROR;
    }

    /* Purge accounts database */
    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_cursor_open(txn, dbi_accounts, &cursor);
    if (rc == 0) {
        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_FIRST);
        while (rc == 0) {
            const char *stored = (const char *)mdata.iov_base;
            if (is_value_expired(stored)) {
                mdbx_cursor_del(cursor, 0);
                count++;
            }
            rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
        }
        mdbx_cursor_close(cursor);
    }

    /* Purge channels database */
    rc = mdbx_cursor_open(txn, dbi_channels, &cursor);
    if (rc == 0) {
        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_FIRST);
        while (rc == 0) {
            const char *stored = (const char *)mdata.iov_base;
            if (is_value_expired(stored)) {
                mdbx_cursor_del(cursor, 0);
                count++;
            }
            rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
        }
        mdbx_cursor_close(cursor);
    }

    rc = mdbx_txn_commit(txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    if (count > 0) {
        log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Purged %d expired metadata entries",
                   count);
    }

    return count;
}

int x3_lmdb_metadata_delete_by_user(const char *account)
{
    MDBX_txn *txn;
    MDBX_cursor *cursor;
    MDBX_val mkey, mdata;
    int count = 0;
    int rc;
    size_t account_len;

    if (!x3_lmdb_is_available() || !account) {
        return LMDB_ERROR;
    }

    account_len = strlen(account);

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_cursor_open(txn, dbi_accounts, &cursor);
    if (rc == 0) {
        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_FIRST);
        while (rc == 0) {
            /*
             * Key format is "account\0key" - check if this entry belongs to
             * the specified account by comparing the account portion.
             */
            if (mkey.iov_len > account_len + 1 &&
                memcmp(mkey.iov_base, account, account_len) == 0 &&
                ((char *)mkey.iov_base)[account_len] == '\0') {
                /* This entry belongs to the target account - delete it */
                mdbx_cursor_del(cursor, 0);
                count++;
            }
            rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
        }
        mdbx_cursor_close(cursor);
    }

    rc = mdbx_txn_commit(txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    if (count > 0) {
        log_module(MAIN_LOG, LOG_INFO,
                   "x3_lmdb: Deleted %d metadata entries for account %s",
                   count, account);
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

    rc = mdbx_env_sync_ex(lmdb_env, force ? true : false, false);
    return rc == MDBX_SUCCESS ? LMDB_SUCCESS : LMDB_ERROR;
}

/* ========== Generic Key-Value Operations ========== */

/**
 * Helper to resolve database name to dbi handle
 */
static int resolve_dbi(const char *db, MDBX_dbi *dbi_out)
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
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
    MDBX_dbi dbi;
    int rc;

    if (!x3_lmdb_is_available() || !db || !key || !value || value_size == 0) {
        return LMDB_ERROR;
    }

    if (resolve_dbi(db, &dbi) != LMDB_SUCCESS) {
        return LMDB_ERROR;
    }

    mkey.iov_len = strlen(key) + 1;
    mkey.iov_base = (void *)key;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_get(txn, dbi, &mkey, &mdata);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Copy value, ensuring null termination */
    size_t copy_len = mdata.iov_len < value_size ? mdata.iov_len : value_size - 1;
    memcpy(value, mdata.iov_base, copy_len);
    value[copy_len] = '\0';

    return LMDB_SUCCESS;
}

int x3_lmdb_set(const char *db, const char *key, const char *value)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
    MDBX_dbi dbi;
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

    mkey.iov_len = strlen(key) + 1;
    mkey.iov_base = (void *)key;
    mdata.iov_len = strlen(value) + 1;
    mdata.iov_base = (void *)value;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_put(txn, dbi, &mkey, &mdata, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_delete(const char *db, const char *key)
{
    MDBX_txn *txn;
    MDBX_val mkey;
    MDBX_dbi dbi;
    int rc;

    if (!x3_lmdb_is_available() || !db || !key) {
        return LMDB_ERROR;
    }

    if (resolve_dbi(db, &dbi) != LMDB_SUCCESS) {
        return LMDB_ERROR;
    }

    mkey.iov_len = strlen(key) + 1;
    mkey.iov_base = (void *)key;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_del(txn, dbi, &mkey, NULL);
    if (rc == MDBX_NOTFOUND) {
        mdbx_txn_abort(txn);
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_dbi_stats(const char *db, size_t *entries_out, size_t *size_out)
{
    MDBX_txn *txn;
    MDBX_stat stat;
    MDBX_dbi dbi;
    int rc;

    if (!x3_lmdb_is_available()) {
        return LMDB_ERROR;
    }

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    if (db == NULL) {
        /* Environment stats */
        MDBX_envinfo info;
        rc = mdbx_env_info_ex(lmdb_env, NULL, &info, sizeof(info));
        if (rc == MDBX_SUCCESS) {
            rc = mdbx_env_stat_ex(lmdb_env, NULL, &stat, sizeof(stat));
        }
        mdbx_txn_abort(txn);

        if (rc != 0) {
            return LMDB_ERROR;
        }

        if (entries_out) {
            *entries_out = stat.ms_entries;
        }
        if (size_out) {
            *size_out = info.mi_geo.upper;
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
            mdbx_txn_abort(txn);
            return LMDB_ERROR;
        }

        rc = mdbx_dbi_stat(txn, dbi, &stat, sizeof(stat));
        mdbx_txn_abort(txn);

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

int x3_lmdb_env_info(struct lmdb_env_info *info_out)
{
    MDBX_envinfo info;
    MDBX_stat envstat;
    int rc;

    if (!x3_lmdb_is_available() || !info_out)
        return LMDB_ERROR;

    memset(info_out, 0, sizeof(*info_out));

    rc = mdbx_env_info_ex(lmdb_env, NULL, &info, sizeof(info));
    if (rc != MDBX_SUCCESS)
        return LMDB_ERROR;

    rc = mdbx_env_stat_ex(lmdb_env, NULL, &envstat, sizeof(envstat));
    if (rc != MDBX_SUCCESS)
        return LMDB_ERROR;

    info_out->geo_current = info.mi_geo.current;
    info_out->geo_upper = info.mi_geo.upper;
    info_out->geo_grow = info.mi_geo.grow;
    info_out->num_readers = info.mi_numreaders;
    info_out->branch_pages = envstat.ms_branch_pages;
    info_out->leaf_pages = envstat.ms_leaf_pages;
    info_out->overflow_pages = envstat.ms_overflow_pages;
    info_out->page_size = envstat.ms_psize;
    info_out->nosync_enabled = lmdb_nosync;
    info_out->nordahead_enabled = lmdb_nordahead;

    {
        size_t total_pages = info.mi_last_pgno + 1;
        size_t data_pages = envstat.ms_branch_pages + envstat.ms_leaf_pages + envstat.ms_overflow_pages;
        info_out->free_pages = total_pages > data_pages ? total_pages - data_pages : 0;
    }

    return LMDB_SUCCESS;
}

/* ========== Channel Access (Keycloak Group Sync) ========== */

int x3_lmdb_chanaccess_get(const char *channel, const char *account, unsigned short *access_out)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = prefix_len + channel_len + 1 + account_len + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = lmdb_cached_get(txn, dbi_metadata, &mkey, &mdata);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Parse access level from stored value (format: "access" or "access:timestamp") */
    *access_out = (unsigned short)strtol((const char *)mdata.iov_base, NULL, 10);
    return LMDB_SUCCESS;
}

int x3_lmdb_chanaccess_get_ex(const char *channel, const char *account,
                               unsigned short *access_out, time_t *timestamp_out)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = prefix_len + channel_len + 1 + account_len + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_get(txn, dbi_metadata, &mkey, &mdata);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Parse format: "access" or "access:timestamp" */
    *access_out = (unsigned short)strtol((const char *)mdata.iov_base, NULL, 10);

    if (timestamp_out) {
        colon = strchr((const char *)mdata.iov_base, ':');
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
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = prefix_len + channel_len + 1 + account_len + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    if (access > 0) {
        /* Store as "access:timestamp" */
        snprintf(valuebuf, sizeof(valuebuf), "%u:%ld", access, (long)timestamp);
        mdata.iov_len = strlen(valuebuf) + 1;
        mdata.iov_base = valuebuf;
        rc = mdbx_put(txn, dbi_metadata, &mkey, &mdata, 0);
    } else {
        /* Access 0 means delete */
        rc = mdbx_del(txn, dbi_metadata, &mkey, NULL);
        if (rc == MDBX_NOTFOUND) {
            rc = 0;
        }
    }

    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_chanaccess_delete(const char *channel, const char *account)
{
    return x3_lmdb_chanaccess_set(channel, account, 0);
}

int x3_lmdb_chanaccess_list(const char *channel, struct lmdb_chanaccess_entry **entries_out)
{
    MDBX_txn *txn;
    MDBX_cursor *cursor;
    MDBX_val mkey, mdata;
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

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_cursor_open(txn, dbi_metadata, &cursor);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    mkey.iov_len = prefix_len;
    mkey.iov_base = prefix;

    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);
    while (rc == 0) {
        /* Check if key still starts with our prefix */
        if (mkey.iov_len < prefix_len ||
            memcmp(mkey.iov_base, prefix, prefix_len) != 0) {
            break;
        }

        /* Extract the account part after "chanaccess:<channel>\0" */
        const char *accountstart = (const char *)mkey.iov_base + prefix_len;
        size_t accountlen = mkey.iov_len - prefix_len - 1; /* -1 for null terminator */

        /* Create entry */
        struct lmdb_chanaccess_entry *entry = malloc(sizeof(*entry));
        if (!entry) {
            break;
        }

        entry->channel = strdup(channel);
        entry->account = strndup(accountstart, accountlen);
        entry->access = (unsigned short)atoi((const char *)mdata.iov_base);
        entry->next = NULL;

        if (tail) {
            tail->next = entry;
        } else {
            head = entry;
        }
        tail = entry;
        count++;

        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
    mdbx_txn_abort(txn);

    *entries_out = head;
    return count;
}

int x3_lmdb_chanaccess_list_account(const char *account, struct lmdb_chanaccess_entry **entries_out)
{
    MDBX_txn *txn;
    MDBX_cursor *cursor;
    MDBX_val mkey, mdata;
    struct lmdb_chanaccess_entry *head = NULL, *tail = NULL;
    int count = 0;
    int rc;
    size_t chanaccess_len = strlen(LMDB_PREFIX_CHANACCESS);

    if (!x3_lmdb_is_available() || !account || !entries_out) {
        return LMDB_ERROR;
    }

    *entries_out = NULL;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_cursor_open(txn, dbi_metadata, &cursor);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Scan all chanaccess entries looking for matching account
     * Key format: "chanaccess:<channel>\0<account>\0"
     */
    mkey.iov_len = chanaccess_len;
    mkey.iov_base = (void *)LMDB_PREFIX_CHANACCESS;

    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);
    while (rc == 0) {
        /* Check if key starts with "chanaccess:" prefix */
        if (mkey.iov_len < chanaccess_len ||
            memcmp(mkey.iov_base, LMDB_PREFIX_CHANACCESS, chanaccess_len) != 0) {
            break;
        }

        /* Parse key: find the null separating channel from account */
        const char *keydata = (const char *)mkey.iov_base;
        const char *channel_start = keydata + chanaccess_len;
        const char *null_pos = memchr(channel_start, '\0', mkey.iov_len - chanaccess_len);

        if (null_pos && null_pos < keydata + mkey.iov_len - 1) {
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
                entry->access = (unsigned short)atoi((const char *)mdata.iov_base);
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

        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
    mdbx_txn_abort(txn);

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

/* ========== Channel Sync Metadata (for Keycloak sync) ========== */

/* Default exponential backoff: 30s, 60s, 120s, 240s, 480s, 960s, max 1h */
#define KC_BACKOFF_BASE_SECS 30
#define KC_BACKOFF_MAX_SECS  3600

int x3_lmdb_chansync_get(const char *channel, struct lmdb_chansync_meta *meta_out)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !channel || !meta_out) {
        return LMDB_ERROR;
    }

    /* Build key: "kcsyncmeta:<channel>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_CHANSYNC, channel);

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_get(txn, dbi_metadata, &mkey, &mdata);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Parse stored data - binary format for efficiency */
    if (mdata.iov_len != sizeof(struct lmdb_chansync_meta)) {
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: chansync_get: size mismatch for %s (%zu vs %zu)",
                   channel, mdata.iov_len, sizeof(struct lmdb_chansync_meta));
        return LMDB_ERROR;
    }

    memcpy(meta_out, mdata.iov_base, sizeof(struct lmdb_chansync_meta));
    return LMDB_SUCCESS;
}

int x3_lmdb_chansync_set(const char *channel, const struct lmdb_chansync_meta *meta)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !channel || !meta) {
        return LMDB_ERROR;
    }

    /* Build key: "kcsyncmeta:<channel>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_CHANSYNC, channel);

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;
    mdata.iov_len = sizeof(struct lmdb_chansync_meta);
    mdata.iov_base = (void *)meta;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_put(txn, dbi_metadata, &mkey, &mdata, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    return (rc == 0) ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_chansync_delete(const char *channel)
{
    MDBX_txn *txn;
    MDBX_val mkey;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !channel) {
        return LMDB_ERROR;
    }

    /* Build key: "kcsyncmeta:<channel>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_CHANSYNC, channel);

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_del(txn, dbi_metadata, &mkey, NULL);
    if (rc == MDBX_NOTFOUND) {
        mdbx_txn_abort(txn);
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    return (rc == 0) ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_chansync_record_failure(const char *channel)
{
    struct lmdb_chansync_meta meta;
    int rc;
    time_t backoff_secs;

    if (!channel) {
        return -1;
    }

    /* Get existing metadata or initialize */
    rc = x3_lmdb_chansync_get(channel, &meta);
    if (rc == LMDB_NOT_FOUND) {
        memset(&meta, 0, sizeof(meta));
    } else if (rc != LMDB_SUCCESS) {
        return -1;
    }

    /* Increment failure count */
    meta.consecutive_failures++;

    /* Calculate exponential backoff: base * 2^(failures-1), capped at max */
    backoff_secs = KC_BACKOFF_BASE_SECS * (1 << (meta.consecutive_failures - 1));
    if (backoff_secs > KC_BACKOFF_MAX_SECS) {
        backoff_secs = KC_BACKOFF_MAX_SECS;
    }

    meta.next_allowed_sync = now + backoff_secs;

    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: chansync_record_failure: %s failure #%d, backoff %ld secs",
               channel, meta.consecutive_failures, (long)backoff_secs);

    rc = x3_lmdb_chansync_set(channel, &meta);
    if (rc != LMDB_SUCCESS) {
        return -1;
    }

    return meta.consecutive_failures;
}

int x3_lmdb_chansync_record_success(const char *channel, uint64_t membership_hash, int entry_count)
{
    struct lmdb_chansync_meta meta;
    int rc;

    if (!channel) {
        return LMDB_ERROR;
    }

    /* Get existing metadata or initialize */
    rc = x3_lmdb_chansync_get(channel, &meta);
    if (rc == LMDB_NOT_FOUND) {
        memset(&meta, 0, sizeof(meta));
    } else if (rc != LMDB_SUCCESS) {
        return LMDB_ERROR;
    }

    /* Update metadata */
    meta.membership_hash = membership_hash;
    meta.last_sync = now;
    meta.consecutive_failures = 0;  /* Reset on success */
    meta.next_allowed_sync = 0;     /* No backoff */
    meta.last_entry_count = entry_count;

    return x3_lmdb_chansync_set(channel, &meta);
}

int x3_lmdb_chansync_in_backoff(const char *channel)
{
    struct lmdb_chansync_meta meta;
    int rc;

    if (!channel) {
        return -1;
    }

    rc = x3_lmdb_chansync_get(channel, &meta);
    if (rc == LMDB_NOT_FOUND) {
        /* No metadata means no failures, not in backoff */
        return 0;
    }
    if (rc != LMDB_SUCCESS) {
        return -1;
    }

    /* Check if still in backoff period */
    if (meta.next_allowed_sync > 0 && now < meta.next_allowed_sync) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: chansync_in_backoff: %s in backoff until %lu (now=%lu)",
                   channel, (unsigned long)meta.next_allowed_sync, (unsigned long)now);
        return 1;
    }

    return 0;
}

/* ========== Activity Data (lastseen/last_present) ========== */

int x3_lmdb_activity_get(const char *account, time_t *lastseen_out, time_t *last_present_out)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;
    time_t expires = 0;

    if (!x3_lmdb_is_available() || !account) {
        return LMDB_ERROR;
    }

    /* Build key: "activity:<account>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_ACTIVITY, account);

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_get(txn, dbi_metadata, &mkey, &mdata);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Parse stored value - format: "T:<expiry>:<lastseen>:<last_present>" or "<lastseen>:<last_present>" */
    const char *stored = (const char *)mdata.iov_base;
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
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    /* Calculate expiry (30 days from now) */
    expires = time(NULL) + LMDB_ACTIVITY_TTL_SECS;

    /* Build value: "T:<expiry>:<lastseen>:<last_present>" */
    snprintf(valuebuf, sizeof(valuebuf), "T:%ld:%ld:%ld",
             (long)expires, (long)lastseen, (long)last_present);

    mdata.iov_len = strlen(valuebuf) + 1;
    mdata.iov_base = valuebuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_put(txn, dbi_metadata, &mkey, &mdata, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
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
    MDBX_txn *txn;
    MDBX_val mkey;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !account) {
        return LMDB_ERROR;
    }

    /* Build key: "activity:<account>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_ACTIVITY, account);

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_del(txn, dbi_metadata, &mkey, NULL);
    if (rc == MDBX_NOTFOUND) {
        mdbx_txn_abort(txn);
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

/* ========== Fingerprint Storage ========== */

int x3_lmdb_fingerprint_get(const char *fingerprint, char *account_out,
                            time_t *registered_out, time_t *last_used_out,
                            time_t *expires_out)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;
    time_t expires = 0;

    if (!x3_lmdb_is_available() || !fingerprint) {
        return LMDB_ERROR;
    }

    /* Build key: "fp:<fingerprint>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_FINGERPRINT, fingerprint);

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_get(txn, dbi_metadata, &mkey, &mdata);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Parse stored value - format: "T:<expiry>:<account>:<registered>:<last_used>" */
    const char *stored = (const char *)mdata.iov_base;
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
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
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

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    /* Calculate expiry (90 days from now) */
    expires = now_time + LMDB_FINGERPRINT_TTL_SECS;

    /* Build value: "T:<expiry>:<account>:<registered>:<last_used>" */
    snprintf(valuebuf, sizeof(valuebuf), "T:%ld:%s:%ld:%ld",
             (long)expires, account, (long)registered, (long)last_used);

    mdata.iov_len = strlen(valuebuf) + 1;
    mdata.iov_base = valuebuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_put(txn, dbi_metadata, &mkey, &mdata, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
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
    MDBX_txn *txn;
    MDBX_val mkey;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !fingerprint) {
        return LMDB_ERROR;
    }

    /* Build key: "fp:<fingerprint>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_FINGERPRINT, fingerprint);

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_del(txn, dbi_metadata, &mkey, NULL);
    if (rc == MDBX_NOTFOUND) {
        mdbx_txn_abort(txn);
        return LMDB_NOT_FOUND;
    } else if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    if (rc == 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Deleted fingerprint %s", fingerprint);
    }
    return rc == 0 ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_fingerprint_list_account(const char *account, struct lmdb_fingerprint_entry **entries_out)
{
    MDBX_txn *txn;
    MDBX_cursor *cursor;
    MDBX_val mkey, mdata;
    struct lmdb_fingerprint_entry *head = NULL, *tail = NULL, *entry;
    int rc, count = 0;
    const char *prefix = LMDB_PREFIX_FINGERPRINT;
    size_t prefix_len = strlen(prefix);

    if (!x3_lmdb_is_available() || !account || !entries_out) {
        return LMDB_ERROR;
    }

    *entries_out = NULL;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_cursor_open(txn, dbi_metadata, &cursor);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Iterate all fp: entries and filter by account */
    mkey.iov_len = prefix_len;
    mkey.iov_base = (void *)prefix;

    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);
    while (rc == 0) {
        const char *key = (const char *)mkey.iov_base;

        /* Check if we're still in fp: prefix */
        if (strncmp(key, prefix, prefix_len) != 0) {
            break;
        }

        /* Parse value to check account */
        const char *stored = (const char *)mdata.iov_base;
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
                    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
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

        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
    mdbx_txn_abort(txn);

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

/* ========== Certificate Expiry ========== */

int x3_lmdb_certexp_set(const char *fingerprint, time_t cert_expires)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    char valuebuf[32];
    int rc;

    if (!x3_lmdb_is_available() || !fingerprint || cert_expires == 0) {
        return LMDB_ERROR;
    }

    /* Build key: "certexp:<fingerprint>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_CERTEXP, fingerprint);

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    /* Store just the timestamp */
    snprintf(valuebuf, sizeof(valuebuf), "%ld", (long)cert_expires);

    mdata.iov_len = strlen(valuebuf) + 1;
    mdata.iov_base = valuebuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_put(txn, dbi_metadata, &mkey, &mdata, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    return (rc == 0) ? LMDB_SUCCESS : LMDB_ERROR;
}

int x3_lmdb_certexp_get(const char *fingerprint, time_t *cert_expires_out)
{
    MDBX_txn *txn;
    MDBX_val mkey, mdata;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !fingerprint) {
        return LMDB_ERROR;
    }

    /* Build key: "certexp:<fingerprint>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_CERTEXP, fingerprint);

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_get(txn, dbi_metadata, &mkey, &mdata);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return (rc == MDBX_NOTFOUND) ? LMDB_NOT_FOUND : LMDB_ERROR;
    }

    if (cert_expires_out) {
        *cert_expires_out = (time_t)strtol((const char*)mdata.iov_base, NULL, 10);
    }

    mdbx_txn_abort(txn);
    return LMDB_SUCCESS;
}

int x3_lmdb_certexp_delete(const char *fingerprint)
{
    MDBX_txn *txn;
    MDBX_val mkey;
    char keybuf[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!x3_lmdb_is_available() || !fingerprint) {
        return LMDB_ERROR;
    }

    /* Build key: "certexp:<fingerprint>" */
    snprintf(keybuf, sizeof(keybuf), "%s%s", LMDB_PREFIX_CERTEXP, fingerprint);

    mkey.iov_len = strlen(keybuf) + 1;
    mkey.iov_base = keybuf;

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    rc = mdbx_del(txn, dbi_metadata, &mkey, NULL);
    if (rc != 0 && rc != MDBX_NOTFOUND) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    return (rc == 0) ? LMDB_SUCCESS : LMDB_ERROR;
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
    unsigned int flags = compact ? MDBX_CP_COMPACT : 0;
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

    /* Perform the hot backup using mdbx_env_copy */
    rc = mdbx_env_copy(lmdb_env, backup_path, flags);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: Snapshot failed: %s", mdbx_strerror(rc));
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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(data_file, sizeof(data_file), "%s/data.mdb", full_path);
        snprintf(lock_file, sizeof(lock_file), "%s/lock.mdb", full_path);
#pragma GCC diagnostic pop

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
static int json_export_db(FILE *fp, MDBX_dbi dbi, const char *db_name, int *first)
{
    MDBX_txn *txn;
    MDBX_cursor *cursor;
    MDBX_val mkey, mdata;
    int rc;
    int entry_count = 0;

    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return 0;
    }

    rc = mdbx_cursor_open(txn, dbi, &cursor);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return 0;
    }

    /* Start database object */
    if (!*first) {
        fprintf(fp, ",\n");
    }
    *first = 0;
    fprintf(fp, "    \"%s\": {\n", db_name);

    int first_entry = 1;
    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_FIRST);
    while (rc == 0) {
        char key_str[LMDB_KEY_BUFFER_SIZE];
        char value_str[LMDB_MAX_VALUE_SIZE];

        /* Convert key to printable string (handle embedded nulls) */
        size_t key_len = mkey.iov_len < sizeof(key_str) - 1 ? mkey.iov_len : sizeof(key_str) - 1;
        memcpy(key_str, mkey.iov_base, key_len);
        key_str[key_len] = '\0';

        /* Replace embedded nulls with '|' for composite keys */
        for (size_t i = 0; i < key_len; i++) {
            if (key_str[i] == '\0') key_str[i] = '|';
        }

        /* Decompress and decode value if needed */
#ifdef WITH_ZSTD
        if (x3_is_compressed(mdata.iov_base, mdata.iov_len)) {
            unsigned char decompressed[LMDB_MAX_VALUE_SIZE];
            size_t decompressed_len;
            if (x3_decompress(mdata.iov_base, mdata.iov_len,
                              decompressed, sizeof(decompressed) - 1, &decompressed_len) >= 0) {
                memcpy(value_str, decompressed, decompressed_len);
                value_str[decompressed_len] = '\0';
            } else {
                snprintf(value_str, sizeof(value_str), "<compressed:%zu bytes>", mdata.iov_len);
            }
        } else
#endif
        {
            size_t val_len = mdata.iov_len < sizeof(value_str) - 1 ? mdata.iov_len : sizeof(value_str) - 1;
            memcpy(value_str, mdata.iov_base, val_len);
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

        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
    }

    fprintf(fp, "\n    }");

    mdbx_cursor_close(cursor);
    mdbx_txn_abort(txn);

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
 * Helper to purge expired entries from account/channel metadata databases.
 * Uses batched read/write transactions to avoid holding a write lock for the
 * entire scan — collects up to batch_size expired keys in a read txn, then
 * deletes them in a short write txn, and repeats.
 */
static unsigned long purge_metadata_db(MDBX_dbi dbi, const char *db_name)
{
    unsigned long purged = 0;
    time_t now = time(NULL);
    unsigned int batch_size = lmdb_purge_batch_size;

    if (!lmdb_initialized)
        return 0;

    /* Key collection buffer for batch deletes */
    char (*key_batch)[LMDB_KEY_BUFFER_SIZE] = NULL;
    size_t *key_lens = NULL;
    key_batch = malloc(batch_size * LMDB_KEY_BUFFER_SIZE);
    key_lens = malloc(batch_size * sizeof(size_t));
    if (!key_batch || !key_lens) {
        free(key_batch);
        free(key_lens);
        return 0;
    }

    /* Resume key for pagination across batches */
    char resume_key[LMDB_KEY_BUFFER_SIZE];
    size_t resume_key_len = 0;
    int has_resume = 0;

    {
    MDBX_txn *read_txn = NULL; /* Carried over from commit_embark_read */

    for (;;) {
        MDBX_txn *txn;
        MDBX_cursor *cursor;
        MDBX_val mkey, mdata;
        unsigned int collected = 0;
        int rc;
        char value_buf[LMDB_MAX_VALUE_SIZE];
        time_t expires;

        /* Phase 1: Read transaction — collect expired keys */
        if (read_txn) {
            txn = read_txn;
            read_txn = NULL;
        } else {
            rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
            if (rc != 0) {
                log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Purge %s: Failed to begin read txn: %s",
                           db_name, mdbx_strerror(rc));
                break;
            }
        }

        rc = mdbx_cursor_open(txn, dbi, &cursor);
        if (rc != 0) {
            mdbx_txn_abort(txn);
            break;
        }

        /* Position cursor: resume from last batch or start from beginning */
        if (has_resume) {
            mkey.iov_base = resume_key;
            mkey.iov_len = resume_key_len;
            rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);
            /* Skip the resume key itself (already processed) */
            if (rc == 0 && mkey.iov_len == resume_key_len &&
                memcmp(mkey.iov_base, resume_key, resume_key_len) == 0) {
                rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
            }
        } else {
            rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_FIRST);
        }

        while (rc == 0) {
            const char *stored = (const char *)mdata.iov_base;

            /* Save position for resume */
            if (mkey.iov_len < LMDB_KEY_BUFFER_SIZE) {
                memcpy(resume_key, mkey.iov_base, mkey.iov_len);
                resume_key_len = mkey.iov_len;
                has_resume = 1;
            }

            /* Check if entry has TTL prefix and is expired */
            if (stored[0] == 'T' && stored[1] == ':') {
                if (decode_ttl_value(stored, value_buf, sizeof(value_buf), &expires) == 0) {
                    if (expires > 0 && expires <= now) {
                        if (mkey.iov_len < LMDB_KEY_BUFFER_SIZE && collected < batch_size) {
                            memcpy(key_batch[collected], mkey.iov_base, mkey.iov_len);
                            key_lens[collected] = mkey.iov_len;
                            collected++;
                        }
                        if (collected >= batch_size)
                            break;
                    }
                }
            }

            rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
        }

        int scan_complete = (rc == MDBX_NOTFOUND && collected < batch_size);
        mdbx_cursor_close(cursor);
        mdbx_txn_abort(txn);

        if (collected == 0)
            break;

        /* Phase 2: Write transaction — delete collected keys */
        rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
        if (rc != 0)
            break;

        for (unsigned int i = 0; i < collected; i++) {
            MDBX_val dkey;
            dkey.iov_base = key_batch[i];
            dkey.iov_len = key_lens[i];
            rc = mdbx_del(txn, dbi, &dkey, NULL);
            if (rc == 0)
                purged++;
        }

        if (!scan_complete) {
            /* Commit write and immediately start read for next batch */
            rc = mdbx_txn_commit_embark_read(txn, &read_txn);
        } else {
            rc = mdbx_txn_commit(txn);
        }
        if (rc != 0) {
            log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Purge %s: Failed to commit batch: %s",
                       db_name, mdbx_strerror(rc));
            read_txn = NULL;
            break;
        }

        if (scan_complete)
            break;
    }

    if (read_txn)
        mdbx_txn_abort(read_txn);
    }

    free(key_batch);
    free(key_lens);

    if (purged > 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Purged %lu expired entries from %s",
                   purged, db_name);
    }

    return purged;
}

/**
 * Purge expired activity entries (30-day TTL).
 * Uses prefix-based cursor positioning and batched transactions.
 */
static unsigned long purge_activity_entries(void)
{
    unsigned long purged = 0;
    time_t now = time(NULL);
    const char *prefix = "activity:";
    size_t prefix_len = strlen(prefix);
    unsigned int batch_size = lmdb_purge_batch_size;

    if (!lmdb_initialized)
        return 0;

    char (*key_batch)[LMDB_KEY_BUFFER_SIZE] = NULL;
    size_t *key_lens = NULL;
    key_batch = malloc(batch_size * LMDB_KEY_BUFFER_SIZE);
    key_lens = malloc(batch_size * sizeof(size_t));
    if (!key_batch || !key_lens) {
        free(key_batch);
        free(key_lens);
        return 0;
    }

    char resume_key[LMDB_KEY_BUFFER_SIZE];
    size_t resume_key_len = 0;
    int has_resume = 0;

    {
    MDBX_txn *read_txn = NULL;

    for (;;) {
        MDBX_txn *txn;
        MDBX_cursor *cursor;
        MDBX_val mkey, mdata;
        unsigned int collected = 0;
        int rc;

        /* Phase 1: Read transaction — collect expired keys */
        if (read_txn) {
            txn = read_txn;
            read_txn = NULL;
        } else {
            rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
            if (rc != 0)
                break;
        }

        rc = mdbx_cursor_open(txn, dbi_metadata, &cursor);
        if (rc != 0) {
            mdbx_txn_abort(txn);
            break;
        }

        /* Position cursor at prefix range */
        if (has_resume) {
            mkey.iov_base = resume_key;
            mkey.iov_len = resume_key_len;
        } else {
            mkey.iov_base = (void *)prefix;
            mkey.iov_len = prefix_len;
        }
        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);

        /* Skip resume key if exact match */
        if (has_resume && rc == 0 && mkey.iov_len == resume_key_len &&
            memcmp(mkey.iov_base, resume_key, resume_key_len) == 0) {
            rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
        }

        while (rc == 0) {
            const char *key = (const char *)mkey.iov_base;

            /* Stop once past the prefix range */
            if (mkey.iov_len <= prefix_len || strncmp(key, prefix, prefix_len) != 0)
                break;

            /* Save position for resume */
            if (mkey.iov_len < LMDB_KEY_BUFFER_SIZE) {
                memcpy(resume_key, mkey.iov_base, mkey.iov_len);
                resume_key_len = mkey.iov_len;
                has_resume = 1;
            }

            const char *stored = (const char *)mdata.iov_base;
            if (stored[0] == 'T' && stored[1] == ':') {
                time_t expires = 0;
                char *colon = strchr(stored + 2, ':');
                if (colon) {
                    expires = (time_t)strtol(stored + 2, NULL, 10);
                    if (expires > 0 && expires <= now) {
                        if (mkey.iov_len < LMDB_KEY_BUFFER_SIZE && collected < batch_size) {
                            memcpy(key_batch[collected], mkey.iov_base, mkey.iov_len);
                            key_lens[collected] = mkey.iov_len;
                            collected++;
                        }
                        if (collected >= batch_size)
                            break;
                    }
                }
            }

            rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
        }

        int scan_complete = (collected < batch_size);
        mdbx_cursor_close(cursor);
        mdbx_txn_abort(txn);

        if (collected == 0)
            break;

        /* Phase 2: Write transaction — delete collected keys */
        rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
        if (rc != 0)
            break;

        for (unsigned int i = 0; i < collected; i++) {
            MDBX_val dkey;
            dkey.iov_base = key_batch[i];
            dkey.iov_len = key_lens[i];
            rc = mdbx_del(txn, dbi_metadata, &dkey, NULL);
            if (rc == 0)
                purged++;
        }

        if (!scan_complete) {
            rc = mdbx_txn_commit_embark_read(txn, &read_txn);
        } else {
            rc = mdbx_txn_commit(txn);
        }
        if (rc != 0) {
            read_txn = NULL;
            break;
        }

        if (scan_complete)
            break;
    }

    if (read_txn)
        mdbx_txn_abort(read_txn);
    }

    free(key_batch);
    free(key_lens);

    if (purged > 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Purged %lu expired activity entries", purged);
    }

    return purged;
}

/**
 * Purge expired fingerprint entries (90-day TTL).
 * Uses prefix-based cursor positioning and batched transactions.
 */
static unsigned long purge_fingerprint_entries(void)
{
    unsigned long purged = 0;
    time_t now = time(NULL);
    const char *prefix = "fp:";
    size_t prefix_len = strlen(prefix);
    unsigned int batch_size = lmdb_purge_batch_size;

    if (!lmdb_initialized)
        return 0;

    char (*key_batch)[LMDB_KEY_BUFFER_SIZE] = NULL;
    size_t *key_lens = NULL;
    key_batch = malloc(batch_size * LMDB_KEY_BUFFER_SIZE);
    key_lens = malloc(batch_size * sizeof(size_t));
    if (!key_batch || !key_lens) {
        free(key_batch);
        free(key_lens);
        return 0;
    }

    char resume_key[LMDB_KEY_BUFFER_SIZE];
    size_t resume_key_len = 0;
    int has_resume = 0;

    {
    MDBX_txn *read_txn = NULL;

    for (;;) {
        MDBX_txn *txn;
        MDBX_cursor *cursor;
        MDBX_val mkey, mdata;
        unsigned int collected = 0;
        int rc;

        /* Phase 1: Read transaction — collect expired keys */
        if (read_txn) {
            txn = read_txn;
            read_txn = NULL;
        } else {
            rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
            if (rc != 0)
                break;
        }

        rc = mdbx_cursor_open(txn, dbi_metadata, &cursor);
        if (rc != 0) {
            mdbx_txn_abort(txn);
            break;
        }

        if (has_resume) {
            mkey.iov_base = resume_key;
            mkey.iov_len = resume_key_len;
        } else {
            mkey.iov_base = (void *)prefix;
            mkey.iov_len = prefix_len;
        }
        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);

        if (has_resume && rc == 0 && mkey.iov_len == resume_key_len &&
            memcmp(mkey.iov_base, resume_key, resume_key_len) == 0) {
            rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
        }

        while (rc == 0) {
            const char *key = (const char *)mkey.iov_base;

            if (mkey.iov_len <= prefix_len || strncmp(key, prefix, prefix_len) != 0)
                break;

            if (mkey.iov_len < LMDB_KEY_BUFFER_SIZE) {
                memcpy(resume_key, mkey.iov_base, mkey.iov_len);
                resume_key_len = mkey.iov_len;
                has_resume = 1;
            }

            const char *stored = (const char *)mdata.iov_base;
            if (stored[0] == 'T' && stored[1] == ':') {
                time_t expires = 0;
                char *colon = strchr(stored + 2, ':');
                if (colon) {
                    expires = (time_t)strtol(stored + 2, NULL, 10);
                    if (expires > 0 && expires <= now) {
                        if (collected < batch_size) {
                            memcpy(key_batch[collected], mkey.iov_base, mkey.iov_len);
                            key_lens[collected] = mkey.iov_len;
                            collected++;
                        }
                        if (collected >= batch_size)
                            break;
                    }
                }
            }

            rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
        }

        int scan_complete = (collected < batch_size);
        mdbx_cursor_close(cursor);
        mdbx_txn_abort(txn);

        if (collected == 0)
            break;

        /* Phase 2: Write transaction — delete collected keys */
        rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
        if (rc != 0)
            break;

        for (unsigned int i = 0; i < collected; i++) {
            MDBX_val dkey;
            dkey.iov_base = key_batch[i];
            dkey.iov_len = key_lens[i];
            rc = mdbx_del(txn, dbi_metadata, &dkey, NULL);
            if (rc == 0)
                purged++;
        }

        if (!scan_complete) {
            rc = mdbx_txn_commit_embark_read(txn, &read_txn);
        } else {
            rc = mdbx_txn_commit(txn);
        }
        if (rc != 0) {
            read_txn = NULL;
            break;
        }

        if (scan_complete)
            break;
    }

    if (read_txn)
        mdbx_txn_abort(read_txn);
    }

    free(key_batch);
    free(key_lens);

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

void x3_lmdb_get_cache_stats(unsigned long *hits_out, unsigned long *misses_out, unsigned int *slots_out)
{
    if (hits_out) *hits_out = lmdb_cache_hits;
    if (misses_out) *misses_out = lmdb_cache_misses;
    if (slots_out) *slots_out = lmdb_cache_slots;
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
    MDBX_txn *txn;
    MDBX_val key, data;
    unsigned char random_bytes[SESSION_TOKEN_ID_LEN];
    char token_id[64];
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    char lmdb_value[256];
    unsigned int version = 0;
    int rc;

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

    /* Build version key: sessver:<username> */
    {
        char ver_key_buf[LMDB_KEY_BUFFER_SIZE];
        MDBX_val ver_key, ver_data;

        snprintf(ver_key_buf, sizeof(ver_key_buf), "%s%s", LMDB_PREFIX_SESSVER, username);
        ver_key.iov_len = strlen(ver_key_buf);
        ver_key.iov_base = ver_key_buf;

        /* Start as read transaction to atomically read version then write token */
        rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
        if (rc != 0) {
            log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: session_create txn_begin failed: %s",
                       mdbx_strerror(rc));
            return LMDB_ERROR;
        }

        /* Read current session version */
        rc = mdbx_get(txn, dbi_metadata, &ver_key, &ver_data);
        if (rc == 0) {
            version = (unsigned int)strtoul(ver_data.iov_base, NULL, 10);
        } else if (rc != MDBX_NOTFOUND) {
            mdbx_txn_abort(txn);
            return LMDB_ERROR;
        }

        /* Promote to write transaction on same MVCC snapshot */
        rc = mdbx_txn_amend(txn);
        if (rc == MDBX_RESULT_TRUE) {
            /* Snapshot advanced — re-read version */
            rc = mdbx_get(txn, dbi_metadata, &ver_key, &ver_data);
            if (rc == 0) {
                version = (unsigned int)strtoul(ver_data.iov_base, NULL, 10);
            } else if (rc != MDBX_NOTFOUND) {
                mdbx_txn_abort(txn);
                return LMDB_ERROR;
            }
        } else if (rc != MDBX_SUCCESS) {
            mdbx_txn_abort(txn);
            return LMDB_ERROR;
        }
    }

    /* Build LMDB key: session:<token_id> */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%s", LMDB_PREFIX_SESSION, token_id);

    /* Build LMDB value: expiry:version:username */
    time_t expiry = now + SESSION_TOKEN_TTL;
    snprintf(lmdb_value, sizeof(lmdb_value), "%lu:%u:%s", (unsigned long)expiry, version, username);

    /* Store the token (still in write txn from amend) */
    key.iov_len = strlen(lmdb_key);
    key.iov_base = lmdb_key;
    data.iov_len = strlen(lmdb_value) + 1;
    data.iov_base = lmdb_value;

    rc = mdbx_put(txn, dbi_metadata, &key, &data, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: session_create mdbx_put failed: %s",
                   mdbx_strerror(rc));
        return LMDB_ERROR;
    }

    /* Commit transaction */
    rc = mdbx_txn_commit(txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: session_create commit failed: %s",
                   mdbx_strerror(rc));
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
    MDBX_txn *txn;
    MDBX_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    const char *token_id;
    char *value_copy = NULL;
    char *expiry_str, *version_str, *username;
    time_t expiry;
    unsigned int stored_version, current_version = 0;
    int rc, need_delete = 0;

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

    /* Start read transaction — all reads + optional delete in one txn */
    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    /* Look up token */
    key.iov_len = strlen(lmdb_key);
    key.iov_base = lmdb_key;

    rc = mdbx_get(txn, dbi_metadata, &key, &data);
    if (rc == MDBX_NOTFOUND) {
        mdbx_txn_abort(txn);
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Parse value: expiry:version:username — copy since data points into mmap */
    value_copy = strndup(data.iov_base, data.iov_len);
    if (!value_copy) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    expiry_str = value_copy;
    version_str = strchr(expiry_str, ':');
    if (!version_str) {
        free(value_copy);
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }
    *version_str++ = '\0';

    username = strchr(version_str, ':');
    if (!username) {
        free(value_copy);
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }
    *username++ = '\0';

    expiry = (time_t)strtoul(expiry_str, NULL, 10);
    stored_version = (unsigned int)strtoul(version_str, NULL, 10);

    /* Check if token has expired */
    if (now >= expiry) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Session token expired for %s", username);
        need_delete = 1;
    }

    /* Check session version (for revoke-all support) — read in same txn */
    if (!need_delete) {
        char ver_key_buf[LMDB_KEY_BUFFER_SIZE];
        MDBX_val ver_key, ver_data;

        snprintf(ver_key_buf, sizeof(ver_key_buf), "%s%s", LMDB_PREFIX_SESSVER, username);
        ver_key.iov_len = strlen(ver_key_buf);
        ver_key.iov_base = ver_key_buf;

        rc = mdbx_get(txn, dbi_metadata, &ver_key, &ver_data);
        if (rc == 0) {
            current_version = (unsigned int)strtoul(ver_data.iov_base, NULL, 10);
        }

        if (stored_version < current_version) {
            log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Session token version mismatch for %s (%u < %u)",
                       username, stored_version, current_version);
            need_delete = 1;
        }
    }

    /* If token is invalid, promote to write and delete it atomically */
    if (need_delete) {
        rc = mdbx_txn_amend(txn);
        if (rc == MDBX_SUCCESS || rc == MDBX_RESULT_TRUE) {
            mdbx_del(txn, dbi_metadata, &key, NULL);
            mdbx_txn_commit(txn);
        } else {
            mdbx_txn_abort(txn);
        }
        free(value_copy);
        return LMDB_NOT_FOUND;
    }

    /* Token is valid — abort read txn */
    mdbx_txn_abort(txn);

    /* Copy username if requested */
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
    MDBX_txn *txn;
    MDBX_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    char version_str[32];
    unsigned int version = 0;
    int rc;

    if (!lmdb_initialized || !username) {
        return LMDB_ERROR;
    }

    /* Build key: sessver:<username> */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%s", LMDB_PREFIX_SESSVER, username);

    /* Start as read transaction to atomically read-then-write */
    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    key.iov_len = strlen(lmdb_key);
    key.iov_base = lmdb_key;

    /* Read current version */
    rc = mdbx_get(txn, dbi_metadata, &key, &data);
    if (rc == 0) {
        version = (unsigned int)strtoul(data.iov_base, NULL, 10);
    } else if (rc != MDBX_NOTFOUND) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Promote to write transaction on same MVCC snapshot */
    rc = mdbx_txn_amend(txn);
    if (rc == MDBX_RESULT_TRUE) {
        /* Snapshot advanced — re-read to get current version */
        rc = mdbx_get(txn, dbi_metadata, &key, &data);
        if (rc == 0) {
            version = (unsigned int)strtoul(data.iov_base, NULL, 10);
        } else if (rc != MDBX_NOTFOUND) {
            mdbx_txn_abort(txn);
            return LMDB_ERROR;
        }
    } else if (rc != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Increment and store new version */
    version++;
    snprintf(version_str, sizeof(version_str), "%u", version);

    data.iov_len = strlen(version_str) + 1;
    data.iov_base = version_str;

    rc = mdbx_put(txn, dbi_metadata, &key, &data, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Revoked all sessions for %s (version now %u)",
               username, version);

    return LMDB_SUCCESS;
}

int x3_lmdb_session_get_version(const char *username, unsigned int *version_out)
{
    MDBX_txn *txn;
    MDBX_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!lmdb_initialized || !username || !version_out) {
        return LMDB_ERROR;
    }

    /* Build key: sessver:<username> */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%s", LMDB_PREFIX_SESSVER, username);

    /* Start read transaction */
    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        *version_out = 0;
        return LMDB_ERROR;
    }

    key.iov_len = strlen(lmdb_key);
    key.iov_base = lmdb_key;

    rc = lmdb_cached_get(txn, dbi_metadata, &key, &data);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
        *version_out = 0;
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        *version_out = 0;
        return LMDB_ERROR;
    }

    *version_out = (unsigned int)strtoul(data.iov_base, NULL, 10);
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
    const char *nosync_str;
    const char *sync_interval_str;

    /* Get database path from configuration */
    dbpath = conf_get_data("services/x3/lmdb_path", RECDB_QSTRING);
    if (!dbpath) {
        dbpath = "x3data/lmdb";
    }

    /* Configure sync settings BEFORE opening environment */
    nosync_str = conf_get_data("services/x3/lmdb_nosync", RECDB_QSTRING);
    if (nosync_str && (atoi(nosync_str) || !strcasecmp(nosync_str, "yes") || !strcasecmp(nosync_str, "true"))) {
        lmdb_nosync = 1;
    }

    sync_interval_str = conf_get_data("services/x3/lmdb_sync_interval", RECDB_QSTRING);
    if (sync_interval_str) {
        unsigned int interval = (unsigned int)strtoul(sync_interval_str, NULL, 10);
        if (interval >= 1 && interval <= 300) {
            lmdb_sync_interval = interval;
        }
    }

    /* Configure auto-growth settings BEFORE opening environment */
    {
        const char *autogrow_str = conf_get_data("services/x3/lmdb_autogrow", RECDB_QSTRING);
        if (autogrow_str) {
            if (!strcasecmp(autogrow_str, "no") || !strcasecmp(autogrow_str, "false") || !strcmp(autogrow_str, "0")) {
                lmdb_autogrow = 0;
            } else {
                lmdb_autogrow = 1;
            }
        }

        const char *growth_step_str = conf_get_data("services/x3/lmdb_growth_step", RECDB_QSTRING);
        if (growth_step_str) {
            intptr_t step = (intptr_t)strtol(growth_step_str, NULL, 10);
            if (step >= 1024 * 1024 && step <= 256 * 1024 * 1024) {
                lmdb_growth_step = step;
            }
        }

        if (lmdb_autogrow) {
            log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Auto-growth enabled (step: %ld bytes, max: %lu bytes)",
                       (long)lmdb_growth_step, (unsigned long)lmdb_mapsize);
        } else {
            log_module(MAIN_LOG, LOG_INFO, "x3_lmdb: Auto-growth disabled (fixed size: %lu bytes)",
                       (unsigned long)lmdb_mapsize);
        }
    }

    /* Configure NORDAHEAD */
    {
        const char *nordahead_str = conf_get_data("services/x3/lmdb_nordahead", RECDB_QSTRING);
        if (nordahead_str) {
            if (!strcasecmp(nordahead_str, "no") || !strcasecmp(nordahead_str, "false") || !strcmp(nordahead_str, "0")) {
                lmdb_nordahead = 0;
            } else {
                lmdb_nordahead = 1;
            }
        }
    }

    /* Configure purge batch size */
    {
        const char *batch_str = conf_get_data("services/x3/lmdb_purge_batch_size", RECDB_QSTRING);
        if (batch_str) {
            unsigned int val = (unsigned int)strtoul(batch_str, NULL, 10);
            if (val >= 10 && val <= 10000)
                lmdb_purge_batch_size = val;
        }
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
    MDBX_txn *txn;
    MDBX_val key, data;
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
                          x3_lmdb_get_scram_iterations(),
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
             (unsigned long)expiry, (int)hash_type, x3_lmdb_get_scram_iterations(),
             salt_hex, stored_key_hex, server_key_hex, username);

    /* Start write transaction */
    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_create txn_begin failed: %s",
                   mdbx_strerror(rc));
        return LMDB_ERROR;
    }

    /* Store the credential */
    key.iov_len = strlen(lmdb_key);
    key.iov_base = lmdb_key;
    data.iov_len = strlen(value_buf) + 1;
    data.iov_base = value_buf;

    rc = mdbx_put(txn, dbi_metadata, &key, &data, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_create mdbx_put failed: %s",
                   mdbx_strerror(rc));
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_create commit failed: %s",
                   mdbx_strerror(rc));
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
    MDBX_txn *txn;
    MDBX_val key, data;
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
    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    key.iov_len = strlen(lmdb_key);
    key.iov_base = lmdb_key;

    rc = mdbx_get(txn, dbi_metadata, &key, &data);
    mdbx_txn_abort(txn);

    if (rc == MDBX_NOTFOUND) {
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
    value_copy = strndup(data.iov_base, data.iov_len);
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
    MDBX_txn *txn;
    MDBX_val key;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    int rc;

    if (!lmdb_initialized || !token_id) {
        return LMDB_ERROR;
    }

    snprintf(lmdb_key, sizeof(lmdb_key), "%s%d:%s", LMDB_PREFIX_SCRAM, (int)hash_type, token_id);

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    key.iov_len = strlen(lmdb_key);
    key.iov_base = lmdb_key;

    rc = mdbx_del(txn, dbi_metadata, &key, NULL);
    if (rc == MDBX_NOTFOUND) {
        mdbx_txn_abort(txn);
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
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

int x3_lmdb_scram_revoke_all(const char *username)
{
    int count = 0;
    char prefix[64];
    size_t prefix_len;
    unsigned int batch_size = lmdb_purge_batch_size;

    if (!lmdb_initialized || !username) {
        return -1;
    }

    snprintf(prefix, sizeof(prefix), "%s", LMDB_PREFIX_SCRAM);
    prefix_len = strlen(prefix);

    char (*key_batch)[LMDB_KEY_BUFFER_SIZE] = NULL;
    size_t *key_lens = NULL;
    key_batch = malloc(batch_size * LMDB_KEY_BUFFER_SIZE);
    key_lens = malloc(batch_size * sizeof(size_t));
    if (!key_batch || !key_lens) {
        free(key_batch);
        free(key_lens);
        return -1;
    }

    char resume_key[LMDB_KEY_BUFFER_SIZE];
    size_t resume_key_len = 0;
    int has_resume = 0;

    MDBX_txn *read_txn = NULL;

    for (;;) {
        MDBX_txn *txn;
        MDBX_cursor *cursor;
        MDBX_val key, data;
        unsigned int collected = 0;
        int rc;

        /* Phase 1: Read transaction — find matching keys */
        if (read_txn) {
            txn = read_txn;
            read_txn = NULL;
        } else {
            rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
            if (rc != 0)
                break;
        }

        rc = mdbx_cursor_open(txn, dbi_metadata, &cursor);
        if (rc != 0) {
            mdbx_txn_abort(txn);
            break;
        }

        if (has_resume) {
            key.iov_base = resume_key;
            key.iov_len = resume_key_len;
        } else {
            key.iov_base = prefix;
            key.iov_len = prefix_len;
        }
        rc = mdbx_cursor_get(cursor, &key, &data, MDBX_SET_RANGE);

        if (has_resume && rc == 0 && key.iov_len == resume_key_len &&
            memcmp(key.iov_base, resume_key, resume_key_len) == 0) {
            rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
        }

        while (rc == 0) {
            if (key.iov_len <= prefix_len ||
                memcmp(key.iov_base, prefix, prefix_len) != 0)
                break;

            if (key.iov_len < LMDB_KEY_BUFFER_SIZE) {
                memcpy(resume_key, key.iov_base, key.iov_len);
                resume_key_len = key.iov_len;
                has_resume = 1;
            }

            /* Check if this credential belongs to the user */
            char *value_copy = strndup(data.iov_base, data.iov_len);
            if (value_copy) {
                char *p = value_copy;
                int colons = 0;
                while (*p && colons < 5) {
                    if (*p == ':') colons++;
                    p++;
                }
                if (colons == 5 && strcasecmp(p, username) == 0) {
                    if (key.iov_len < LMDB_KEY_BUFFER_SIZE && collected < batch_size) {
                        memcpy(key_batch[collected], key.iov_base, key.iov_len);
                        key_lens[collected] = key.iov_len;
                        collected++;
                    }
                }
                free(value_copy);
            }

            if (collected >= batch_size)
                break;

            rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
        }

        int scan_complete = (collected < batch_size);
        mdbx_cursor_close(cursor);
        mdbx_txn_abort(txn);

        if (collected == 0)
            break;

        /* Phase 2: Write transaction — delete collected keys */
        rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
        if (rc != 0)
            break;

        for (unsigned int i = 0; i < collected; i++) {
            MDBX_val dkey;
            dkey.iov_base = key_batch[i];
            dkey.iov_len = key_lens[i];
            rc = mdbx_del(txn, dbi_metadata, &dkey, NULL);
            if (rc == 0)
                count++;
        }

        if (!scan_complete) {
            rc = mdbx_txn_commit_embark_read(txn, &read_txn);
            if (rc != MDBX_SUCCESS)
                read_txn = NULL;
        } else {
            mdbx_txn_commit(txn);
        }

        if (scan_complete)
            break;
    }

    if (read_txn)
        mdbx_txn_abort(read_txn);

    free(key_batch);
    free(key_lens);

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
    MDBX_txn *txn;
    MDBX_val key, data;
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
                          x3_lmdb_get_scram_iterations(),
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
             (int)hash_type, x3_lmdb_get_scram_iterations(),
             salt_hex, stored_key_hex, server_key_hex, account);

    /* Start write transaction */
    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_acct_create txn_begin failed: %s",
                   mdbx_strerror(rc));
        return LMDB_ERROR;
    }

    /* Store the credential */
    key.iov_len = strlen(lmdb_key);
    key.iov_base = lmdb_key;
    data.iov_len = strlen(value_buf) + 1;
    data.iov_base = value_buf;

    rc = mdbx_put(txn, dbi_metadata, &key, &data, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_acct_create mdbx_put failed: %s",
                   mdbx_strerror(rc));
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_acct_create commit failed: %s",
                   mdbx_strerror(rc));
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

/* ========== Async SCRAM Creation (Threadpool) ========== */

#ifdef HAVE_PTHREAD_H

/* Work context for async SCRAM creation */
struct scram_async_work {
    char account[128];           /* Account name */
    char password[256];          /* Plaintext password (cleared after use) */
    scram_async_callback callback;
    void *user_ctx;
    int result;                  /* Number of credentials created */
};

/* Worker function - runs in threadpool thread */
static void *scram_async_worker(void *arg)
{
    struct scram_async_work *work = arg;

    /* Do the actual SCRAM creation (blocking PBKDF2) */
    work->result = x3_lmdb_scram_acct_create_all(work->account, work->password);

    /* Clear password from memory immediately */
    memset(work->password, 0, sizeof(work->password));

    return work;
}

/* Callback wrapper - runs in main thread */
static void scram_async_done(void *result, void *user_data, tp_state_t state)
{
    struct scram_async_work *work = result;

    (void)user_data;  /* Unused */

    if (state == TP_STATE_COMPLETED) {
        if (work->callback) {
            work->callback(work->user_ctx, work->result);
        }
    } else {
        /* Task was cancelled or failed */
        if (work->callback) {
            work->callback(work->user_ctx, -1);
        }
    }

    /* Final cleanup - ensure password is cleared */
    memset(work->password, 0, sizeof(work->password));
    free(work);
}

int x3_lmdb_scram_acct_create_all_async(const char *account, const char *password,
                                         scram_async_callback callback, void *ctx)
{
    struct scram_async_work *work;

    if (!account || !password || !callback) {
        return -1;
    }

    if (!threadpool_is_initialized()) {
        /* Fallback to sync - call callback directly */
        int result = x3_lmdb_scram_acct_create_all(account, password);
        callback(ctx, result);
        return 0;
    }

    /* Allocate work structure */
    work = calloc(1, sizeof(*work));
    if (!work) {
        return -1;
    }

    /* Initialize work */
    strncpy(work->account, account, sizeof(work->account) - 1);
    strncpy(work->password, password, sizeof(work->password) - 1);
    work->callback = callback;
    work->user_ctx = ctx;

    /* Submit to threadpool - SCRAM creation is lower priority than password verify */
    if (!threadpool_submit(scram_async_worker, work, scram_async_done, NULL, TP_PRIORITY_NORMAL)) {
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Failed to submit async SCRAM creation");
        memset(work->password, 0, sizeof(work->password));
        free(work);
        return -1;
    }

    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Async SCRAM creation started for account %s", account);
    return 0;
}

#else /* !HAVE_PTHREAD_H */

/* Stub implementation without pthreads - just call sync version */
int x3_lmdb_scram_acct_create_all_async(const char *account, const char *password,
                                         scram_async_callback callback, void *ctx)
{
    int result;

    if (!account || !password || !callback)
        return -1;

    result = x3_lmdb_scram_acct_create_all(account, password);
    callback(ctx, result);
    return 0;
}

#endif /* HAVE_PTHREAD_H */

/**
 * Get SCRAM credential for an account with specified hash type.
 */
int x3_lmdb_scram_acct_get(const char *account, enum scram_hash_type hash_type,
                            struct scram_credential *cred_out)
{
    MDBX_txn *txn;
    MDBX_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    char *value_copy, *p, *fields[7];
    int field_count = 0;
    size_t hash_len;
    int rc;

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
    rc = mdbx_txn_begin(lmdb_env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != 0) {
        return LMDB_ERROR;
    }

    key.iov_len = strlen(lmdb_key);
    key.iov_base = lmdb_key;

    rc = lmdb_cached_get(txn, dbi_metadata, &key, &data);
    if (rc == MDBX_NOTFOUND) {
        mdbx_txn_abort(txn);
        return LMDB_NOT_FOUND;
    }
    if (rc != 0) {
        mdbx_txn_abort(txn);
        return LMDB_ERROR;
    }

    /* Parse value: 0:hashtype:iteration:salt:storedkey:serverkey:account */
    value_copy = strndup(data.iov_base, data.iov_len);
    mdbx_txn_abort(txn);

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

    /* Parse salt from hex (hex_to_bytes returns 0 on success, -1 on failure) */
    if (hex_to_bytes(fields[3], cred_out->salt, SCRAM_SALT_LEN) != 0) {
        free(value_copy);
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Invalid SCRAM salt for %s", account);
        return LMDB_ERROR;
    }

    /* Parse stored_key from hex */
    if (hex_to_bytes(fields[4], cred_out->stored_key, hash_len) != 0) {
        free(value_copy);
        log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: Invalid SCRAM stored_key for %s", account);
        return LMDB_ERROR;
    }

    /* Parse server_key from hex */
    if (hex_to_bytes(fields[5], cred_out->server_key, hash_len) != 0) {
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
    MDBX_txn *txn;
    MDBX_val key;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    int rc, count = 0;
    enum scram_hash_type hash_types[] = { SCRAM_HASH_SHA1, SCRAM_HASH_SHA256, SCRAM_HASH_SHA512 };
    size_t i;

    if (!lmdb_initialized || !account) {
        return -1;
    }

    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return -1;
    }

    /* Delete each hash type */
    for (i = 0; i < sizeof(hash_types) / sizeof(hash_types[0]); i++) {
        snprintf(lmdb_key, sizeof(lmdb_key), "%s%d:%s",
                 LMDB_PREFIX_SCRAM_ACCT, (int)hash_types[i], account);

        key.iov_len = strlen(lmdb_key);
        key.iov_base = lmdb_key;

        rc = mdbx_del(txn, dbi_metadata, &key, NULL);
        if (rc == 0) {
            count++;
        }
    }

    rc = mdbx_txn_commit(txn);
    if (rc != 0) {
        return -1;
    }

    if (count > 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Deleted %d SCRAM credential(s) for account %s",
                   count, account);
    }

    return count;
}

/**
 * Set SCRAM credential for an account from pre-computed base64 values (SHA-256 only).
 * Used by Keycloak webhook to pre-populate cache with credentials generated
 * by the Keycloak SPI.
 */
int x3_lmdb_scram_acct_set(const char *account,
                           const char *salt_b64,
                           int iterations,
                           const char *stored_key_b64,
                           const char *server_key_b64,
                           time_t timestamp,
                           time_t ttl)
{
    MDBX_txn *txn;
    MDBX_val key, data;
    char lmdb_key[LMDB_KEY_BUFFER_SIZE];
    char value_buf[512];
    unsigned char salt[SCRAM_SALT_LEN];
    unsigned char stored_key[SCRAM_SHA256_LEN];
    unsigned char server_key[SCRAM_SHA256_LEN];
    char salt_hex[SCRAM_SALT_LEN * 2 + 1];
    char stored_key_hex[SCRAM_SHA256_LEN * 2 + 1];
    char server_key_hex[SCRAM_SHA256_LEN * 2 + 1];
    size_t decoded_len;
    time_t expiry;
    int rc, i;

    if (!lmdb_initialized || !account || !salt_b64 || !stored_key_b64 || !server_key_b64) {
        return LMDB_ERROR;
    }

    /* Decode base64 values */
    {
        char *decoded_salt;
        if (!base64_decode_alloc(salt_b64, strlen(salt_b64), &decoded_salt, &decoded_len) ||
            decoded_len != SCRAM_SALT_LEN) {
            log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: scram_acct_set invalid salt for %s", account);
            return LMDB_ERROR;
        }
        memcpy(salt, decoded_salt, SCRAM_SALT_LEN);
        free(decoded_salt);
    }

    {
        char *decoded_stored;
        if (!base64_decode_alloc(stored_key_b64, strlen(stored_key_b64), &decoded_stored, &decoded_len) ||
            decoded_len != SCRAM_SHA256_LEN) {
            log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: scram_acct_set invalid stored_key for %s", account);
            return LMDB_ERROR;
        }
        memcpy(stored_key, decoded_stored, SCRAM_SHA256_LEN);
        free(decoded_stored);
    }

    {
        char *decoded_server;
        if (!base64_decode_alloc(server_key_b64, strlen(server_key_b64), &decoded_server, &decoded_len) ||
            decoded_len != SCRAM_SHA256_LEN) {
            log_module(MAIN_LOG, LOG_WARNING, "x3_lmdb: scram_acct_set invalid server_key for %s", account);
            return LMDB_ERROR;
        }
        memcpy(server_key, decoded_server, SCRAM_SHA256_LEN);
        free(decoded_server);
    }

    /* Convert to hex for storage (same format as scram_acct_create) */
    for (i = 0; i < SCRAM_SALT_LEN; i++) {
        sprintf(salt_hex + i * 2, "%02x", salt[i]);
    }
    salt_hex[SCRAM_SALT_LEN * 2] = '\0';

    for (i = 0; i < SCRAM_SHA256_LEN; i++) {
        sprintf(stored_key_hex + i * 2, "%02x", stored_key[i]);
        sprintf(server_key_hex + i * 2, "%02x", server_key[i]);
    }
    stored_key_hex[SCRAM_SHA256_LEN * 2] = '\0';
    server_key_hex[SCRAM_SHA256_LEN * 2] = '\0';

    /* Calculate expiry */
    expiry = ttl > 0 ? timestamp + ttl : 0;

    /* Build LMDB key: scram_acct:<hash_type>:<account> */
    snprintf(lmdb_key, sizeof(lmdb_key), "%s%d:%s",
             LMDB_PREFIX_SCRAM_ACCT, (int)SCRAM_HASH_SHA256, account);

    /* Build value: expiry:hashtype:iteration:salt:storedkey:serverkey:account */
    snprintf(value_buf, sizeof(value_buf), "%lu:%d:%d:%s:%s:%s:%s",
             (unsigned long)expiry, (int)SCRAM_HASH_SHA256, iterations,
             salt_hex, stored_key_hex, server_key_hex, account);

    /* Start write transaction */
    rc = mdbx_txn_begin(lmdb_env, NULL, 0, &txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_acct_set txn_begin failed: %s",
                   mdbx_strerror(rc));
        return LMDB_ERROR;
    }

    /* Store the credential */
    key.iov_len = strlen(lmdb_key);
    key.iov_base = lmdb_key;
    data.iov_len = strlen(value_buf) + 1;
    data.iov_base = value_buf;

    rc = mdbx_put(txn, dbi_metadata, &key, &data, 0);
    if (rc != 0) {
        mdbx_txn_abort(txn);
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_acct_set mdbx_put failed: %s",
                   mdbx_strerror(rc));
        return LMDB_ERROR;
    }

    rc = mdbx_txn_commit(txn);
    if (rc != 0) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_lmdb: scram_acct_set commit failed: %s",
                   mdbx_strerror(rc));
        return LMDB_ERROR;
    }

    log_module(MAIN_LOG, LOG_DEBUG, "x3_lmdb: Set SCRAM-SHA-256 credential for account %s from webhook",
               account);

    return LMDB_SUCCESS;
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

int x3_lmdb_scram_acct_set(const char *account,
                           const char *salt_b64,
                           int iterations,
                           const char *stored_key_b64,
                           const char *server_key_b64,
                           time_t timestamp,
                           time_t ttl)
{
    (void)account; (void)salt_b64; (void)iterations;
    (void)stored_key_b64; (void)server_key_b64;
    (void)timestamp; (void)ttl;
    return LMDB_ERROR;
}

#endif /* WITH_SSL */

#endif /* WITH_MDBX */
