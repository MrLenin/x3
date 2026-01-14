/* mempool.c - Memory pool allocator implementation
 * Copyright 2025 AfterNET Development Team
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
 */

#include "common.h"
#include "mempool.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Magic numbers for debug builds */
#ifndef NDEBUG
#define MEMPOOL_MAGIC       0xDEADBEEF
#define MEMPOOL_FREE_MAGIC  0xFEEDFACE
#define MEMPOOL_ALLOC_MAGIC 0xCAFEBABE
#endif

/* Maximum number of pools we track for dump_all */
#define MAX_POOLS 64

/* Slab structure - a chunk of pre-allocated objects */
struct slab {
    struct slab *next;
    unsigned int capacity;
    unsigned int used;
    char data[];  /* Flexible array member */
};

/* Object header (hidden before user data) */
struct pool_obj_header {
    mempool_t *pool;             /* Owner pool for validation */
    struct pool_obj_header *next_free;  /* Next in free list (when free) */
#ifndef NDEBUG
    unsigned int magic;          /* For corruption detection */
    unsigned int alloc_seq;      /* Allocation sequence number */
#endif
};

/* Memory pool structure */
struct mempool {
    const char *name;
    size_t object_size;          /* User-requested size */
    size_t slot_size;            /* Size including header, aligned */
    size_t alignment;

    /* Free list (LIFO for cache locality) */
    struct pool_obj_header *free_list;
    unsigned int free_count;

    /* Slabs (chunks of memory) */
    struct slab *slabs;
    unsigned int slab_count;

    /* Configuration */
    unsigned int grow_count;
    unsigned int max_count;

    /* Statistics */
    unsigned long total_objects;
    unsigned long alloc_count;
    unsigned long free_count_stat;
    unsigned long grow_count_stat;
    unsigned long peak_usage;
    size_t memory_used;

#ifndef NDEBUG
    unsigned int magic;
    unsigned int next_alloc_seq;
#endif
};

/* Global pool registry */
static mempool_t *pool_registry[MAX_POOLS];
static unsigned int pool_count = 0;
static struct log_type *MP_LOG;

/* Global pools */
mempool_t *mp_msgbuf = NULL;
mempool_t *mp_string64 = NULL;
mempool_t *mp_string256 = NULL;
mempool_t *mp_curl_ctx = NULL;
mempool_t *mp_timeq = NULL;

/* Structure pools */
mempool_t *mp_auth_ctx = NULL;
mempool_t *mp_cookie_ctx = NULL;
mempool_t *mp_userdata = NULL;
mempool_t *mp_nickinfo = NULL;
mempool_t *mp_bandata = NULL;

/* I/O queue buffer pools */
mempool_t *mp_ioq_1k = NULL;
mempool_t *mp_ioq_4k = NULL;
mempool_t *mp_ioq_16k = NULL;

/* Helper: round up to alignment */
static size_t
align_up(size_t size, size_t alignment)
{
    return (size + alignment - 1) & ~(alignment - 1);
}

/* Helper: add a slab to a pool */
static int
mempool_add_slab(mempool_t *pool, unsigned int count)
{
    struct slab *slab;
    size_t slab_size;
    unsigned int i;
    char *ptr;

    /* Check max_count limit */
    if (pool->max_count > 0 && pool->total_objects + count > pool->max_count) {
        count = pool->max_count - pool->total_objects;
        if (count == 0)
            return -1;
    }

    slab_size = sizeof(struct slab) + (pool->slot_size * count);
    slab = malloc(slab_size);
    if (!slab)
        return -1;

    slab->capacity = count;
    slab->used = 0;
    slab->next = pool->slabs;
    pool->slabs = slab;
    pool->slab_count++;
    pool->memory_used += slab_size;
    pool->grow_count_stat++;

    /* Add all slots to free list */
    ptr = slab->data;
    for (i = 0; i < count; i++) {
        struct pool_obj_header *hdr = (struct pool_obj_header *)ptr;
        hdr->pool = pool;
        hdr->next_free = pool->free_list;
#ifndef NDEBUG
        hdr->magic = MEMPOOL_FREE_MAGIC;
        hdr->alloc_seq = 0;
#endif
        pool->free_list = hdr;
        pool->free_count++;
        pool->total_objects++;
        ptr += pool->slot_size;
    }

    return 0;
}

mempool_t *
mempool_create(const char *name, size_t object_size, size_t alignment,
               unsigned int initial_count, unsigned int max_count,
               unsigned int grow_count)
{
    mempool_t *pool;
    size_t header_size;

    if (object_size == 0)
        return NULL;

    pool = calloc(1, sizeof(*pool));
    if (!pool)
        return NULL;

    /* Default alignment to pointer size */
    if (alignment == 0)
        alignment = sizeof(void *);

    /* Calculate slot size: header + object, aligned */
    header_size = align_up(sizeof(struct pool_obj_header), alignment);
    pool->slot_size = header_size + align_up(object_size, alignment);

    pool->name = name ? name : "unnamed";
    pool->object_size = object_size;
    pool->alignment = alignment;
    pool->grow_count = grow_count > 0 ? grow_count : 32;
    pool->max_count = max_count;

#ifndef NDEBUG
    pool->magic = MEMPOOL_MAGIC;
    pool->next_alloc_seq = 1;
#endif

    /* Preallocate initial objects */
    if (initial_count > 0) {
        if (mempool_add_slab(pool, initial_count) < 0) {
            free(pool);
            return NULL;
        }
    }

    /* Register pool for dump_all */
    if (pool_count < MAX_POOLS) {
        pool_registry[pool_count++] = pool;
    }

    return pool;
}

void
mempool_destroy(mempool_t *pool, int check_leaks)
{
    struct slab *slab, *next;
    unsigned int i;

    if (!pool)
        return;

#ifndef NDEBUG
    if (pool->magic != MEMPOOL_MAGIC) {
        log_module(MP_LOG, LOG_ERROR,
                   "mempool_destroy: pool corruption detected (bad magic)");
        return;
    }
#endif

    if (check_leaks && pool->free_count != pool->total_objects) {
        unsigned long leaked = pool->total_objects - pool->free_count;
        log_module(MP_LOG, LOG_WARNING,
                   "mempool '%s': %lu objects leaked (total=%lu, free=%u)",
                   pool->name, leaked, pool->total_objects, pool->free_count);
    }

    /* Free all slabs */
    for (slab = pool->slabs; slab; slab = next) {
        next = slab->next;
        free(slab);
    }

    /* Unregister from pool registry */
    for (i = 0; i < pool_count; i++) {
        if (pool_registry[i] == pool) {
            pool_registry[i] = pool_registry[--pool_count];
            break;
        }
    }

#ifndef NDEBUG
    pool->magic = 0;
#endif
    free(pool);
}

void *
mempool_alloc(mempool_t *pool)
{
    struct pool_obj_header *hdr;
    void *obj;
    unsigned long in_use;

    if (!pool)
        return NULL;

#ifndef NDEBUG
    if (pool->magic != MEMPOOL_MAGIC) {
        log_module(MP_LOG, LOG_ERROR,
                   "mempool_alloc: pool corruption detected");
        return NULL;
    }
#endif

    /* Grow pool if empty */
    if (!pool->free_list) {
        if (mempool_add_slab(pool, pool->grow_count) < 0)
            return NULL;
    }

    /* Pop from free list */
    hdr = pool->free_list;
    pool->free_list = hdr->next_free;
    pool->free_count--;
    pool->alloc_count++;

#ifndef NDEBUG
    if (hdr->magic != MEMPOOL_FREE_MAGIC) {
        log_module(MP_LOG, LOG_ERROR,
                   "mempool_alloc: object corruption detected (double alloc?)");
        return NULL;
    }
    hdr->magic = MEMPOOL_ALLOC_MAGIC;
    hdr->alloc_seq = pool->next_alloc_seq++;
#endif

    /* Track peak usage */
    in_use = pool->total_objects - pool->free_count;
    if (in_use > pool->peak_usage)
        pool->peak_usage = in_use;

    /* Return pointer past header */
    obj = (char *)hdr + align_up(sizeof(struct pool_obj_header), pool->alignment);
    return obj;
}

void *
mempool_zalloc(mempool_t *pool)
{
    void *obj = mempool_alloc(pool);
    if (obj)
        memset(obj, 0, pool->object_size);
    return obj;
}

void
mempool_free(mempool_t *pool, void *obj)
{
    struct pool_obj_header *hdr;
    size_t header_offset;

    if (!pool || !obj)
        return;

#ifndef NDEBUG
    if (pool->magic != MEMPOOL_MAGIC) {
        log_module(MP_LOG, LOG_ERROR,
                   "mempool_free: pool corruption detected");
        return;
    }
#endif

    /* Get header from object pointer */
    header_offset = align_up(sizeof(struct pool_obj_header), pool->alignment);
    hdr = (struct pool_obj_header *)((char *)obj - header_offset);

#ifndef NDEBUG
    if (hdr->magic != MEMPOOL_ALLOC_MAGIC) {
        log_module(MP_LOG, LOG_ERROR,
                   "mempool_free: object corruption or double free detected");
        return;
    }
    if (hdr->pool != pool) {
        log_module(MP_LOG, LOG_ERROR,
                   "mempool_free: object returned to wrong pool");
        return;
    }
    hdr->magic = MEMPOOL_FREE_MAGIC;
#endif

    /* Push to free list (LIFO for cache locality) */
    hdr->next_free = pool->free_list;
    pool->free_list = hdr;
    pool->free_count++;
    pool->free_count_stat++;
}

void
mempool_get_stats(mempool_t *pool, struct mempool_stats *stats)
{
    if (!pool || !stats)
        return;

    stats->name = pool->name;
    stats->object_size = pool->object_size;
    stats->alignment = pool->alignment;
    stats->total_objects = pool->total_objects;
    stats->free_objects = pool->free_count;
    stats->alloc_count = pool->alloc_count;
    stats->free_count = pool->free_count_stat;
    stats->grow_count = pool->grow_count_stat;
    stats->peak_usage = pool->peak_usage;
    stats->memory_used = pool->memory_used;
}

size_t
mempool_shrink(mempool_t *pool, unsigned int keep_free)
{
    /*
     * Shrinking is complex for slab allocators because we can't free
     * individual objects back to the system - we'd need to free entire
     * slabs, which requires tracking which objects belong to which slab.
     *
     * For now, this is a no-op. A more sophisticated implementation could:
     * 1. Track slab membership for each object
     * 2. Move objects between slabs to consolidate
     * 3. Free completely empty slabs
     */
    (void)pool;
    (void)keep_free;
    return 0;
}

void
mempool_dump_all(void)
{
    unsigned int i;
    struct mempool_stats stats;

    log_module(MP_LOG, LOG_INFO, "=== Memory Pool Status ===");
    log_module(MP_LOG, LOG_INFO, "%-16s %8s %8s %8s %8s %10s",
               "Pool", "ObjSize", "Total", "Free", "Peak", "Memory");

    for (i = 0; i < pool_count; i++) {
        mempool_get_stats(pool_registry[i], &stats);
        log_module(MP_LOG, LOG_INFO, "%-16s %8zu %8lu %8lu %8lu %10zu",
                   stats.name, stats.object_size, stats.total_objects,
                   stats.free_objects, stats.peak_usage, stats.memory_used);
    }

    log_module(MP_LOG, LOG_INFO, "=== End Memory Pool Status ===");
}

unsigned int
mempool_count(void)
{
    return pool_count;
}

int
mempool_init_global(void)
{
    /* Initialize logging */
    MP_LOG = log_register_type("mempool", "file:mempool.log");

    /* Create message buffer pool (512 bytes, common IRC message size) */
    mp_msgbuf = mempool_create("msgbuf", 512, 8, 100, 0, 50);
    if (!mp_msgbuf)
        goto fail;

    /* Create string pools */
    mp_string64 = mempool_create("string64", 64, 8, 200, 0, 100);
    if (!mp_string64)
        goto fail;

    mp_string256 = mempool_create("string256", 256, 8, 100, 0, 50);
    if (!mp_string256)
        goto fail;

    /* Create CURL context pool */
    mp_curl_ctx = mempool_create("curl_ctx", 128, 8, 20, 100, 10);
    if (!mp_curl_ctx)
        goto fail;

    /* Create timer queue entry pool (struct timeq_entry ~16 bytes) */
    mp_timeq = mempool_create("timeq", 24, 8, 100, 0, 50);
    if (!mp_timeq)
        goto fail;

    /* Structure pools for frequently allocated objects */

    /* auth_async_ctx: ~200 bytes, high frequency during SASL auth */
    mp_auth_ctx = mempool_create("auth_ctx", 200, 8, 50, 0, 25);
    if (!mp_auth_ctx)
        goto fail;

    /* cookie_async_ctx: ~260 bytes, account activation flows */
    mp_cookie_ctx = mempool_create("cookie_ctx", 264, 8, 20, 0, 10);
    if (!mp_cookie_ctx)
        goto fail;

    /* userData: ~120 bytes, very high frequency on channel joins */
    mp_userdata = mempool_create("userdata", 128, 8, 200, 0, 100);
    if (!mp_userdata)
        goto fail;

    /* nick_info: ~64 bytes, nick registration */
    mp_nickinfo = mempool_create("nickinfo", 64, 8, 100, 0, 50);
    if (!mp_nickinfo)
        goto fail;

    /* banData: ~216 bytes (118 mask + 31 owner + 8 channel + 24 times + 8 reason + 16 prev/next + padding) */
    mp_bandata = mempool_create("bandata", 232, 8, 50, 0, 25);
    if (!mp_bandata)
        goto fail;

    /* I/O queue buffer pools - tiered sizes for ioset.c */
    /* 1KB: initial ioq allocation, very high frequency */
    mp_ioq_1k = mempool_create("ioq_1k", 1024, 8, 50, 0, 25);
    if (!mp_ioq_1k)
        goto fail;

    /* 4KB: common grow size (1024 -> 2048 -> 4096) */
    mp_ioq_4k = mempool_create("ioq_4k", 4096, 8, 20, 0, 10);
    if (!mp_ioq_4k)
        goto fail;

    /* 16KB: large transfers */
    mp_ioq_16k = mempool_create("ioq_16k", 16384, 8, 10, 0, 5);
    if (!mp_ioq_16k)
        goto fail;

    log_module(MP_LOG, LOG_INFO, "Global memory pools initialized");
    return 0;

fail:
    mempool_cleanup_global();
    return -1;
}

void
mempool_cleanup_global(void)
{
    if (mp_msgbuf) {
        mempool_destroy(mp_msgbuf, 1);
        mp_msgbuf = NULL;
    }
    if (mp_string64) {
        mempool_destroy(mp_string64, 1);
        mp_string64 = NULL;
    }
    if (mp_string256) {
        mempool_destroy(mp_string256, 1);
        mp_string256 = NULL;
    }
    if (mp_curl_ctx) {
        mempool_destroy(mp_curl_ctx, 1);
        mp_curl_ctx = NULL;
    }
    if (mp_timeq) {
        mempool_destroy(mp_timeq, 1);
        mp_timeq = NULL;
    }

    /* Structure pools */
    if (mp_auth_ctx) {
        mempool_destroy(mp_auth_ctx, 1);
        mp_auth_ctx = NULL;
    }
    if (mp_cookie_ctx) {
        mempool_destroy(mp_cookie_ctx, 1);
        mp_cookie_ctx = NULL;
    }
    if (mp_userdata) {
        mempool_destroy(mp_userdata, 1);
        mp_userdata = NULL;
    }
    if (mp_nickinfo) {
        mempool_destroy(mp_nickinfo, 1);
        mp_nickinfo = NULL;
    }
    if (mp_bandata) {
        mempool_destroy(mp_bandata, 1);
        mp_bandata = NULL;
    }

    /* I/O queue buffer pools */
    if (mp_ioq_1k) {
        mempool_destroy(mp_ioq_1k, 1);
        mp_ioq_1k = NULL;
    }
    if (mp_ioq_4k) {
        mempool_destroy(mp_ioq_4k, 1);
        mp_ioq_4k = NULL;
    }
    if (mp_ioq_16k) {
        mempool_destroy(mp_ioq_16k, 1);
        mp_ioq_16k = NULL;
    }

    log_module(MP_LOG, LOG_INFO, "Global memory pools cleaned up");
}

char *
pool_strdup(const char *str)
{
    size_t len;
    char *s;
    mempool_t *pool;

    if (!str)
        return NULL;

    len = strlen(str) + 1;

    /* Select appropriate pool */
    if (len <= 64 && mp_string64) {
        pool = mp_string64;
    } else if (len <= 256 && mp_string256) {
        pool = mp_string256;
    } else {
        /* Too large for pools, use regular malloc */
        return strdup(str);
    }

    s = mempool_alloc(pool);
    if (s)
        memcpy(s, str, len);
    return s;
}

void
pool_strfree(char *str)
{
    struct pool_obj_header *hdr;
    size_t header_offset;
    size_t len;

    if (!str)
        return;

    /*
     * Check string length first to determine if it COULD have come from a pool.
     * Only pool-sized strings have headers we can safely read.
     * Strings > 256 bytes are allocated via strdup(), no header exists.
     */
    len = strlen(str) + 1;

    if (len <= 64 && mp_string64) {
        header_offset = align_up(sizeof(struct pool_obj_header), mp_string64->alignment);
        hdr = (struct pool_obj_header *)((char *)str - header_offset);
        if (hdr->pool == mp_string64) {
            mempool_free(mp_string64, str);
            return;
        }
    }

    if (len <= 256 && mp_string256) {
        header_offset = align_up(sizeof(struct pool_obj_header), mp_string256->alignment);
        hdr = (struct pool_obj_header *)((char *)str - header_offset);
        if (hdr->pool == mp_string256) {
            mempool_free(mp_string256, str);
            return;
        }
    }

    /* Not from a pool (too large or header doesn't match), use regular free */
    free(str);
}

void
pool_strfree_v(void *str)
{
    pool_strfree((char *)str);
}
