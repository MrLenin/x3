/* mempool.h - Memory pool allocator for frequently allocated objects
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

#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <stddef.h>

/* Memory pool handle */
typedef struct mempool mempool_t;

/* Pool statistics */
struct mempool_stats {
    const char *name;            /* Pool name */
    size_t object_size;          /* Size of each object */
    size_t alignment;            /* Alignment requirement */
    unsigned long total_objects; /* Total objects in pool */
    unsigned long free_objects;  /* Currently available */
    unsigned long alloc_count;   /* Total allocations */
    unsigned long free_count;    /* Total frees */
    unsigned long grow_count;    /* Times pool expanded */
    unsigned long peak_usage;    /* Maximum concurrent allocations */
    size_t memory_used;          /* Total bytes allocated from system */
};

/**
 * Create a memory pool
 * @param name Pool name (for debugging)
 * @param object_size Size of each object
 * @param alignment Required alignment (0 = sizeof(void*))
 * @param initial_count Initial objects to preallocate
 * @param max_count Maximum objects (0 = unlimited)
 * @param grow_count Objects to add when pool exhausted
 * @return Pool handle, or NULL on failure
 */
mempool_t *mempool_create(const char *name, size_t object_size,
                          size_t alignment, unsigned int initial_count,
                          unsigned int max_count, unsigned int grow_count);

/**
 * Destroy a memory pool
 * @param pool Pool to destroy
 * @param check_leaks If true, warn about unreturned objects
 */
void mempool_destroy(mempool_t *pool, int check_leaks);

/**
 * Allocate an object from the pool
 * @return Object pointer, or NULL if pool exhausted
 */
void *mempool_alloc(mempool_t *pool);

/**
 * Return an object to the pool
 */
void mempool_free(mempool_t *pool, void *obj);

/**
 * Zero-fill and allocate (like calloc)
 */
void *mempool_zalloc(mempool_t *pool);

/**
 * Get pool statistics
 */
void mempool_get_stats(mempool_t *pool, struct mempool_stats *stats);

/**
 * Shrink pool by releasing unused memory
 * @param keep_free Minimum free objects to keep
 * @return Bytes released
 */
size_t mempool_shrink(mempool_t *pool, unsigned int keep_free);

/**
 * Debug: Dump all pools to log
 */
void mempool_dump_all(void);

/**
 * Get number of registered pools
 */
unsigned int mempool_count(void);

/* Global pools (initialized at startup) */
extern mempool_t *mp_msgbuf;     /* IRC message buffers (512 bytes) */
extern mempool_t *mp_string64;   /* 64-byte strings */
extern mempool_t *mp_string256;  /* 256-byte strings */
extern mempool_t *mp_curl_ctx;   /* CURL request contexts */
extern mempool_t *mp_timeq;      /* Timer queue entries (~16 bytes) */

/**
 * Initialize global memory pools
 * Call once at startup before any allocations
 * @return 0 on success, -1 on failure
 */
int mempool_init_global(void);

/**
 * Cleanup global memory pools
 */
void mempool_cleanup_global(void);

/* Convenience macros for common operations */
#define POOL_ALLOC(pool) mempool_alloc(pool)
#define POOL_ZALLOC(pool) mempool_zalloc(pool)
#define POOL_FREE(pool, obj) mempool_free(pool, obj)

/**
 * Automatically select appropriate string pool
 * Falls back to strdup() for strings larger than 256 bytes
 */
char *pool_strdup(const char *str);

/**
 * Free a string that may have been allocated from a pool
 * Detects pool-allocated strings and returns them to the correct pool
 */
void pool_strfree(char *str);

#endif /* MEMPOOL_H */
