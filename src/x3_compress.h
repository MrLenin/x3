/*
 * X3 - Zstandard Compression Module
 * Copyright (C) 2024 AfterNET Development Team
 *
 * Provides zstd-based compression for metadata values stored in LMDB.
 * Compression is transparent - values are compressed on write and
 * decompressed on read, with automatic detection via magic byte.
 */
#ifndef X3_COMPRESS_H
#define X3_COMPRESS_H

#include "config.h"

#ifdef WITH_ZSTD

/* Magic byte to identify compressed data */
#define X3_COMPRESS_MAGIC 0x1F

/* Default compression threshold (bytes) */
#define X3_COMPRESS_THRESHOLD_DEFAULT 256

/* Default compression level (1-22, 3 is fast with good ratio) */
#define X3_COMPRESS_LEVEL_DEFAULT 3

/* Maximum uncompressed size we'll accept (safety limit) */
#define X3_COMPRESS_MAX_UNCOMPRESSED 65536

/**
 * Initialize compression subsystem
 * @param threshold Minimum size to trigger compression (0 = use default)
 * @param level Compression level 1-22 (0 = use default)
 */
void x3_compress_init(size_t threshold, int level);

/**
 * Check if data appears to be compressed
 * @param data Data buffer
 * @param len Data length
 * @return 1 if compressed, 0 if not
 */
int x3_is_compressed(const unsigned char *data, size_t len);

/**
 * Compress data if it exceeds the threshold
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer (must be at least ZSTD_compressBound(input_len) + 1)
 * @param output_size Size of output buffer
 * @param output_len Output: actual compressed length
 * @return 1 if compressed, 0 if passed through unchanged, -1 on error
 */
int x3_compress(const unsigned char *input, size_t input_len,
                unsigned char *output, size_t output_size, size_t *output_len);

/**
 * Decompress data if it has compression magic byte
 * @param input Input data (possibly compressed)
 * @param input_len Input length
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @param output_len Output: actual decompressed length
 * @return 1 if decompressed, 0 if passed through unchanged, -1 on error
 */
int x3_decompress(const unsigned char *input, size_t input_len,
                  unsigned char *output, size_t output_size, size_t *output_len);

/**
 * Get current compression threshold
 */
size_t x3_compress_get_threshold(void);

/**
 * Set compression threshold
 */
void x3_compress_set_threshold(size_t threshold);

/**
 * Get current compression level
 */
int x3_compress_get_level(void);

/**
 * Set compression level (1-22)
 */
void x3_compress_set_level(int level);

#else /* !WITH_ZSTD */

/* Stubs when zstd not available */
#define x3_compress_init(t, l)      do {} while(0)
#define x3_is_compressed(d, l)      (0)
#define x3_compress(i, il, o, os, ol) (0)
#define x3_decompress(i, il, o, os, ol) (0)
#define x3_compress_get_threshold() (0)
#define x3_compress_set_threshold(t) do {} while(0)
#define x3_compress_get_level()     (0)
#define x3_compress_set_level(l)    do {} while(0)

#endif /* WITH_ZSTD */
#endif /* X3_COMPRESS_H */
