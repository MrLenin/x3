/*
 * X3 - Zstandard Compression Module Implementation
 * Copyright (C) 2024 AfterNET Development Team
 *
 * Provides zstd-based compression for metadata values stored in LMDB.
 */

#include "config.h"

#ifdef WITH_ZSTD

#include "x3_compress.h"
#include "log.h"
#include <zstd.h>
#include <string.h>

static size_t compression_threshold = X3_COMPRESS_THRESHOLD_DEFAULT;
static int compression_level = X3_COMPRESS_LEVEL_DEFAULT;

void x3_compress_init(size_t threshold, int level)
{
    if (threshold > 0)
        compression_threshold = threshold;
    if (level >= 1 && level <= ZSTD_maxCLevel())
        compression_level = level;
}

int x3_is_compressed(const unsigned char *data, size_t len)
{
    return (len > 1 && data[0] == X3_COMPRESS_MAGIC);
}

int x3_compress(const unsigned char *input, size_t input_len,
                unsigned char *output, size_t output_size, size_t *output_len)
{
    size_t compressed_size;

    /* Don't compress small values */
    if (input_len < compression_threshold) {
        if (input_len > output_size)
            return -1;
        memcpy(output, input, input_len);
        *output_len = input_len;
        return 0;
    }

    /* Need room for magic byte + compressed data */
    if (output_size < 2)
        return -1;

    /* Compress with zstd */
    compressed_size = ZSTD_compress(output + 1, output_size - 1,
                                     input, input_len, compression_level);

    if (ZSTD_isError(compressed_size)) {
        log_module(MAIN_LOG, LOG_WARNING, "x3_compress: zstd compression failed: %s",
                   ZSTD_getErrorName(compressed_size));
        /* Fall back to uncompressed */
        if (input_len > output_size)
            return -1;
        memcpy(output, input, input_len);
        *output_len = input_len;
        return 0;
    }

    /* Only use compression if it actually saves space */
    if (compressed_size + 1 >= input_len) {
        if (input_len > output_size)
            return -1;
        memcpy(output, input, input_len);
        *output_len = input_len;
        return 0;
    }

    /* Add magic byte */
    output[0] = X3_COMPRESS_MAGIC;
    *output_len = compressed_size + 1;
    return 1;
}

int x3_decompress(const unsigned char *input, size_t input_len,
                  unsigned char *output, size_t output_size, size_t *output_len)
{
    size_t decompressed_size;

    /* Check for magic byte */
    if (!x3_is_compressed(input, input_len)) {
        if (input_len > output_size) {
            log_module(MAIN_LOG, LOG_ERROR, "x3_decompress: output buffer too small");
            return -1;
        }
        memcpy(output, input, input_len);
        *output_len = input_len;
        return 0;
    }

    /* Decompress (skip magic byte) */
    decompressed_size = ZSTD_decompress(output, output_size,
                                         input + 1, input_len - 1);

    if (ZSTD_isError(decompressed_size)) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_decompress: zstd decompression failed: %s",
                   ZSTD_getErrorName(decompressed_size));
        return -1;
    }

    /* Safety check */
    if (decompressed_size > X3_COMPRESS_MAX_UNCOMPRESSED) {
        log_module(MAIN_LOG, LOG_ERROR, "x3_decompress: decompressed size too large: %zu",
                   decompressed_size);
        return -1;
    }

    *output_len = decompressed_size;
    return 1;
}

size_t x3_compress_get_threshold(void)
{
    return compression_threshold;
}

void x3_compress_set_threshold(size_t threshold)
{
    compression_threshold = threshold;
}

int x3_compress_get_level(void)
{
    return compression_level;
}

void x3_compress_set_level(int level)
{
    if (level >= 1 && level <= ZSTD_maxCLevel())
        compression_level = level;
}

#endif /* WITH_ZSTD */
