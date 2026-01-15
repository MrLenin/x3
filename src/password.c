/*
 * password.c - Modern password hashing module for X3
 *
 * Provides a modular password hashing system supporting multiple algorithms.
 * See password.h for API documentation.
 *
 * Copyright (C) 2026 AfterNET Development Team
 * Licensed under GNU GPL v2 or later
 */

#include "common.h"
#include "password.h"
#include "threadpool.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifdef WITH_SSL
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#endif

/* Forward declaration of legacy MD5 functions */
extern const char *cryptpass(const char *pass, char *buffer);
extern int checkpass(const char *pass, const char *crypted);

/* PBKDF2 parameters */
#define PBKDF2_SALT_LEN      16
#define PBKDF2_SHA256_LEN    32   /* SHA256 output: 256 bits */
#define PBKDF2_SHA512_LEN    64   /* SHA512 output: 512 bits */
#define PBKDF2_ITERATIONS    10000  /* Default: 10k iterations (~100ms sync, <10ms async) */

/* bcrypt parameters (reused from Nefarious ircd_crypt_bcrypt.c) */
#define BCRYPT_DEFAULT_COST 12
#define BCRYPT_SALT_LEN     16

/* bcrypt custom base64 alphabet */
static const char bcrypt_base64[] =
    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/* Standard base64 alphabet */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Global configuration with defaults */
struct pw_config pw_config = {
    .default_algorithm = PW_ALG_PBKDF2_SHA256,
    .pbkdf2_iterations = PBKDF2_ITERATIONS,
    .bcrypt_cost = 12,
    .enable_lazy_migration = 1,
    .allow_legacy_md5 = 1,
};

/* Base64 encode (no padding) */
static int base64_encode(const unsigned char *input, int input_len, char *output)
{
    int i, j;
    unsigned int triplet;

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

/* Base64 decode - writes only the actual decoded bytes (no buffer overflow) */
static int base64_decode(const char *input, unsigned char *output)
{
    int i, j, len;
    unsigned int triplet;
    unsigned char d[4];
    const char *p;

    if (!input)
        return -1;

    len = strlen(input);
    if (len == 0)
        return 0;

    for (i = 0, j = 0; i < len; ) {
        int remaining = len - i;
        int bytes_this_block;

        for (int k = 0; k < 4; k++) {
            if (i < len) {
                p = strchr(base64_chars, input[i]);
                if (p == NULL)
                    return -1;
                d[k] = p - base64_chars;
                i++;
            } else {
                d[k] = 0;
            }
        }

        triplet = (d[0] << 18) | (d[1] << 12) | (d[2] << 6) | d[3];

        /* Only write the bytes we'll actually keep - avoids buffer overflow */
        if (remaining >= 4) {
            bytes_this_block = 3;
        } else if (remaining == 3) {
            bytes_this_block = 2;
        } else if (remaining == 2) {
            bytes_this_block = 1;
        } else {
            bytes_this_block = 0;
        }

        if (bytes_this_block >= 1) output[j++] = (triplet >> 16) & 0xff;
        if (bytes_this_block >= 2) output[j++] = (triplet >> 8) & 0xff;
        if (bytes_this_block >= 3) output[j++] = triplet & 0xff;
    }

    return j;
}

#ifdef WITH_SSL
/* Perform PBKDF2 key derivation with specified digest */
static int do_pbkdf2(const char *password, const unsigned char *salt,
                     size_t salt_len, int iterations,
                     unsigned char *output, size_t output_len,
                     const char *digest_name)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[5];
    int ret = 0;

    kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (kdf == NULL) {
        log_module(MAIN_LOG, LOG_ERROR, "pw: EVP_KDF_fetch failed");
        goto cleanup;
    }

    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL) {
        log_module(MAIN_LOG, LOG_ERROR, "pw: EVP_KDF_CTX_new failed");
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)digest_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                   (void *)password, strlen(password));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                   (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, &iterations);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, output, output_len, params) != 1) {
        log_module(MAIN_LOG, LOG_ERROR, "pw: EVP_KDF_derive failed");
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (ctx) EVP_KDF_CTX_free(ctx);
    if (kdf) EVP_KDF_free(kdf);
    return ret;
}

/* Convenience wrapper for PBKDF2-SHA256 */
static int do_pbkdf2_sha256(const char *password, const unsigned char *salt,
                            size_t salt_len, int iterations,
                            unsigned char *output, size_t output_len)
{
    return do_pbkdf2(password, salt, salt_len, iterations, output, output_len, "SHA256");
}

/* Convenience wrapper for PBKDF2-SHA512 */
static int do_pbkdf2_sha512(const char *password, const unsigned char *salt,
                            size_t salt_len, int iterations,
                            unsigned char *output, size_t output_len)
{
    return do_pbkdf2(password, salt, salt_len, iterations, output, output_len, "SHA512");
}

/* Hash password with PBKDF2-SHA256 */
static int hash_pbkdf2_sha256(const char *password, char *output, size_t output_len)
{
    unsigned char salt[PBKDF2_SALT_LEN];
    unsigned char hash[PBKDF2_SHA256_LEN];
    char salt_b64[32];
    char hash_b64[64];

    if (RAND_bytes(salt, PBKDF2_SALT_LEN) != 1) {
        log_module(MAIN_LOG, LOG_ERROR, "pw: RAND_bytes failed");
        return -1;
    }

    if (!do_pbkdf2_sha256(password, salt, PBKDF2_SALT_LEN,
                          pw_config.pbkdf2_iterations, hash, PBKDF2_SHA256_LEN)) {
        return -1;
    }

    base64_encode(salt, PBKDF2_SALT_LEN, salt_b64);
    base64_encode(hash, PBKDF2_SHA256_LEN, hash_b64);

    snprintf(output, output_len, "$pbkdf2-sha256$i=%d$%s$%s",
             pw_config.pbkdf2_iterations, salt_b64, hash_b64);

    return 0;
}

/* Hash password with PBKDF2-SHA512 */
static int hash_pbkdf2_sha512(const char *password, char *output, size_t output_len)
{
    unsigned char salt[PBKDF2_SALT_LEN];
    unsigned char hash[PBKDF2_SHA512_LEN];
    char salt_b64[32];
    char hash_b64[128];

    if (RAND_bytes(salt, PBKDF2_SALT_LEN) != 1) {
        log_module(MAIN_LOG, LOG_ERROR, "pw: RAND_bytes failed");
        return -1;
    }

    if (!do_pbkdf2_sha512(password, salt, PBKDF2_SALT_LEN,
                          pw_config.pbkdf2_iterations, hash, PBKDF2_SHA512_LEN)) {
        return -1;
    }

    base64_encode(salt, PBKDF2_SALT_LEN, salt_b64);
    base64_encode(hash, PBKDF2_SHA512_LEN, hash_b64);

    snprintf(output, output_len, "$pbkdf2-sha512$i=%d$%s$%s",
             pw_config.pbkdf2_iterations, salt_b64, hash_b64);

    return 0;
}

/* Verify password against PBKDF2-SHA256 hash */
static int verify_pbkdf2_sha256(const char *password, const char *hash)
{
    const char *p;
    char iter_str[16], salt_b64[64], hash_b64[128];
    unsigned char salt[PBKDF2_SALT_LEN];
    unsigned char stored_hash[PBKDF2_SHA256_LEN];
    unsigned char computed_hash[PBKDF2_SHA256_LEN];
    int iterations, salt_len, hash_len;
    int i;

    /* Format: $pbkdf2-sha256$i=NNNN$salt$hash */
    if (strncmp(hash, "$pbkdf2-sha256$", 15) != 0)
        return 0;

    p = hash + 15;

    /* Parse i=iterations */
    if (strncmp(p, "i=", 2) != 0)
        return 0;
    p += 2;

    for (i = 0; *p && *p != '$' && i < 15; i++, p++)
        iter_str[i] = *p;
    iter_str[i] = '\0';

    if (*p != '$') return 0;
    p++;

    iterations = atoi(iter_str);
    if (iterations <= 0) return 0;

    /* Parse salt */
    for (i = 0; *p && *p != '$' && i < 63; i++, p++)
        salt_b64[i] = *p;
    salt_b64[i] = '\0';

    if (*p != '$') return 0;
    p++;

    /* Parse hash */
    for (i = 0; *p && i < 127; i++, p++)
        hash_b64[i] = *p;
    hash_b64[i] = '\0';

    /* Decode */
    salt_len = base64_decode(salt_b64, salt);
    if (salt_len < 0)
        return 0;

    hash_len = base64_decode(hash_b64, stored_hash);
    if (hash_len < 0 || hash_len != PBKDF2_SHA256_LEN)
        return 0;

    /* Compute and compare */
    if (!do_pbkdf2_sha256(password, salt, salt_len, iterations,
                          computed_hash, PBKDF2_SHA256_LEN)) {
        return 0;
    }

    /* Constant-time comparison */
    return CRYPTO_memcmp(computed_hash, stored_hash, PBKDF2_SHA256_LEN) == 0 ? 1 : 0;
}

/* Verify password against PBKDF2-SHA512 hash */
static int verify_pbkdf2_sha512(const char *password, const char *hash)
{
    const char *p;
    char iter_str[16], salt_b64[64], hash_b64[128];
    unsigned char salt[PBKDF2_SALT_LEN];
    unsigned char stored_hash[PBKDF2_SHA512_LEN];
    unsigned char computed_hash[PBKDF2_SHA512_LEN];
    int iterations, salt_len, hash_len;
    int i;

    /* Format: $pbkdf2-sha512$i=NNNN$salt$hash */
    if (strncmp(hash, "$pbkdf2-sha512$", 15) != 0)
        return 0;

    p = hash + 15;

    /* Parse i=iterations */
    if (strncmp(p, "i=", 2) != 0)
        return 0;
    p += 2;

    for (i = 0; *p && *p != '$' && i < 15; i++, p++)
        iter_str[i] = *p;
    iter_str[i] = '\0';

    if (*p != '$') return 0;
    p++;

    iterations = atoi(iter_str);
    if (iterations <= 0) return 0;

    /* Parse salt */
    for (i = 0; *p && *p != '$' && i < 63; i++, p++)
        salt_b64[i] = *p;
    salt_b64[i] = '\0';

    if (*p != '$') return 0;
    p++;

    /* Parse hash */
    for (i = 0; *p && i < 127; i++, p++)
        hash_b64[i] = *p;
    hash_b64[i] = '\0';

    /* Decode */
    salt_len = base64_decode(salt_b64, salt);
    if (salt_len < 0) return 0;

    hash_len = base64_decode(hash_b64, stored_hash);
    if (hash_len < 0 || hash_len != PBKDF2_SHA512_LEN) return 0;

    /* Compute and compare */
    if (!do_pbkdf2_sha512(password, salt, salt_len, iterations,
                          computed_hash, PBKDF2_SHA512_LEN)) {
        return 0;
    }

    /* Constant-time comparison */
    return CRYPTO_memcmp(computed_hash, stored_hash, PBKDF2_SHA512_LEN) == 0 ? 1 : 0;
}
#endif /* WITH_SSL */

/* ============= bcrypt implementation (from Nefarious ircd_crypt_bcrypt.c) ============= */

/* Generate random bytes from /dev/urandom (fallback if RAND_bytes unavailable) */
static int get_random_bytes(unsigned char *buf, size_t len)
{
    int fd;
    ssize_t n;

#ifdef WITH_SSL
    /* Prefer OpenSSL's RAND_bytes when available */
    if (RAND_bytes(buf, len) == 1)
        return 0;
#endif

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;

    n = read(fd, buf, len);
    close(fd);

    return (n == (ssize_t)len) ? 0 : -1;
}

/* Generate a bcrypt salt string */
static char *generate_bcrypt_salt(char *salt, int cost)
{
    unsigned char raw[BCRYPT_SALT_LEN];
    int i;
    unsigned long v;

    if (cost < 4) cost = 4;
    if (cost > 31) cost = 31;

    if (get_random_bytes(raw, BCRYPT_SALT_LEN) < 0)
        return NULL;

    /* Format: $2y$XX$ followed by 22 base64 characters */
    sprintf(salt, "$2y$%02d$", cost);

    /* Encode 16 bytes (128 bits) into 22 base64 characters */
    for (i = 0; i < 5; i++) {
        v = (raw[i*3] << 16) | (raw[i*3+1] << 8) | raw[i*3+2];
        salt[7 + i*4]     = bcrypt_base64[(v >> 18) & 0x3f];
        salt[7 + i*4 + 1] = bcrypt_base64[(v >> 12) & 0x3f];
        salt[7 + i*4 + 2] = bcrypt_base64[(v >> 6) & 0x3f];
        salt[7 + i*4 + 3] = bcrypt_base64[v & 0x3f];
    }
    /* Last byte */
    v = raw[15];
    salt[27] = bcrypt_base64[(v >> 2) & 0x3f];
    salt[28] = bcrypt_base64[(v << 4) & 0x3f];
    salt[29] = '\0';

    return salt;
}

/* Hash password with bcrypt */
static int hash_bcrypt(const char *password, char *output, size_t output_len)
{
    char salt[30];
    const char *result;

    if (generate_bcrypt_salt(salt, pw_config.bcrypt_cost) == NULL) {
        log_module(MAIN_LOG, LOG_ERROR, "pw: bcrypt salt generation failed");
        return -1;
    }

    result = crypt(password, salt);
    if (result == NULL) {
        log_module(MAIN_LOG, LOG_ERROR, "pw: crypt() returned NULL");
        return -1;
    }

    /* Verify it's actually a bcrypt result */
    if (result[0] != '$' || result[1] != '2') {
        log_module(MAIN_LOG, LOG_ERROR, "pw: crypt() did not return bcrypt hash (system may not support bcrypt)");
        return -1;
    }

    if (strlen(result) >= output_len) {
        log_module(MAIN_LOG, LOG_ERROR, "pw: bcrypt output buffer too small");
        return -1;
    }

    strcpy(output, result);
    return 0;
}

/* Verify password against bcrypt hash */
static int verify_bcrypt(const char *password, const char *hash)
{
    const char *result;
    size_t hash_len;

    /* Hash must be a valid bcrypt format */
    if (strlen(hash) < 28 || hash[0] != '$' || hash[1] != '2' ||
        (hash[2] != 'a' && hash[2] != 'b' && hash[2] != 'y') || hash[3] != '$') {
        return 0;
    }

    result = crypt(password, hash);
    if (result == NULL)
        return 0;

    hash_len = strlen(hash);

    /* Constant-time comparison */
#ifdef WITH_SSL
    return CRYPTO_memcmp(result, hash, hash_len) == 0 ? 1 : 0;
#else
    /* Fallback to regular strcmp if no OpenSSL (timing attack possible) */
    return strcmp(result, hash) == 0 ? 1 : 0;
#endif
}

/* ============= End bcrypt implementation ============= */

void pw_init(void)
{
    log_module(MAIN_LOG, LOG_INFO, "Password module initialized (default: %s, iterations: %d)",
               pw_algorithm_name(pw_config.default_algorithm),
               pw_config.pbkdf2_iterations);
}

enum pw_algorithm pw_detect_algorithm(const char *hash)
{
    if (!hash || !*hash)
        return PW_ALG_UNKNOWN;

    /* PBKDF2-SHA256: $pbkdf2-sha256$... */
    if (strncmp(hash, "$pbkdf2-sha256$", 15) == 0)
        return PW_ALG_PBKDF2_SHA256;

    /* PBKDF2-SHA512: $pbkdf2-sha512$... */
    if (strncmp(hash, "$pbkdf2-sha512$", 15) == 0)
        return PW_ALG_PBKDF2_SHA512;

    /* bcrypt: $2a$, $2b$, $2y$ */
    if (strlen(hash) >= 4 && hash[0] == '$' && hash[1] == '2' &&
        (hash[2] == 'a' || hash[2] == 'b' || hash[2] == 'y') && hash[3] == '$')
        return PW_ALG_BCRYPT;

    /* Argon2id: $argon2id$... */
    if (strncmp(hash, "$argon2id$", 10) == 0)
        return PW_ALG_ARGON2ID;

    /* Legacy X3 seeded MD5: $XXXXXXXX followed by 32 hex chars */
    if (hash[0] == '$' && strlen(hash) == 41) {
        int i, valid = 1;
        for (i = 1; i < 9 && valid; i++)
            valid = (hash[i] >= '0' && hash[i] <= '9') ||
                    (hash[i] >= 'A' && hash[i] <= 'F') ||
                    (hash[i] >= 'a' && hash[i] <= 'f');
        if (valid)
            return PW_ALG_MD5_LEGACY;
    }

    /* Plain MD5: 32 hex characters */
    if (strlen(hash) == 32) {
        int i, valid = 1;
        for (i = 0; i < 32 && valid; i++)
            valid = (hash[i] >= '0' && hash[i] <= '9') ||
                    (hash[i] >= 'a' && hash[i] <= 'f') ||
                    (hash[i] >= 'A' && hash[i] <= 'F');
        if (valid)
            return PW_ALG_MD5_PLAIN;
    }

    return PW_ALG_UNKNOWN;
}

const char *pw_algorithm_name(enum pw_algorithm algorithm)
{
    switch (algorithm) {
        case PW_ALG_MD5_LEGACY:    return "md5-legacy";
        case PW_ALG_MD5_PLAIN:     return "md5";
        case PW_ALG_PBKDF2_SHA256: return "pbkdf2-sha256";
        case PW_ALG_PBKDF2_SHA512: return "pbkdf2-sha512";
        case PW_ALG_BCRYPT:        return "bcrypt";
        case PW_ALG_ARGON2ID:      return "argon2id";
        default:                   return "unknown";
    }
}

int pw_hash(const char *password, char *output, size_t output_len)
{
    return pw_hash_with(password, pw_config.default_algorithm, output, output_len);
}

int pw_hash_with(const char *password, enum pw_algorithm algorithm,
                 char *output, size_t output_len)
{
    if (!password || !output || output_len < 64)
        return -1;

    switch (algorithm) {
#ifdef WITH_SSL
        case PW_ALG_PBKDF2_SHA256:
            return hash_pbkdf2_sha256(password, output, output_len);
        case PW_ALG_PBKDF2_SHA512:
            return hash_pbkdf2_sha512(password, output, output_len);
#endif
        case PW_ALG_BCRYPT:
            return hash_bcrypt(password, output, output_len);

        case PW_ALG_MD5_PLAIN:
            /* Fall back to legacy for now */
            if (cryptpass(password, output))
                return 0;
            return -1;

        default:
            log_module(MAIN_LOG, LOG_ERROR, "pw_hash: unsupported algorithm %d", algorithm);
            return -1;
    }
}

int pw_verify(const char *password, const char *hash)
{
    enum pw_algorithm alg;

    if (!password || !hash)
        return -1;

    alg = pw_detect_algorithm(hash);

    switch (alg) {
#ifdef WITH_SSL
        case PW_ALG_PBKDF2_SHA256:
            return verify_pbkdf2_sha256(password, hash);
        case PW_ALG_PBKDF2_SHA512:
            return verify_pbkdf2_sha512(password, hash);
#endif
        case PW_ALG_BCRYPT:
            return verify_bcrypt(password, hash);

        case PW_ALG_MD5_LEGACY:
        case PW_ALG_MD5_PLAIN:
            if (!pw_config.allow_legacy_md5) {
                log_module(MAIN_LOG, LOG_WARNING, "pw_verify: legacy MD5 disabled");
                return 0;
            }
            return checkpass(password, hash);

        case PW_ALG_UNKNOWN:
            /* Try legacy checkpass as fallback */
            return checkpass(password, hash);

        default:
            log_module(MAIN_LOG, LOG_ERROR, "pw_verify: unsupported algorithm %s",
                       pw_algorithm_name(alg));
            return 0;
    }
}

int pw_needs_rehash(const char *hash)
{
    enum pw_algorithm alg;

    if (!hash)
        return 1;

    alg = pw_detect_algorithm(hash);

    /* Legacy MD5 always needs rehash */
    if (alg == PW_ALG_MD5_LEGACY || alg == PW_ALG_MD5_PLAIN)
        return 1;

    /* Unknown algorithm needs rehash */
    if (alg == PW_ALG_UNKNOWN)
        return 1;

    /* If not using default algorithm, needs rehash */
    if (alg != pw_config.default_algorithm)
        return 1;

    /* TODO: Check iteration count for PBKDF2 */

    return 0;
}

/* Add Base64 padding to make length a multiple of 4 */
static void base64_add_padding(char *b64_str)
{
    size_t len = strlen(b64_str);
    int padding = (4 - (len % 4)) % 4;
    while (padding-- > 0) {
        b64_str[len++] = '=';
    }
    b64_str[len] = '\0';
}

int pw_export_keycloak(const char *hash, char *cred_data, size_t cred_data_len,
                       char *secret_data, size_t secret_data_len)
{
    enum pw_algorithm alg = pw_detect_algorithm(hash);
    const char *p;
    const char *alg_name;
    char iter_str[16], salt_b64[68], hash_b64[132];  /* Extra space for padding */
    int i, iterations;

    /* Only PBKDF2 variants can be exported to Keycloak */
    if (alg == PW_ALG_PBKDF2_SHA256) {
        p = hash + 15;  /* Skip $pbkdf2-sha256$ */
        alg_name = "pbkdf2-sha256";
    } else if (alg == PW_ALG_PBKDF2_SHA512) {
        p = hash + 15;  /* Skip $pbkdf2-sha512$ */
        alg_name = "pbkdf2-sha512";
    } else {
        return -1;
    }

    /* Parse the hash - Format: $pbkdf2-shaXXX$i=NNNN$salt$hash */
    if (strncmp(p, "i=", 2) != 0)
        return -1;
    p += 2;

    for (i = 0; *p && *p != '$' && i < 15; i++, p++)
        iter_str[i] = *p;
    iter_str[i] = '\0';
    if (*p != '$') return -1;
    p++;

    iterations = atoi(iter_str);

    for (i = 0; *p && *p != '$' && i < 63; i++, p++)
        salt_b64[i] = *p;
    salt_b64[i] = '\0';
    if (*p != '$') return -1;
    p++;

    for (i = 0; *p && i < 127; i++, p++)
        hash_b64[i] = *p;
    hash_b64[i] = '\0';

    /* Keycloak requires proper Base64 padding */
    base64_add_padding(salt_b64);
    base64_add_padding(hash_b64);

    /* Keycloak credentialData format */
    snprintf(cred_data, cred_data_len,
             "{\"algorithm\":\"%s\",\"hashIterations\":%d}",
             alg_name, iterations);

    /* Keycloak secretData format */
    snprintf(secret_data, secret_data_len,
             "{\"value\":\"%s\",\"salt\":\"%s\"}",
             hash_b64, salt_b64);

    return 0;
}

int pw_export_ldap(const char *hash, char *ldap_hash, size_t ldap_hash_len)
{
    enum pw_algorithm alg = pw_detect_algorithm(hash);

    switch (alg) {
        case PW_ALG_PBKDF2_SHA256:
            snprintf(ldap_hash, ldap_hash_len, "{PBKDF2-SHA256}%s", hash);
            return 0;

        case PW_ALG_PBKDF2_SHA512:
            snprintf(ldap_hash, ldap_hash_len, "{PBKDF2-SHA512}%s", hash);
            return 0;

        case PW_ALG_BCRYPT:
            snprintf(ldap_hash, ldap_hash_len, "{BCRYPT}%s", hash);
            return 0;

        default:
            return -1;
    }
}

/* Compatibility wrappers */
const char *pw_cryptpass(const char *pass, char *buffer)
{
    if (pw_hash(pass, buffer, PW_MAX_HASH_LEN) == 0)
        return buffer;
    return NULL;
}

/* ============= Async password operations (threadpool) ============= */

#ifdef HAVE_PTHREAD_H

/* Internal work types */
enum pw_work_type {
    PW_WORK_HASH,
    PW_WORK_HASH_WITH,
    PW_WORK_VERIFY
};

/* Internal work structure */
struct pw_work {
    enum pw_work_type type;
    struct pw_async_ctx *ctx;
};

/* Worker function - runs in threadpool thread */
static void *pw_worker(void *arg)
{
    struct pw_work *work = arg;
    struct pw_async_ctx *ctx = work->ctx;

    switch (work->type) {
    case PW_WORK_HASH:
        ctx->result = pw_hash(ctx->password, ctx->output_hash, sizeof(ctx->output_hash));
        break;

    case PW_WORK_HASH_WITH:
        ctx->result = pw_hash_with(ctx->password, ctx->algorithm,
                                    ctx->output_hash, sizeof(ctx->output_hash));
        break;

    case PW_WORK_VERIFY:
        ctx->result = pw_verify(ctx->password, ctx->stored_hash);
        break;
    }

    /* Clear password from memory immediately */
    memset(ctx->password, 0, sizeof(ctx->password));

    return work;
}

/* Callback wrapper - runs in main thread */
static void pw_callback_wrapper(void *result, void *user_data, tp_state_t state)
{
    struct pw_work *work = result;
    struct pw_async_ctx *ctx = work->ctx;
    const char *hash_out = NULL;

    (void)user_data;  /* Unused */

    if (state == TP_STATE_COMPLETED) {
        /* For hash operations, provide the output hash */
        if (work->type == PW_WORK_HASH || work->type == PW_WORK_HASH_WITH) {
            if (ctx->result == 0)
                hash_out = ctx->output_hash;
        }

        /* Invoke user callback */
        if (ctx->callback) {
            ctx->callback(ctx->user_ctx, ctx->result, hash_out);
        }
    } else {
        /* Task was cancelled or failed */
        if (ctx->callback) {
            ctx->callback(ctx->user_ctx, -1, NULL);
        }
    }

    /* Cleanup - clear any sensitive data */
    memset(ctx->password, 0, sizeof(ctx->password));
    memset(ctx->stored_hash, 0, sizeof(ctx->stored_hash));
    free(ctx);
    free(work);
}

int pw_hash_async(const char *password, pw_async_callback callback, void *ctx)
{
    return pw_hash_with_async(password, pw_config.default_algorithm, callback, ctx);
}

int pw_hash_with_async(const char *password, enum pw_algorithm algorithm,
                       pw_async_callback callback, void *ctx)
{
    struct pw_work *work;
    struct pw_async_ctx *async_ctx;

    if (!password || !callback)
        return -1;

    if (!threadpool_is_initialized()) {
        /* Fallback to sync - call callback directly */
        char hash[PW_MAX_HASH_LEN];
        int result = pw_hash_with(password, algorithm, hash, sizeof(hash));
        callback(ctx, result, result == 0 ? hash : NULL);
        return 0;
    }

    /* Allocate work structures */
    work = malloc(sizeof(*work));
    async_ctx = malloc(sizeof(*async_ctx));
    if (!work || !async_ctx) {
        free(work);
        free(async_ctx);
        return -1;
    }

    /* Initialize context */
    memset(async_ctx, 0, sizeof(*async_ctx));
    strncpy(async_ctx->password, password, sizeof(async_ctx->password) - 1);
    async_ctx->algorithm = algorithm;
    async_ctx->callback = callback;
    async_ctx->user_ctx = ctx;

    /* Initialize work */
    work->type = PW_WORK_HASH_WITH;
    work->ctx = async_ctx;

    /* Submit to threadpool */
    if (!threadpool_submit(pw_worker, work, pw_callback_wrapper, NULL, TP_PRIORITY_HIGH)) {
        memset(async_ctx->password, 0, sizeof(async_ctx->password));
        free(async_ctx);
        free(work);
        return -1;
    }

    return 0;
}

int pw_verify_async(const char *password, const char *hash,
                    pw_async_callback callback, void *ctx)
{
    struct pw_work *work;
    struct pw_async_ctx *async_ctx;

    if (!password || !hash || !callback)
        return -1;

    if (!threadpool_is_initialized()) {
        /* Fallback to sync - call callback directly */
        int result = pw_verify(password, hash);
        callback(ctx, result, NULL);
        return 0;
    }

    /* Allocate work structures */
    work = malloc(sizeof(*work));
    async_ctx = malloc(sizeof(*async_ctx));
    if (!work || !async_ctx) {
        free(work);
        free(async_ctx);
        return -1;
    }

    /* Initialize context */
    memset(async_ctx, 0, sizeof(*async_ctx));
    strncpy(async_ctx->password, password, sizeof(async_ctx->password) - 1);
    strncpy(async_ctx->stored_hash, hash, sizeof(async_ctx->stored_hash) - 1);
    async_ctx->callback = callback;
    async_ctx->user_ctx = ctx;

    /* Initialize work */
    work->type = PW_WORK_VERIFY;
    work->ctx = async_ctx;

    /* Submit to threadpool - password verification is high priority */
    if (!threadpool_submit(pw_worker, work, pw_callback_wrapper, NULL, TP_PRIORITY_HIGH)) {
        memset(async_ctx->password, 0, sizeof(async_ctx->password));
        free(async_ctx);
        free(work);
        return -1;
    }

    return 0;
}

#else /* !HAVE_PTHREAD_H */

/* Stub implementations without pthreads - just call sync versions */

int pw_hash_async(const char *password, pw_async_callback callback, void *ctx)
{
    char hash[PW_MAX_HASH_LEN];
    int result;

    if (!password || !callback)
        return -1;

    result = pw_hash(password, hash, sizeof(hash));
    callback(ctx, result, result == 0 ? hash : NULL);
    return 0;
}

int pw_hash_with_async(const char *password, enum pw_algorithm algorithm,
                       pw_async_callback callback, void *ctx)
{
    char hash[PW_MAX_HASH_LEN];
    int result;

    if (!password || !callback)
        return -1;

    result = pw_hash_with(password, algorithm, hash, sizeof(hash));
    callback(ctx, result, result == 0 ? hash : NULL);
    return 0;
}

int pw_verify_async(const char *password, const char *hash,
                    pw_async_callback callback, void *ctx)
{
    int result;

    if (!password || !hash || !callback)
        return -1;

    result = pw_verify(password, hash);
    callback(ctx, result, NULL);
    return 0;
}

#endif /* HAVE_PTHREAD_H */

