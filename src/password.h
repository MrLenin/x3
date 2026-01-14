/*
 * password.h - Modern password hashing module for X3
 *
 * Provides a modular password hashing system supporting multiple algorithms:
 * - Legacy MD5 (for backward compatibility)
 * - PBKDF2-SHA256 (primary, OWASP recommended)
 * - PBKDF2-SHA512 (alternative)
 * - bcrypt (if available)
 *
 * Features:
 * - Algorithm detection from hash format
 * - Lazy migration on login (rehash old passwords)
 * - Keycloak credential export support
 * - OpenLDAP password format export
 *
 * Copyright (C) 2026 AfterNET Development Team
 * Licensed under GNU GPL v2 or later
 */

#ifndef PASSWORD_H
#define PASSWORD_H

#include <stddef.h>

/* Maximum length for password hash strings */
#define PW_MAX_HASH_LEN 256

/* Algorithm identifiers */
enum pw_algorithm {
    PW_ALG_UNKNOWN = 0,
    PW_ALG_MD5_LEGACY,      /* Legacy X3 seeded MD5: $XXXXXXXX... */
    PW_ALG_MD5_PLAIN,       /* Plain MD5 hex (32 chars) */
    PW_ALG_PBKDF2_SHA256,   /* PBKDF2-SHA256: $pbkdf2-sha256$... */
    PW_ALG_PBKDF2_SHA512,   /* PBKDF2-SHA512: $pbkdf2-sha512$... */
    PW_ALG_BCRYPT,          /* bcrypt: $2a$/$2b$/$2y$... */
    PW_ALG_ARGON2ID,        /* Argon2id: $argon2id$... (future) */
};

/* Password module configuration */
struct pw_config {
    enum pw_algorithm default_algorithm;  /* Algorithm for new passwords */
    int pbkdf2_iterations;                /* PBKDF2 iteration count (default: 100000) */
    int bcrypt_cost;                      /* bcrypt cost factor (default: 12) */
    int enable_lazy_migration;            /* Rehash old passwords on login */
    int allow_legacy_md5;                 /* Allow MD5 for verification (not new hashes) */
};

/* Global configuration (set at startup) */
extern struct pw_config pw_config;

/*
 * Initialize the password module with configuration.
 * Should be called during service startup.
 */
void pw_init(void);

/*
 * Hash a password using the configured default algorithm.
 *
 * @param password  The plaintext password to hash
 * @param output    Buffer to receive the hash (must be PW_MAX_HASH_LEN bytes)
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int pw_hash(const char *password, char *output, size_t output_len);

/*
 * Hash a password using a specific algorithm.
 *
 * @param password  The plaintext password to hash
 * @param algorithm The algorithm to use
 * @param output    Buffer to receive the hash
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int pw_hash_with(const char *password, enum pw_algorithm algorithm,
                 char *output, size_t output_len);

/*
 * Verify a password against a stored hash.
 * Automatically detects the algorithm from the hash format.
 *
 * @param password  The plaintext password to verify
 * @param hash      The stored hash to verify against
 * @return 1 if password matches, 0 if not, -1 on error
 */
int pw_verify(const char *password, const char *hash);

/*
 * Check if a hash needs to be upgraded to the current algorithm.
 * Returns true if:
 * - Hash uses a weaker algorithm than configured default
 * - Hash uses fewer iterations than configured
 * - Hash format is deprecated
 *
 * @param hash  The stored hash to check
 * @return 1 if rehash needed, 0 if hash is current
 */
int pw_needs_rehash(const char *hash);

/*
 * Detect the algorithm used to create a hash.
 *
 * @param hash  The hash string to analyze
 * @return The algorithm identifier, or PW_ALG_UNKNOWN
 */
enum pw_algorithm pw_detect_algorithm(const char *hash);

/*
 * Get human-readable name for an algorithm.
 *
 * @param algorithm  The algorithm identifier
 * @return Static string with algorithm name
 */
const char *pw_algorithm_name(enum pw_algorithm algorithm);

/*
 * Export hash in Keycloak credential import format.
 * Only works for PBKDF2 hashes (Keycloak's supported format).
 *
 * @param hash        The hash to export
 * @param cred_data   Buffer for credentialData JSON (min 256 bytes)
 * @param secret_data Buffer for secretData JSON (min 512 bytes)
 * @return 0 on success, -1 if format not exportable
 */
int pw_export_keycloak(const char *hash, char *cred_data, size_t cred_data_len,
                       char *secret_data, size_t secret_data_len);

/*
 * Export hash in OpenLDAP password format.
 * Adds appropriate {SCHEME} prefix.
 *
 * @param hash        The hash to export
 * @param ldap_hash   Buffer for LDAP format (min PW_MAX_HASH_LEN bytes)
 * @param ldap_hash_len Size of output buffer
 * @return 0 on success, -1 if format not exportable
 */
int pw_export_ldap(const char *hash, char *ldap_hash, size_t ldap_hash_len);

/*
 * Compatibility wrappers - these wrap the legacy cryptpass/checkpass
 * functions to use the new password module internally.
 * Use these during the migration period.
 */

/*
 * Hash password (compatibility wrapper for cryptpass).
 * Uses pw_hash() internally but returns pointer like cryptpass.
 *
 * @param pass    The plaintext password
 * @param buffer  Buffer for the hash (min PW_MAX_HASH_LEN bytes)
 * @return Pointer to buffer, or NULL on error
 */
const char *pw_cryptpass(const char *pass, char *buffer);

/*
 * ============= Async password operations (threadpool) =============
 *
 * These functions offload CPU-intensive password hashing to the threadpool
 * to avoid blocking the main event loop. The callback runs in the main
 * thread after the operation completes.
 */

/* Callback type for async password operations */
typedef void (*pw_async_callback)(void *ctx, int result, const char *hash);

/* Async work context - allocated by caller, freed by library after callback */
struct pw_async_ctx {
    char password[256];              /* Copy of password (cleared after use) */
    char stored_hash[PW_MAX_HASH_LEN]; /* For verify: stored hash to check against */
    char output_hash[PW_MAX_HASH_LEN]; /* For hash: result goes here */
    enum pw_algorithm algorithm;      /* For hash_with: algorithm to use */
    int result;                       /* 0=success, -1=error, 1=verified */
    pw_async_callback callback;       /* User callback */
    void *user_ctx;                   /* User context passed to callback */
};

/*
 * Hash password asynchronously using default algorithm.
 * Callback receives: result (0=success, -1=error), hash string.
 *
 * @param password  Plaintext password (copied internally)
 * @param callback  Called in main thread when done
 * @param ctx       Passed to callback
 * @return 0 if submitted, -1 on error (callback not called)
 */
int pw_hash_async(const char *password, pw_async_callback callback, void *ctx);

/*
 * Hash password asynchronously using specific algorithm.
 *
 * @param password  Plaintext password (copied internally)
 * @param algorithm Algorithm to use
 * @param callback  Called in main thread when done
 * @param ctx       Passed to callback
 * @return 0 if submitted, -1 on error (callback not called)
 */
int pw_hash_with_async(const char *password, enum pw_algorithm algorithm,
                       pw_async_callback callback, void *ctx);

/*
 * Verify password asynchronously.
 * Callback receives: result (1=match, 0=no match, -1=error), NULL for hash.
 *
 * @param password  Plaintext password (copied internally)
 * @param hash      Stored hash to verify against (copied internally)
 * @param callback  Called in main thread when done
 * @param ctx       Passed to callback
 * @return 0 if submitted, -1 on error (callback not called)
 */
int pw_verify_async(const char *password, const char *hash,
                    pw_async_callback callback, void *ctx);

#endif /* PASSWORD_H */
