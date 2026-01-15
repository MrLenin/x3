/*
 * X3 - SSL/TLS Wrapper Module
 * Copyright (C) 2024 AfterNET Development Team
 *
 * Provides SSL/TLS support for X3 S2S connections to IRC servers.
 * Wraps OpenSSL with non-blocking I/O compatible with ioset abstraction.
 */
#ifndef X3_SSL_H
#define X3_SSL_H

#include "config.h"

#ifdef WITH_SSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <sys/types.h>

/* SSL connection state */
enum x3_ssl_state {
    X3_SSL_DISCONNECTED = 0,
    X3_SSL_CONNECTING,      /* SSL handshake in progress */
    X3_SSL_CONNECTED,       /* SSL established */
    X3_SSL_ERROR
};

/* SSL connection context */
struct x3_ssl_conn {
    SSL *ssl;
    SSL_CTX *ctx;           /* Reference to context (not owned) */
    enum x3_ssl_state state;
    int want_read;          /* SSL_ERROR_WANT_READ pending */
    int want_write;         /* SSL_ERROR_WANT_WRITE pending */
    int fd;                 /* Socket file descriptor */
};

/* ========== Initialization ========== */

/**
 * Initialize the global SSL library
 * Must be called before any other SSL functions
 * @return 0 on success, -1 on failure
 */
int x3_ssl_init(void);

/**
 * Shutdown the SSL library and cleanup
 */
void x3_ssl_shutdown(void);

/**
 * Check if SSL support is available and initialized
 * @return 1 if available, 0 if not
 */
int x3_ssl_is_available(void);

/* ========== Context Management ========== */

/**
 * Create SSL context for client (outbound) connections
 * @param cert_file Path to client certificate (can be NULL)
 * @param key_file Path to client private key (can be NULL)
 * @param verify_peer 1 to verify server certificate, 0 to skip
 * @param ca_file Path to CA certificate file (can be NULL for system CAs)
 * @return SSL_CTX on success, NULL on failure
 */
SSL_CTX *x3_ssl_create_client_ctx(const char *cert_file, const char *key_file,
                                   int verify_peer, const char *ca_file);

/**
 * Free an SSL context
 * @param ctx Context to free (can be NULL)
 */
void x3_ssl_free_ctx(SSL_CTX *ctx);

/* ========== Connection Management ========== */

/**
 * Start SSL handshake on an existing connected socket (non-blocking)
 * @param ctx SSL context to use
 * @param fd Socket file descriptor (must already be connected)
 * @return x3_ssl_conn on success, NULL on failure
 */
struct x3_ssl_conn *x3_ssl_connect(SSL_CTX *ctx, int fd);

/**
 * Continue SSL handshake (call when socket is readable/writable)
 * @param conn SSL connection
 * @return 1 if handshake complete, 0 if need more I/O, -1 on error
 */
int x3_ssl_handshake(struct x3_ssl_conn *conn);

/**
 * Check if SSL connection needs read event
 * @param conn SSL connection
 * @return 1 if waiting for read, 0 otherwise
 */
int x3_ssl_want_read(struct x3_ssl_conn *conn);

/**
 * Check if SSL connection needs write event
 * @param conn SSL connection
 * @return 1 if waiting for write, 0 otherwise
 */
int x3_ssl_want_write(struct x3_ssl_conn *conn);

/**
 * Get SSL connection state
 * @param conn SSL connection
 * @return Current state
 */
enum x3_ssl_state x3_ssl_get_state(struct x3_ssl_conn *conn);

/* ========== I/O Operations ========== */

/**
 * SSL-aware read (replaces recv())
 * @param conn SSL connection
 * @param buf Buffer to read into
 * @param len Maximum bytes to read
 * @return Bytes read, 0 on EOF, -1 on error (check want_read/want_write)
 */
ssize_t x3_ssl_read(struct x3_ssl_conn *conn, void *buf, size_t len);

/**
 * Check if SSL layer has buffered data ready to read
 * IMPORTANT: Must check this after SSL_read to avoid missing data.
 * SSL can buffer decrypted data internally that won't wake up epoll.
 * @param conn SSL connection
 * @return Number of bytes available, 0 if none
 */
int x3_ssl_pending(struct x3_ssl_conn *conn);

/**
 * SSL-aware write (replaces send())
 * @param conn SSL connection
 * @param buf Buffer to write from
 * @param len Bytes to write
 * @return Bytes written, -1 on error (check want_read/want_write)
 */
ssize_t x3_ssl_write(struct x3_ssl_conn *conn, const void *buf, size_t len);

/* ========== Certificate Verification ========== */

/**
 * Get peer certificate fingerprint (SHA256)
 * @param conn SSL connection
 * @param buf Buffer for hex fingerprint (needs at least 65 bytes)
 * @param buflen Size of buffer
 * @return 0 on success, -1 on failure
 */
int x3_ssl_get_fingerprint(struct x3_ssl_conn *conn, char *buf, size_t buflen);

/**
 * Verify peer certificate fingerprint matches expected value
 * @param conn SSL connection
 * @param expected Expected fingerprint (hex string, case-insensitive)
 * @return 1 if match, 0 if mismatch, -1 on error
 */
int x3_ssl_verify_fingerprint(struct x3_ssl_conn *conn, const char *expected);

/**
 * Get peer certificate common name
 * @param conn SSL connection
 * @param buf Buffer for CN
 * @param buflen Size of buffer
 * @return 0 on success, -1 on failure
 */
int x3_ssl_get_peer_cn(struct x3_ssl_conn *conn, char *buf, size_t buflen);

/* ========== Connection Info ========== */

/**
 * Get cipher name for the connection
 * @param conn SSL connection
 * @return Cipher name string, or NULL if not connected
 */
const char *x3_ssl_get_cipher(struct x3_ssl_conn *conn);

/**
 * Get protocol version for the connection
 * @param conn SSL connection
 * @return Protocol version string (e.g., "TLSv1.3"), or NULL if not connected
 */
const char *x3_ssl_get_version(struct x3_ssl_conn *conn);

/* ========== Cleanup ========== */

/**
 * Close SSL connection and free resources
 * @param conn SSL connection (can be NULL)
 */
void x3_ssl_close(struct x3_ssl_conn *conn);

/**
 * Get last SSL error as a string
 * @return Error string (static buffer, do not free)
 */
const char *x3_ssl_error_string(void);

#else /* !WITH_SSL */

/* Stub definitions when SSL is not compiled in */
struct x3_ssl_conn;

#define x3_ssl_init()                           (0)
#define x3_ssl_shutdown()                       do {} while(0)
#define x3_ssl_is_available()                   (0)
#define x3_ssl_create_client_ctx(c,k,v,a)       (NULL)
#define x3_ssl_free_ctx(c)                      do {} while(0)
#define x3_ssl_connect(c,f)                     (NULL)
#define x3_ssl_handshake(c)                     (-1)
#define x3_ssl_want_read(c)                     (0)
#define x3_ssl_want_write(c)                    (0)
#define x3_ssl_get_state(c)                     (0)
#define x3_ssl_read(c,b,l)                      (-1)
#define x3_ssl_pending(c)                       (0)
#define x3_ssl_write(c,b,l)                     (-1)
#define x3_ssl_get_fingerprint(c,b,l)           (-1)
#define x3_ssl_verify_fingerprint(c,e)          (-1)
#define x3_ssl_get_peer_cn(c,b,l)               (-1)
#define x3_ssl_get_cipher(c)                    (NULL)
#define x3_ssl_get_version(c)                   (NULL)
#define x3_ssl_close(c)                         do {} while(0)
#define x3_ssl_error_string()                   ("SSL not compiled in")

#endif /* WITH_SSL */

#endif /* X3_SSL_H */
