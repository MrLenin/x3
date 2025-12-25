/*
 * X3 - SSL/TLS Wrapper Module
 * Copyright (C) 2024 AfterNET Development Team
 *
 * Provides SSL/TLS support for X3 S2S connections to IRC servers.
 * Wraps OpenSSL with non-blocking I/O compatible with ioset abstraction.
 */

#include "x3_ssl.h"

#ifdef WITH_SSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "log.h"

/* Module-level state */
static int ssl_initialized = 0;

/* Error buffer for x3_ssl_error_string() */
static char ssl_error_buf[256];

/* ========== Initialization ========== */

int x3_ssl_init(void)
{
    if (ssl_initialized)
        return 0;

    /* OpenSSL 1.1.0+ auto-initializes, but explicit init is safe */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif

    ssl_initialized = 1;
    log_module(MAIN_LOG, LOG_INFO, "SSL/TLS support initialized (OpenSSL %s)",
               OpenSSL_version(OPENSSL_VERSION));
    return 0;
}

void x3_ssl_shutdown(void)
{
    if (!ssl_initialized)
        return;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    ERR_free_strings();
#endif

    ssl_initialized = 0;
    log_module(MAIN_LOG, LOG_INFO, "SSL/TLS support shutdown");
}

int x3_ssl_is_available(void)
{
    return ssl_initialized;
}

/* ========== Context Management ========== */

SSL_CTX *x3_ssl_create_client_ctx(const char *cert_file, const char *key_file,
                                   int verify_peer, const char *ca_file)
{
    SSL_CTX *ctx;

    if (!ssl_initialized) {
        log_module(MAIN_LOG, LOG_ERROR, "SSL not initialized");
        return NULL;
    }

    /* Create context using TLS client method */
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        log_module(MAIN_LOG, LOG_ERROR, "Failed to create SSL context: %s",
                   x3_ssl_error_string());
        return NULL;
    }

    /* Enforce TLS 1.2+ minimum version */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* Set verification mode */
    if (verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

        /* Load CA certificates */
        if (ca_file && ca_file[0]) {
            if (!SSL_CTX_load_verify_locations(ctx, ca_file, NULL)) {
                log_module(MAIN_LOG, LOG_WARNING, "Failed to load CA file %s: %s",
                           ca_file, x3_ssl_error_string());
            }
        } else {
            /* Use system default CA certificates */
            SSL_CTX_set_default_verify_paths(ctx);
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    /* Load client certificate if provided */
    if (cert_file && cert_file[0]) {
        if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
            log_module(MAIN_LOG, LOG_ERROR, "Failed to load certificate %s: %s",
                       cert_file, x3_ssl_error_string());
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    /* Load client private key if provided */
    if (key_file && key_file[0]) {
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
            log_module(MAIN_LOG, LOG_ERROR, "Failed to load private key %s: %s",
                       key_file, x3_ssl_error_string());
            SSL_CTX_free(ctx);
            return NULL;
        }

        /* Verify private key matches certificate */
        if (!SSL_CTX_check_private_key(ctx)) {
            log_module(MAIN_LOG, LOG_ERROR, "Private key does not match certificate");
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    return ctx;
}

void x3_ssl_free_ctx(SSL_CTX *ctx)
{
    if (ctx)
        SSL_CTX_free(ctx);
}

/* ========== Connection Management ========== */

struct x3_ssl_conn *x3_ssl_connect(SSL_CTX *ctx, int fd)
{
    struct x3_ssl_conn *conn;

    if (!ctx) {
        log_module(MAIN_LOG, LOG_ERROR, "NULL SSL context");
        return NULL;
    }

    conn = calloc(1, sizeof(*conn));
    if (!conn) {
        log_module(MAIN_LOG, LOG_ERROR, "Failed to allocate SSL connection");
        return NULL;
    }

    conn->ctx = ctx;
    conn->fd = fd;
    conn->state = X3_SSL_DISCONNECTED;

    /* Create SSL object */
    conn->ssl = SSL_new(ctx);
    if (!conn->ssl) {
        log_module(MAIN_LOG, LOG_ERROR, "Failed to create SSL object: %s",
                   x3_ssl_error_string());
        free(conn);
        return NULL;
    }

    /* Attach to socket */
    if (!SSL_set_fd(conn->ssl, fd)) {
        log_module(MAIN_LOG, LOG_ERROR, "Failed to set SSL fd: %s",
                   x3_ssl_error_string());
        SSL_free(conn->ssl);
        free(conn);
        return NULL;
    }

    /* Set to client mode */
    SSL_set_connect_state(conn->ssl);
    conn->state = X3_SSL_CONNECTING;

    /* Start handshake (non-blocking) */
    if (x3_ssl_handshake(conn) < 0) {
        /* Error during initial handshake attempt */
        if (conn->state == X3_SSL_ERROR) {
            SSL_free(conn->ssl);
            free(conn);
            return NULL;
        }
    }

    return conn;
}

int x3_ssl_handshake(struct x3_ssl_conn *conn)
{
    int ret, err;

    if (!conn || !conn->ssl)
        return -1;

    if (conn->state == X3_SSL_CONNECTED)
        return 1;

    if (conn->state != X3_SSL_CONNECTING)
        return -1;

    /* Clear pending flags */
    conn->want_read = 0;
    conn->want_write = 0;

    ret = SSL_connect(conn->ssl);
    if (ret == 1) {
        /* Handshake complete */
        conn->state = X3_SSL_CONNECTED;
        log_module(MAIN_LOG, LOG_INFO, "SSL handshake complete: %s using %s",
                   x3_ssl_get_version(conn), x3_ssl_get_cipher(conn));
        return 1;
    }

    err = SSL_get_error(conn->ssl, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:
            conn->want_read = 1;
            return 0; /* Need to wait for readable */

        case SSL_ERROR_WANT_WRITE:
            conn->want_write = 1;
            return 0; /* Need to wait for writable */

        case SSL_ERROR_ZERO_RETURN:
            log_module(MAIN_LOG, LOG_WARNING, "SSL connection closed during handshake");
            conn->state = X3_SSL_ERROR;
            return -1;

        case SSL_ERROR_SYSCALL:
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                conn->want_read = 1;
                return 0;
            }
            log_module(MAIN_LOG, LOG_ERROR, "SSL handshake syscall error: %s",
                       strerror(errno));
            conn->state = X3_SSL_ERROR;
            return -1;

        default:
            log_module(MAIN_LOG, LOG_ERROR, "SSL handshake error: %s",
                       x3_ssl_error_string());
            conn->state = X3_SSL_ERROR;
            return -1;
    }
}

int x3_ssl_want_read(struct x3_ssl_conn *conn)
{
    return conn ? conn->want_read : 0;
}

int x3_ssl_want_write(struct x3_ssl_conn *conn)
{
    return conn ? conn->want_write : 0;
}

enum x3_ssl_state x3_ssl_get_state(struct x3_ssl_conn *conn)
{
    return conn ? conn->state : X3_SSL_DISCONNECTED;
}

/* ========== I/O Operations ========== */

ssize_t x3_ssl_read(struct x3_ssl_conn *conn, void *buf, size_t len)
{
    int ret, err;

    if (!conn || !conn->ssl)
        return -1;

    if (conn->state != X3_SSL_CONNECTED)
        return -1;

    conn->want_read = 0;
    conn->want_write = 0;

    ret = SSL_read(conn->ssl, buf, (int)len);
    if (ret > 0)
        return ret;

    err = SSL_get_error(conn->ssl, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:
            conn->want_read = 1;
            errno = EAGAIN;
            return -1;

        case SSL_ERROR_WANT_WRITE:
            conn->want_write = 1;
            errno = EAGAIN;
            return -1;

        case SSL_ERROR_ZERO_RETURN:
            /* Clean shutdown */
            return 0;

        case SSL_ERROR_SYSCALL:
            if (errno == 0)
                return 0; /* EOF */
            return -1;

        default:
            log_module(MAIN_LOG, LOG_WARNING, "SSL read error: %s",
                       x3_ssl_error_string());
            return -1;
    }
}

ssize_t x3_ssl_write(struct x3_ssl_conn *conn, const void *buf, size_t len)
{
    int ret, err;

    if (!conn || !conn->ssl)
        return -1;

    if (conn->state != X3_SSL_CONNECTED)
        return -1;

    conn->want_read = 0;
    conn->want_write = 0;

    ret = SSL_write(conn->ssl, buf, (int)len);
    if (ret > 0)
        return ret;

    err = SSL_get_error(conn->ssl, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:
            conn->want_read = 1;
            errno = EAGAIN;
            return -1;

        case SSL_ERROR_WANT_WRITE:
            conn->want_write = 1;
            errno = EAGAIN;
            return -1;

        case SSL_ERROR_ZERO_RETURN:
            return 0;

        case SSL_ERROR_SYSCALL:
            return -1;

        default:
            log_module(MAIN_LOG, LOG_WARNING, "SSL write error: %s",
                       x3_ssl_error_string());
            return -1;
    }
}

/* ========== Certificate Verification ========== */

int x3_ssl_get_fingerprint(struct x3_ssl_conn *conn, char *buf, size_t buflen)
{
    X509 *cert;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    unsigned int i;
    char *p;

    if (!conn || !conn->ssl || buflen < 65)
        return -1;

    cert = SSL_get_peer_certificate(conn->ssl);
    if (!cert)
        return -1;

    if (!X509_digest(cert, EVP_sha256(), md, &md_len)) {
        X509_free(cert);
        return -1;
    }

    X509_free(cert);

    /* Convert to hex string */
    p = buf;
    for (i = 0; i < md_len && (size_t)(p - buf + 3) < buflen; i++) {
        if (i > 0)
            *p++ = ':';
        sprintf(p, "%02X", md[i]);
        p += 2;
    }
    *p = '\0';

    return 0;
}

int x3_ssl_verify_fingerprint(struct x3_ssl_conn *conn, const char *expected)
{
    char actual[128];
    const char *ap, *ep;

    if (!expected || !expected[0])
        return 1; /* No fingerprint required */

    if (x3_ssl_get_fingerprint(conn, actual, sizeof(actual)) < 0)
        return -1;

    /* Compare ignoring case and colons */
    ap = actual;
    ep = expected;
    while (*ap && *ep) {
        /* Skip colons/spaces in both */
        while (*ap == ':' || *ap == ' ')
            ap++;
        while (*ep == ':' || *ep == ' ')
            ep++;

        if (!*ap || !*ep)
            break;

        if (tolower((unsigned char)*ap) != tolower((unsigned char)*ep))
            return 0; /* Mismatch */

        ap++;
        ep++;
    }

    /* Skip trailing colons/spaces */
    while (*ap == ':' || *ap == ' ')
        ap++;
    while (*ep == ':' || *ep == ' ')
        ep++;

    return (*ap == '\0' && *ep == '\0') ? 1 : 0;
}

int x3_ssl_get_peer_cn(struct x3_ssl_conn *conn, char *buf, size_t buflen)
{
    X509 *cert;
    X509_NAME *name;
    int idx;

    if (!conn || !conn->ssl)
        return -1;

    cert = SSL_get_peer_certificate(conn->ssl);
    if (!cert)
        return -1;

    name = X509_get_subject_name(cert);
    if (!name) {
        X509_free(cert);
        return -1;
    }

    idx = X509_NAME_get_text_by_NID(name, NID_commonName, buf, (int)buflen);
    X509_free(cert);

    return (idx >= 0) ? 0 : -1;
}

/* ========== Connection Info ========== */

const char *x3_ssl_get_cipher(struct x3_ssl_conn *conn)
{
    if (!conn || !conn->ssl || conn->state != X3_SSL_CONNECTED)
        return NULL;
    return SSL_get_cipher(conn->ssl);
}

const char *x3_ssl_get_version(struct x3_ssl_conn *conn)
{
    if (!conn || !conn->ssl || conn->state != X3_SSL_CONNECTED)
        return NULL;
    return SSL_get_version(conn->ssl);
}

/* ========== Cleanup ========== */

void x3_ssl_close(struct x3_ssl_conn *conn)
{
    if (!conn)
        return;

    if (conn->ssl) {
        /* Attempt clean shutdown (non-blocking, best effort) */
        if (conn->state == X3_SSL_CONNECTED)
            SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }

    free(conn);
}

const char *x3_ssl_error_string(void)
{
    unsigned long err = ERR_get_error();
    if (err == 0)
        return "No error";
    ERR_error_string_n(err, ssl_error_buf, sizeof(ssl_error_buf));
    return ssl_error_buf;
}

#endif /* WITH_SSL */
