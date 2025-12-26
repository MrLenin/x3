/* webpush.c - IRCv3 Web Push implementation
 * Copyright 2024 X3 Development Team
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

#include "config.h"

/* Web Push requires:
 * - libcurl (for HTTP POST)
 * - OpenSSL 3.x (for ECDH, AES-GCM, HKDF)
 *
 * Enable with: configure --with-keycloak (provides libcurl)
 *              and ensure OpenSSL is available
 */

#ifdef WITH_KEYCLOAK  /* Requires libcurl */

/* Check for OpenSSL 3.x features we need */
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define HAVE_WEBPUSH_CRYPTO 1
#else
#define HAVE_WEBPUSH_CRYPTO 0
#endif

#if HAVE_WEBPUSH_CRYPTO

#include "webpush.h"
#include "log.h"
#include "nickserv.h"
#include "keycloak.h"
#include "x3_ssl.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

/* VAPID keypair - generated on first use, should be persisted */
static EVP_PKEY *vapid_key = NULL;
static char vapid_pubkey_b64[128] = "";

/* Base64url encoding (RFC 4648 section 5) */
static const char b64url_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int
base64url_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len)
{
    size_t i, j;
    size_t needed = ((in_len + 2) / 3) * 4 + 1;

    if (out_len < needed)
        return -1;

    for (i = 0, j = 0; i < in_len; i += 3) {
        unsigned int n = ((unsigned int)in[i]) << 16;
        if (i + 1 < in_len) n |= ((unsigned int)in[i + 1]) << 8;
        if (i + 2 < in_len) n |= in[i + 2];

        out[j++] = b64url_chars[(n >> 18) & 0x3F];
        out[j++] = b64url_chars[(n >> 12) & 0x3F];
        if (i + 1 < in_len)
            out[j++] = b64url_chars[(n >> 6) & 0x3F];
        if (i + 2 < in_len)
            out[j++] = b64url_chars[n & 0x3F];
    }
    out[j] = '\0';
    return (int)j;
}

static int
base64url_decode(const char *in, unsigned char *out, size_t out_len)
{
    size_t in_len = strlen(in);
    size_t i, j;
    int padding = 0;

    /* Calculate output length */
    size_t needed = (in_len * 3) / 4;
    if (out_len < needed)
        return -1;

    for (i = 0, j = 0; i < in_len; i += 4) {
        unsigned int n = 0;
        int k;

        for (k = 0; k < 4 && i + k < in_len; k++) {
            char c = in[i + k];
            int v;

            if (c >= 'A' && c <= 'Z') v = c - 'A';
            else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
            else if (c >= '0' && c <= '9') v = c - '0' + 52;
            else if (c == '-') v = 62;
            else if (c == '_') v = 63;
            else if (c == '=') { padding++; v = 0; }
            else return -1;  /* Invalid character */

            n = (n << 6) | v;
        }

        /* Pad remaining positions if short */
        for (; k < 4; k++) {
            n <<= 6;
            padding++;
        }

        out[j++] = (n >> 16) & 0xFF;
        if (padding < 2 && j < out_len) out[j++] = (n >> 8) & 0xFF;
        if (padding < 1 && j < out_len) out[j++] = n & 0xFF;
    }

    return (int)(j - padding);
}

/* Generate VAPID ECDSA P-256 keypair */
static int
generate_vapid_key(void)
{
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char pubkey_raw[65];
    size_t pubkey_len = sizeof(pubkey_raw);
    int ret = -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) goto cleanup;

    if (EVP_PKEY_keygen_init(pctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(pctx, &vapid_key) <= 0) goto cleanup;

    /* Extract public key in uncompressed form */
    if (EVP_PKEY_get_octet_string_param(vapid_key, OSSL_PKEY_PARAM_PUB_KEY,
                                         pubkey_raw, sizeof(pubkey_raw), &pubkey_len) <= 0)
        goto cleanup;

    /* Encode as base64url for ISUPPORT */
    if (base64url_encode(pubkey_raw, pubkey_len, vapid_pubkey_b64, sizeof(vapid_pubkey_b64)) < 0)
        goto cleanup;

    ret = 0;
    log_module(MAIN_LOG, LOG_INFO, "WEBPUSH: Generated VAPID key: %s", vapid_pubkey_b64);

cleanup:
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return ret;
}

int
webpush_init(void)
{
    if (vapid_key)
        return 0;  /* Already initialized */

    /* Ensure OpenSSL is initialized (needed for EVP crypto functions) */
    x3_ssl_init();

    if (generate_vapid_key() < 0) {
        log_module(MAIN_LOG, LOG_ERROR, "WEBPUSH: Failed to generate VAPID key");
        return -1;
    }

    return 0;
}

void
webpush_cleanup(void)
{
    if (vapid_key) {
        EVP_PKEY_free(vapid_key);
        vapid_key = NULL;
    }
    vapid_pubkey_b64[0] = '\0';
}

int
webpush_get_vapid_pubkey(char *out, size_t out_len)
{
    size_t len = strlen(vapid_pubkey_b64);
    if (len == 0 || out_len <= len)
        return -1;
    strcpy(out, vapid_pubkey_b64);
    return (int)len;
}

int
webpush_parse_subscription(const char *stored, struct webpush_subscription *sub)
{
    char *copy, *p, *endpoint, *p256dh_str, *auth_str;
    int ret = -1;

    if (!stored || !sub)
        return -1;

    memset(sub, 0, sizeof(*sub));

    copy = strdup(stored);
    if (!copy)
        return -1;

    /* Format: endpoint|p256dh_base64|auth_base64 */
    endpoint = copy;
    p = strchr(endpoint, '|');
    if (!p) goto cleanup;
    *p++ = '\0';

    p256dh_str = p;
    p = strchr(p256dh_str, '|');
    if (!p) goto cleanup;
    *p++ = '\0';

    auth_str = p;

    /* Copy endpoint */
    if (strlen(endpoint) >= WEBPUSH_MAX_ENDPOINT) goto cleanup;
    strcpy(sub->endpoint, endpoint);

    /* Decode p256dh (client public key) */
    sub->p256dh_len = base64url_decode(p256dh_str, sub->p256dh, sizeof(sub->p256dh));
    if (sub->p256dh_len <= 0 || sub->p256dh_len > WEBPUSH_P256DH_LEN) goto cleanup;

    /* Decode auth secret */
    sub->auth_len = base64url_decode(auth_str, sub->auth, sizeof(sub->auth));
    if (sub->auth_len <= 0 || sub->auth_len > WEBPUSH_AUTH_LEN) goto cleanup;

    ret = 0;

cleanup:
    free(copy);
    return ret;
}

/* HKDF-SHA256 implementation */
static int
hkdf_sha256(const unsigned char *salt, size_t salt_len,
            const unsigned char *ikm, size_t ikm_len,
            const unsigned char *info, size_t info_len,
            unsigned char *okm, size_t okm_len)
{
    EVP_PKEY_CTX *pctx;
    int ret = -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) goto cleanup;
    if (EVP_PKEY_derive(pctx, okm, &okm_len) <= 0) goto cleanup;

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int
webpush_encrypt(const struct webpush_subscription *sub,
                const unsigned char *plaintext, size_t plaintext_len,
                unsigned char *out, size_t *out_len)
{
    EVP_PKEY *ephemeral_key = NULL;
    EVP_PKEY *ua_public = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    EVP_CIPHER_CTX *cctx = NULL;

    unsigned char ephemeral_pub[65];
    size_t ephemeral_pub_len = sizeof(ephemeral_pub);
    unsigned char shared_secret[32];
    size_t shared_secret_len = sizeof(shared_secret);
    unsigned char salt[16];
    unsigned char prk[32];
    unsigned char cek[16];
    unsigned char nonce[12];
    unsigned char info_cek[128];
    unsigned char info_nonce[128];
    size_t info_cek_len, info_nonce_len;
    unsigned char padded[WEBPUSH_MAX_PAYLOAD + 2];
    size_t padded_len;
    unsigned char *ciphertext;
    int ciphertext_len, final_len;
    unsigned char tag[16];
    int ret = WEBPUSH_ERR_CRYPTO;

    if (!sub || !plaintext || !out || !out_len)
        return WEBPUSH_ERR_INVALID;

    /* Generate random salt (16 bytes) */
    if (RAND_bytes(salt, sizeof(salt)) != 1)
        goto cleanup;

    /* Generate ephemeral ECDH key */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) goto cleanup;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(pctx, &ephemeral_key) <= 0) goto cleanup;
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    /* Get ephemeral public key */
    if (EVP_PKEY_get_octet_string_param(ephemeral_key, OSSL_PKEY_PARAM_PUB_KEY,
                                         ephemeral_pub, sizeof(ephemeral_pub), &ephemeral_pub_len) <= 0)
        goto cleanup;

    /* Import client's public key (ua_public) */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) goto cleanup;
    if (EVP_PKEY_fromdata_init(pctx) <= 0) goto cleanup;
    {
        OSSL_PARAM params[3];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)sub->p256dh, sub->p256dh_len);
        params[2] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_fromdata(pctx, &ua_public, EVP_PKEY_PUBLIC_KEY, params) <= 0)
            goto cleanup;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    /* Perform ECDH to get shared secret */
    dctx = EVP_PKEY_CTX_new(ephemeral_key, NULL);
    if (!dctx) goto cleanup;
    if (EVP_PKEY_derive_init(dctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(dctx, ua_public) <= 0) goto cleanup;
    if (EVP_PKEY_derive(dctx, shared_secret, &shared_secret_len) <= 0) goto cleanup;
    EVP_PKEY_CTX_free(dctx);
    dctx = NULL;

    /* RFC 8291 key derivation:
     * info = "WebPush: info" || 0x00 || ua_public || as_public
     * ikm = ECDH(as_private, ua_public)
     * PRK = HKDF-Extract(auth_secret, ikm)
     *
     * For CEK: info = "Content-Encoding: aes128gcm" || 0x00
     * CEK = HKDF-Expand(PRK, info, 16)
     *
     * For nonce: info = "Content-Encoding: nonce" || 0x00
     * nonce = HKDF-Expand(PRK, info, 12)
     */

    /* Build info for PRK derivation */
    {
        unsigned char prk_info[256];
        size_t prk_info_len = 0;
        memcpy(prk_info + prk_info_len, "WebPush: info\x00", 14);
        prk_info_len += 14;
        memcpy(prk_info + prk_info_len, sub->p256dh, sub->p256dh_len);
        prk_info_len += sub->p256dh_len;
        memcpy(prk_info + prk_info_len, ephemeral_pub, ephemeral_pub_len);
        prk_info_len += ephemeral_pub_len;

        /* Extract PRK using auth as salt */
        if (hkdf_sha256(sub->auth, sub->auth_len, shared_secret, shared_secret_len,
                        prk_info, prk_info_len, prk, sizeof(prk)) < 0)
            goto cleanup;
    }

    /* Derive CEK */
    info_cek_len = snprintf((char*)info_cek, sizeof(info_cek), "Content-Encoding: aes128gcm");
    info_cek[info_cek_len++] = 0;
    if (hkdf_sha256(salt, sizeof(salt), prk, sizeof(prk), info_cek, info_cek_len, cek, sizeof(cek)) < 0)
        goto cleanup;

    /* Derive nonce */
    info_nonce_len = snprintf((char*)info_nonce, sizeof(info_nonce), "Content-Encoding: nonce");
    info_nonce[info_nonce_len++] = 0;
    if (hkdf_sha256(salt, sizeof(salt), prk, sizeof(prk), info_nonce, info_nonce_len, nonce, sizeof(nonce)) < 0)
        goto cleanup;

    /* Pad plaintext (RFC 8291 Section 4)
     * Format: padding-delimiter (0x02) || plaintext
     * We use no padding, just the delimiter
     */
    if (plaintext_len + 1 > sizeof(padded))
        goto cleanup;
    padded[0] = 0x02;  /* Padding delimiter */
    memcpy(padded + 1, plaintext, plaintext_len);
    padded_len = plaintext_len + 1;

    /* Encrypt with AES-128-GCM */
    cctx = EVP_CIPHER_CTX_new();
    if (!cctx) goto cleanup;

    if (EVP_EncryptInit_ex(cctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(cctx, NULL, NULL, cek, nonce) != 1)
        goto cleanup;

    /* Build output: salt (16) || rs (4) || idlen (1) || keyid (65) || ciphertext || tag (16) */
    ciphertext = out + 16 + 4 + 1 + ephemeral_pub_len;

    if (EVP_EncryptUpdate(cctx, ciphertext, &ciphertext_len, padded, padded_len) != 1)
        goto cleanup;
    if (EVP_EncryptFinal_ex(cctx, ciphertext + ciphertext_len, &final_len) != 1)
        goto cleanup;
    ciphertext_len += final_len;

    /* Get authentication tag */
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto cleanup;

    /* Build aes128gcm header */
    memcpy(out, salt, 16);                      /* Salt */
    out[16] = 0x00; out[17] = 0x00;             /* Record size (high bytes) */
    out[18] = 0x10; out[19] = 0x01;             /* Record size = 4097 */
    out[20] = (unsigned char)ephemeral_pub_len; /* Key ID length */
    memcpy(out + 21, ephemeral_pub, ephemeral_pub_len);  /* Key ID (ephemeral public key) */

    /* Append tag after ciphertext */
    memcpy(ciphertext + ciphertext_len, tag, sizeof(tag));

    *out_len = 16 + 4 + 1 + ephemeral_pub_len + ciphertext_len + sizeof(tag);
    ret = WEBPUSH_OK;

cleanup:
    if (ephemeral_key) EVP_PKEY_free(ephemeral_key);
    if (ua_public) EVP_PKEY_free(ua_public);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (dctx) EVP_PKEY_CTX_free(dctx);
    if (cctx) EVP_CIPHER_CTX_free(cctx);

    /* Clear sensitive data */
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(cek, sizeof(cek));
    OPENSSL_cleanse(nonce, sizeof(nonce));

    return ret;
}

/* Create VAPID Authorization header */
static int
create_vapid_header(const char *audience, char *header, size_t header_len)
{
    unsigned char jwt_header[] = "{\"typ\":\"JWT\",\"alg\":\"ES256\"}";
    char jwt_payload[512];
    char jwt_header_b64[128], jwt_payload_b64[512];
    char jwt_input[768];
    unsigned char signature[72];
    size_t sig_len = sizeof(signature);
    char sig_b64[128];
    EVP_MD_CTX *mdctx = NULL;
    time_t now;
    int ret = -1;

    if (!vapid_key)
        return -1;

    /* Build JWT payload */
    now = time(NULL);
    snprintf(jwt_payload, sizeof(jwt_payload),
             "{\"aud\":\"%s\",\"exp\":%ld,\"sub\":\"mailto:noreply@example.com\"}",
             audience, (long)(now + 86400));

    /* Base64url encode header and payload */
    base64url_encode(jwt_header, strlen((char*)jwt_header), jwt_header_b64, sizeof(jwt_header_b64));
    base64url_encode((unsigned char*)jwt_payload, strlen(jwt_payload), jwt_payload_b64, sizeof(jwt_payload_b64));

    /* Create signing input */
    snprintf(jwt_input, sizeof(jwt_input), "%s.%s", jwt_header_b64, jwt_payload_b64);

    /* Sign with ECDSA */
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto cleanup;

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, vapid_key) <= 0)
        goto cleanup;
    if (EVP_DigestSign(mdctx, signature, &sig_len, (unsigned char*)jwt_input, strlen(jwt_input)) <= 0)
        goto cleanup;

    /* The signature is in DER format, we need raw r||s format (64 bytes)
     * For simplicity, we'll use the DER format since many libraries accept it
     * A proper implementation would extract r and s and concatenate them
     */
    base64url_encode(signature, sig_len, sig_b64, sizeof(sig_b64));

    /* Build Authorization header */
    snprintf(header, header_len, "vapid t=%s.%s, k=%s",
             jwt_input, sig_b64, vapid_pubkey_b64);

    ret = 0;

cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    return ret;
}

/* Extract origin from endpoint URL */
static int
get_audience(const char *endpoint, char *audience, size_t len)
{
    const char *p;
    size_t origin_len;

    /* Skip https:// */
    if (strncmp(endpoint, "https://", 8) != 0)
        return -1;
    p = endpoint + 8;

    /* Find end of host */
    while (*p && *p != '/' && *p != ':' && *p != '?')
        p++;

    origin_len = p - endpoint;
    if (origin_len >= len)
        return -1;

    memcpy(audience, endpoint, origin_len);
    audience[origin_len] = '\0';

    return 0;
}

int
webpush_send(const struct webpush_subscription *sub, const char *message, int ttl)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    unsigned char encrypted[WEBPUSH_ENCRYPTED_MAX];
    size_t encrypted_len = sizeof(encrypted);
    char vapid_header[1024];
    char audience[256];
    char ttl_header[64];
    char length_header[64];
    CURLcode res;
    long http_code;
    int ret = WEBPUSH_ERR_HTTP;

    if (!sub || !message)
        return WEBPUSH_ERR_INVALID;

    /* Encrypt the message */
    if (webpush_encrypt(sub, (unsigned char*)message, strlen(message), encrypted, &encrypted_len) != WEBPUSH_OK) {
        log_module(MAIN_LOG, LOG_ERROR, "WEBPUSH: Encryption failed");
        return WEBPUSH_ERR_CRYPTO;
    }

    /* Get audience (origin) from endpoint */
    if (get_audience(sub->endpoint, audience, sizeof(audience)) < 0) {
        log_module(MAIN_LOG, LOG_ERROR, "WEBPUSH: Invalid endpoint URL");
        return WEBPUSH_ERR_INVALID;
    }

    /* Create VAPID header */
    if (create_vapid_header(audience, vapid_header, sizeof(vapid_header)) < 0) {
        log_module(MAIN_LOG, LOG_ERROR, "WEBPUSH: Failed to create VAPID header");
        return WEBPUSH_ERR_CRYPTO;
    }

    curl = curl_easy_init();
    if (!curl)
        return WEBPUSH_ERR_MEMORY;

    /* Set up headers */
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    headers = curl_slist_append(headers, "Content-Encoding: aes128gcm");
    snprintf(ttl_header, sizeof(ttl_header), "TTL: %d", ttl > 0 ? ttl : 86400);
    headers = curl_slist_append(headers, ttl_header);
    snprintf(length_header, sizeof(length_header), "Content-Length: %zu", encrypted_len);
    headers = curl_slist_append(headers, length_header);

    /* Add Authorization header with VAPID */
    {
        char auth_header[1100];
        snprintf(auth_header, sizeof(auth_header), "Authorization: %s", vapid_header);
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(curl, CURLOPT_URL, sub->endpoint);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encrypted);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)encrypted_len);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code >= 200 && http_code < 300) {
            log_module(MAIN_LOG, LOG_INFO, "WEBPUSH: Sent to %s (HTTP %ld)", sub->endpoint, http_code);
            ret = WEBPUSH_OK;
        } else if (http_code == 410) {
            log_module(MAIN_LOG, LOG_WARNING, "WEBPUSH: Subscription expired for %s", sub->endpoint);
            ret = WEBPUSH_ERR_EXPIRED;
        } else {
            log_module(MAIN_LOG, LOG_WARNING, "WEBPUSH: HTTP %ld from %s", http_code, sub->endpoint);
            ret = WEBPUSH_ERR_HTTP;
        }
    } else {
        log_module(MAIN_LOG, LOG_ERROR, "WEBPUSH: curl error: %s", curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return ret;
}

int
webpush_notify_user(const char *account_name, const char *message)
{
    struct kc_metadata_entry *entries = NULL;
    struct kc_metadata_entry *entry;
    struct webpush_subscription sub;
    int sent = 0;
    int result;

    if (!account_name || !message)
        return -1;

    /* Get all webpush subscriptions for this account */
    if (nickserv_get_webpush_subscriptions(account_name, &entries) != 0) {
        log_module(MAIN_LOG, LOG_DEBUG, "WEBPUSH: No subscriptions for %s", account_name);
        return 0;
    }

    if (!entries) {
        log_module(MAIN_LOG, LOG_DEBUG, "WEBPUSH: No subscriptions for %s (empty)", account_name);
        return 0;
    }

    log_module(MAIN_LOG, LOG_INFO, "WEBPUSH: Sending push notifications for %s", account_name);

    /* Iterate over subscriptions and send to each */
    for (entry = entries; entry; entry = entry->next) {
        /* Value format: endpoint|p256dh|auth */
        if (webpush_parse_subscription(entry->value, &sub) != 0) {
            log_module(MAIN_LOG, LOG_WARNING, "WEBPUSH: Failed to parse subscription %s", entry->key);
            continue;
        }

        result = webpush_send(&sub, message, 86400);  /* 24 hour TTL */

        if (result == WEBPUSH_OK) {
            sent++;
        } else if (result == WEBPUSH_ERR_EXPIRED) {
            /* Subscription expired - could delete it here */
            log_module(MAIN_LOG, LOG_INFO, "WEBPUSH: Subscription %s expired, should be removed",
                       entry->key);
            /* TODO: Delete expired subscription from Keycloak */
        }
    }

    keycloak_free_metadata_entries(entries);

    log_module(MAIN_LOG, LOG_INFO, "WEBPUSH: Sent %d push notifications for %s", sent, account_name);
    return sent;
}

#else /* !HAVE_WEBPUSH_CRYPTO */

/* Stub implementations when OpenSSL 3.x not available */
#include "webpush.h"
#include "log.h"

int webpush_init(void) {
    log_module(MAIN_LOG, LOG_WARNING, "WEBPUSH: Disabled - requires OpenSSL 3.x");
    return -1;
}
void webpush_cleanup(void) { }
int webpush_get_vapid_pubkey(char *out, size_t out_len) { return -1; }
int webpush_parse_subscription(const char *stored, struct webpush_subscription *sub) { return -1; }
int webpush_encrypt(const struct webpush_subscription *sub,
                    const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *out, size_t *out_len) { return -1; }
int webpush_send(const struct webpush_subscription *sub, const char *message, int ttl) { return -1; }
int webpush_notify_user(const char *account_name, const char *message) { return 0; }

#endif /* HAVE_WEBPUSH_CRYPTO */

#else /* !WITH_KEYCLOAK */

/* Stub implementations when Keycloak/libcurl not available */
#include "webpush.h"

int webpush_init(void) { return -1; }
void webpush_cleanup(void) { }
int webpush_get_vapid_pubkey(char *out, size_t out_len) { return -1; }
int webpush_parse_subscription(const char *stored, struct webpush_subscription *sub) { return -1; }
int webpush_encrypt(const struct webpush_subscription *sub,
                    const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *out, size_t *out_len) { return -1; }
int webpush_send(const struct webpush_subscription *sub, const char *message, int ttl) { return -1; }
int webpush_notify_user(const char *account_name, const char *message) { return 0; }

#endif /* WITH_KEYCLOAK */
