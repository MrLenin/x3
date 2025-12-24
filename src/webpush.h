/* webpush.h - IRCv3 Web Push implementation
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

#ifndef WEBPUSH_H
#define WEBPUSH_H

#include <stddef.h>

/* RFC 8291 - Web Push Message Encryption
 * RFC 8292 - VAPID
 * RFC 8030 - HTTP Push Protocol
 */

/* Maximum sizes */
#define WEBPUSH_MAX_ENDPOINT 512
#define WEBPUSH_MAX_PAYLOAD 4096
#define WEBPUSH_P256DH_LEN 65       /* Uncompressed P-256 public key */
#define WEBPUSH_AUTH_LEN 16         /* Auth secret */
#define WEBPUSH_VAPID_KEY_LEN 65    /* VAPID public key */
#define WEBPUSH_ENCRYPTED_MAX (WEBPUSH_MAX_PAYLOAD + 128)

/* Subscription info parsed from storage */
struct webpush_subscription {
    char endpoint[WEBPUSH_MAX_ENDPOINT];
    unsigned char p256dh[WEBPUSH_P256DH_LEN];
    size_t p256dh_len;
    unsigned char auth[WEBPUSH_AUTH_LEN];
    size_t auth_len;
};

/* Push result codes */
enum webpush_result {
    WEBPUSH_OK = 0,
    WEBPUSH_ERR_CRYPTO = -1,
    WEBPUSH_ERR_HTTP = -2,
    WEBPUSH_ERR_EXPIRED = -3,
    WEBPUSH_ERR_INVALID = -4,
    WEBPUSH_ERR_MEMORY = -5
};

/**
 * Initialize the webpush subsystem.
 * Generates VAPID keys if not already present.
 * @return 0 on success, -1 on error
 */
int webpush_init(void);

/**
 * Cleanup the webpush subsystem.
 */
void webpush_cleanup(void);

/**
 * Get the VAPID public key in base64url encoding.
 * @param out Buffer to receive key (at least 100 bytes)
 * @param out_len Size of output buffer
 * @return Length of key, or -1 on error
 */
int webpush_get_vapid_pubkey(char *out, size_t out_len);

/**
 * Parse a subscription from stored format.
 * Format: endpoint|p256dh_base64|auth_base64
 * @param stored The stored subscription string
 * @param sub Output subscription structure
 * @return 0 on success, -1 on error
 */
int webpush_parse_subscription(const char *stored, struct webpush_subscription *sub);

/**
 * Encrypt a message for web push delivery.
 * Implements RFC 8291 (aes128gcm content encoding).
 * @param sub The subscription to encrypt for
 * @param plaintext The message to encrypt
 * @param plaintext_len Length of message
 * @param out Buffer for encrypted output
 * @param out_len Size of output buffer, updated with actual length
 * @return 0 on success, negative error code on failure
 */
int webpush_encrypt(const struct webpush_subscription *sub,
                    const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *out, size_t *out_len);

/**
 * Send a push notification to a subscription.
 * @param sub The subscription to send to
 * @param message The IRC message to send
 * @param ttl Time-to-live in seconds
 * @return 0 on success, negative error code on failure
 */
int webpush_send(const struct webpush_subscription *sub,
                 const char *message, int ttl);

/**
 * Send push notifications for a user who has messages.
 * Called when a message arrives for an offline user.
 * @param account_name The user's account name
 * @param message The IRC message that triggered the push
 * @return Number of pushes sent, or -1 on error
 */
int webpush_notify_user(const char *account_name, const char *message);

#endif /* WEBPUSH_H */
