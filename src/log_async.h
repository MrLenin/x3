/*
 * log_async.h - Asynchronous logging subsystem
 * Copyright 2024 AfterNET Development Team
 *
 * Ring buffer + dedicated writer thread for non-blocking log writes.
 * Based on Nefarious ircd_log_async pattern.
 */

#ifndef LOG_ASYNC_H
#define LOG_ASYNC_H

#include "config.h"
#include <stddef.h>

/* Maximum size of a single log entry */
#define LOG_ASYNC_MAX_ENTRY 2048

/* Default ring buffer size (number of entries) */
#define LOG_ASYNC_BUFFER_SIZE_DEFAULT 4096

#ifdef HAVE_PTHREAD_H

/*
 * Initialize the async logging subsystem.
 * @param buffer_size Number of entries in ring buffer (0 for default)
 * @return 0 on success, -1 on failure
 */
int log_async_init(unsigned int buffer_size);

/*
 * Shutdown the async logging subsystem.
 * Flushes pending entries and waits for writer thread to exit.
 */
void log_async_shutdown(void);

/*
 * Write a log entry asynchronously.
 * @param fd File descriptor to write to (-1 to skip file write)
 * @param syslog_priority Syslog priority (0 to skip syslog)
 * @param message Pre-formatted message to write
 * @param len Length of message
 * @return 0 if queued, 1 if sync fallback used, -1 on error
 */
int log_async_write(int fd, int syslog_priority, const char *message, size_t len);

/*
 * Flush all pending log entries (blocking).
 */
void log_async_flush(void);

/*
 * Check if async logging is available and running.
 * @return 1 if available, 0 otherwise
 */
int log_async_available(void);

/*
 * Get async logging statistics.
 */
void log_async_stats(unsigned long *queued, unsigned long *written, unsigned long *dropped);

#else /* !HAVE_PTHREAD_H */

/* Stub implementations when pthread is not available */
#define log_async_init(s)           (0)
#define log_async_shutdown()        do {} while (0)
#define log_async_write(fd, p, m, l) (-1)
#define log_async_flush()           do {} while (0)
#define log_async_available()       (0)
#define log_async_stats(q, w, d)    do { if(q) *q=0; if(w) *w=0; if(d) *d=0; } while (0)

#endif /* HAVE_PTHREAD_H */

#endif /* LOG_ASYNC_H */
