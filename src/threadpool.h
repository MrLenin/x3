/* threadpool.h - Thread pool for offloading CPU-intensive work
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

#ifndef THREADPOOL_H
#define THREADPOOL_H

#include "config.h"

#ifdef HAVE_PTHREAD_H

#include <pthread.h>
#include <time.h>

/* Task priority levels */
typedef enum {
    TP_PRIORITY_LOW = 0,
    TP_PRIORITY_NORMAL = 1,
    TP_PRIORITY_HIGH = 2,
    TP_PRIORITY_CRITICAL = 3,
    TP_PRIORITY_COUNT
} tp_priority_t;

/* Task state */
typedef enum {
    TP_STATE_PENDING,
    TP_STATE_RUNNING,
    TP_STATE_COMPLETED,
    TP_STATE_CANCELLED,
    TP_STATE_FAILED
} tp_state_t;

/* Task function signatures */
typedef void *(*tp_work_func)(void *arg);
typedef void (*tp_callback_func)(void *result, void *user_data, tp_state_t state);

/* Task handle (opaque to callers) */
typedef struct tp_task tp_task_t;

/* Task descriptor */
struct tp_task {
    tp_work_func work;              /* Function to execute in worker */
    tp_callback_func callback;       /* Called in main thread when done */
    void *arg;                       /* Argument to work function */
    void *user_data;                 /* Passed to callback */
    void *result;                    /* Result from work function */
    tp_state_t state;                /* Current state */
    tp_priority_t priority;          /* Scheduling priority */
    unsigned long task_id;           /* Unique task ID for tracking */
    time_t submit_time;              /* When task was submitted */
    time_t start_time;               /* When worker started */
    time_t complete_time;            /* When worker finished */
    struct tp_task *next;            /* Queue linkage */
};

/* Thread pool configuration */
struct tp_config {
    unsigned int min_threads;        /* Minimum worker threads (default: 2) */
    unsigned int max_threads;        /* Maximum worker threads (default: 4) */
    unsigned int queue_size;         /* Max pending tasks (default: 1000) */
    unsigned int idle_timeout_sec;   /* Shrink idle threads after sec (default: 60) */
    const char *name;                /* Pool name for logging */
};

/* Thread pool statistics */
struct tp_stats {
    unsigned long tasks_submitted;
    unsigned long tasks_completed;
    unsigned long tasks_cancelled;
    unsigned long tasks_failed;
    unsigned long total_wait_time_ms;
    unsigned long total_exec_time_ms;
    unsigned int active_threads;
    unsigned int idle_threads;
    unsigned int queue_depth;
    unsigned int queue_high_water;
};

/**
 * Initialize thread pool with configuration
 * @return 0 on success, -1 on failure
 */
int threadpool_init(const struct tp_config *config);

/**
 * Shutdown thread pool, cancelling pending tasks
 * @param wait_ms Max time to wait for running tasks (0 = don't wait)
 */
void threadpool_shutdown(unsigned int wait_ms);

/**
 * Check if thread pool is initialized
 */
int threadpool_is_initialized(void);

/**
 * Submit a task to the thread pool
 * @param work Function to execute in worker thread
 * @param arg Argument passed to work function
 * @param callback Function called in main thread when done (can be NULL)
 * @param user_data Passed to callback
 * @param priority Task priority
 * @return Task handle, or NULL on failure
 */
tp_task_t *threadpool_submit(tp_work_func work, void *arg,
                              tp_callback_func callback, void *user_data,
                              tp_priority_t priority);

/**
 * Cancel a pending task (no-op if already running)
 * @return 1 if cancelled, 0 if already running/complete
 */
int threadpool_cancel(tp_task_t *task);

/**
 * Check task state
 */
tp_state_t threadpool_task_state(tp_task_t *task);

/**
 * Process completed task callbacks (call from main event loop)
 * @param max_callbacks Max callbacks to process (0 = all)
 * @return Number of callbacks processed
 */
int threadpool_process_callbacks(unsigned int max_callbacks);

/**
 * Get file descriptor for completion notification
 * (for integration with select/epoll)
 * @return FD to monitor for readability, or -1 if not available
 */
int threadpool_get_notify_fd(void);

/**
 * Get statistics
 */
void threadpool_get_stats(struct tp_stats *stats);

/**
 * Convenience function: submit and forget (no callback)
 */
static inline tp_task_t *
threadpool_submit_simple(tp_work_func work, void *arg)
{
    return threadpool_submit(work, arg, NULL, NULL, TP_PRIORITY_NORMAL);
}

#else /* !HAVE_PTHREAD_H */

/* Stub definitions when pthreads not available */
typedef enum { TP_PRIORITY_LOW, TP_PRIORITY_NORMAL, TP_PRIORITY_HIGH, TP_PRIORITY_CRITICAL, TP_PRIORITY_COUNT } tp_priority_t;
typedef enum { TP_STATE_PENDING, TP_STATE_RUNNING, TP_STATE_COMPLETED, TP_STATE_CANCELLED, TP_STATE_FAILED } tp_state_t;
typedef void *(*tp_work_func)(void *arg);
typedef void (*tp_callback_func)(void *result, void *user_data, tp_state_t state);
typedef struct tp_task tp_task_t;
struct tp_config { unsigned int min_threads, max_threads, queue_size, idle_timeout_sec; const char *name; };
struct tp_stats { unsigned long tasks_submitted, tasks_completed, tasks_cancelled, tasks_failed, total_wait_time_ms, total_exec_time_ms; unsigned int active_threads, idle_threads, queue_depth, queue_high_water; };

#define threadpool_init(c) (0)
#define threadpool_shutdown(w) do {} while(0)
#define threadpool_is_initialized() (0)
#define threadpool_submit(w,a,c,u,p) (NULL)
#define threadpool_cancel(t) (0)
#define threadpool_task_state(t) (TP_STATE_FAILED)
#define threadpool_process_callbacks(m) (0)
#define threadpool_get_notify_fd() (-1)
#define threadpool_get_stats(s) do { memset(s, 0, sizeof(struct tp_stats)); } while(0)
#define threadpool_submit_simple(w,a) (NULL)

#endif /* HAVE_PTHREAD_H */

#endif /* THREADPOOL_H */
