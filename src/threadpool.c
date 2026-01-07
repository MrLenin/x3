/* threadpool.c - Thread pool implementation
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

#include "config.h"

#ifdef HAVE_PTHREAD_H

#include "common.h"
#include "threadpool.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

/* Try to use eventfd for notification, fall back to pipe */
#ifdef __linux__
#include <sys/eventfd.h>
#define USE_EVENTFD 1
#else
#define USE_EVENTFD 0
#endif

/* Worker thread info */
struct worker {
    pthread_t thread;
    unsigned int id;
    int running;
    time_t idle_since;
};

/* Thread pool state */
static struct {
    /* Configuration */
    struct tp_config config;

    /* Workers */
    struct worker *workers;
    unsigned int num_workers;
    unsigned int active_workers;

    /* Task queues (one per priority level) */
    struct tp_task *queues[TP_PRIORITY_COUNT];
    struct tp_task *queue_tails[TP_PRIORITY_COUNT];
    unsigned int queue_depths[TP_PRIORITY_COUNT];
    unsigned int total_queued;

    /* Completed tasks (for callback processing) */
    struct tp_task *completed_head;
    struct tp_task *completed_tail;
    unsigned int completed_count;

    /* Synchronization */
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_cond;
    pthread_mutex_t completed_lock;

    /* Notification FD for main thread */
#if USE_EVENTFD
    int notify_fd;
#else
    int notify_pipe[2];
#endif

    /* Statistics */
    struct tp_stats stats;

    /* State */
    int initialized;
    int shutting_down;
    unsigned long next_task_id;

} pool = {
    .initialized = 0,
    .shutting_down = 0,
#if USE_EVENTFD
    .notify_fd = -1,
#else
    .notify_pipe = {-1, -1},
#endif
};

static struct log_type *TP_LOG;

/* Forward declarations */
static void *worker_thread(void *arg);
static void notify_main_thread(void);
static void clear_notification(void);

int
threadpool_init(const struct tp_config *config)
{
    unsigned int i;
    int rc;

    if (pool.initialized)
        return 0;

    TP_LOG = log_register_type("threadpool", "file:threadpool.log");

    /* Apply configuration with defaults */
    pool.config.name = config && config->name ? config->name : "default";
    pool.config.min_threads = config && config->min_threads > 0 ? config->min_threads : 2;
    pool.config.max_threads = config && config->max_threads > 0 ? config->max_threads : 4;
    pool.config.queue_size = config && config->queue_size > 0 ? config->queue_size : 1000;
    pool.config.idle_timeout_sec = config && config->idle_timeout_sec > 0 ? config->idle_timeout_sec : 60;

    if (pool.config.min_threads > pool.config.max_threads)
        pool.config.min_threads = pool.config.max_threads;

    /* Initialize synchronization primitives */
    if ((rc = pthread_mutex_init(&pool.queue_lock, NULL)) != 0) {
        log_module(TP_LOG, LOG_ERROR, "Failed to init queue mutex: %s", strerror(rc));
        return -1;
    }

    if ((rc = pthread_cond_init(&pool.queue_cond, NULL)) != 0) {
        log_module(TP_LOG, LOG_ERROR, "Failed to init queue cond: %s", strerror(rc));
        pthread_mutex_destroy(&pool.queue_lock);
        return -1;
    }

    if ((rc = pthread_mutex_init(&pool.completed_lock, NULL)) != 0) {
        log_module(TP_LOG, LOG_ERROR, "Failed to init completed mutex: %s", strerror(rc));
        pthread_cond_destroy(&pool.queue_cond);
        pthread_mutex_destroy(&pool.queue_lock);
        return -1;
    }

    /* Create notification mechanism */
#if USE_EVENTFD
    pool.notify_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (pool.notify_fd < 0) {
        log_module(TP_LOG, LOG_ERROR, "Failed to create eventfd: %s", strerror(errno));
        goto fail_sync;
    }
#else
    if (pipe(pool.notify_pipe) < 0) {
        log_module(TP_LOG, LOG_ERROR, "Failed to create notification pipe: %s", strerror(errno));
        goto fail_sync;
    }
    /* Make non-blocking */
    fcntl(pool.notify_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(pool.notify_pipe[1], F_SETFL, O_NONBLOCK);
#endif

    /* Initialize queues */
    for (i = 0; i < TP_PRIORITY_COUNT; i++) {
        pool.queues[i] = NULL;
        pool.queue_tails[i] = NULL;
        pool.queue_depths[i] = 0;
    }
    pool.total_queued = 0;
    pool.completed_head = NULL;
    pool.completed_tail = NULL;
    pool.completed_count = 0;

    /* Allocate worker array */
    pool.workers = calloc(pool.config.max_threads, sizeof(struct worker));
    if (!pool.workers) {
        log_module(TP_LOG, LOG_ERROR, "Failed to allocate worker array");
        goto fail_notify;
    }

    /* Initialize statistics */
    memset(&pool.stats, 0, sizeof(pool.stats));

    pool.initialized = 1;
    pool.shutting_down = 0;
    pool.next_task_id = 1;

    /* Start minimum number of worker threads */
    pool.num_workers = 0;
    for (i = 0; i < pool.config.min_threads; i++) {
        pool.workers[i].id = i;
        pool.workers[i].running = 1;
        pool.workers[i].idle_since = 0;

        rc = pthread_create(&pool.workers[i].thread, NULL, worker_thread, &pool.workers[i]);
        if (rc != 0) {
            log_module(TP_LOG, LOG_ERROR, "Failed to create worker thread %u: %s", i, strerror(rc));
            pool.workers[i].running = 0;
            /* Continue with fewer threads */
        } else {
            pool.num_workers++;
        }
    }

    if (pool.num_workers == 0) {
        log_module(TP_LOG, LOG_ERROR, "Failed to create any worker threads");
        goto fail_workers;
    }

    log_module(TP_LOG, LOG_INFO, "Thread pool '%s' initialized with %u workers (min=%u, max=%u)",
               pool.config.name, pool.num_workers, pool.config.min_threads, pool.config.max_threads);

    return 0;

fail_workers:
    free(pool.workers);
    pool.workers = NULL;
fail_notify:
#if USE_EVENTFD
    if (pool.notify_fd >= 0) {
        close(pool.notify_fd);
        pool.notify_fd = -1;
    }
#else
    if (pool.notify_pipe[0] >= 0) {
        close(pool.notify_pipe[0]);
        close(pool.notify_pipe[1]);
        pool.notify_pipe[0] = pool.notify_pipe[1] = -1;
    }
#endif
fail_sync:
    pthread_mutex_destroy(&pool.completed_lock);
    pthread_cond_destroy(&pool.queue_cond);
    pthread_mutex_destroy(&pool.queue_lock);
    return -1;
}

void
threadpool_shutdown(unsigned int wait_ms)
{
    unsigned int i;
    struct tp_task *task, *next;

    if (!pool.initialized)
        return;

    log_module(TP_LOG, LOG_INFO, "Shutting down thread pool '%s'", pool.config.name);

    /* Signal shutdown */
    pthread_mutex_lock(&pool.queue_lock);
    pool.shutting_down = 1;
    pthread_cond_broadcast(&pool.queue_cond);
    pthread_mutex_unlock(&pool.queue_lock);

    /* Wait for workers to finish (portable implementation) */

    for (i = 0; i < pool.config.max_threads; i++) {
        if (pool.workers[i].running) {
            if (wait_ms > 0) {
                /* Poll with usleep for portability instead of pthread_timedjoin_np */
                unsigned int waited = 0;
                while (pool.workers[i].running && waited < wait_ms) {
                    usleep(10000); /* 10ms */
                    waited += 10;
                }
            }
            /* Workers should have exited due to shutting_down flag, just join */
            pthread_join(pool.workers[i].thread, NULL);
        }
    }

    /* Free pending tasks */
    pthread_mutex_lock(&pool.queue_lock);
    for (i = 0; i < TP_PRIORITY_COUNT; i++) {
        for (task = pool.queues[i]; task; task = next) {
            next = task->next;
            pool.stats.tasks_cancelled++;
            free(task);
        }
        pool.queues[i] = NULL;
        pool.queue_tails[i] = NULL;
    }
    pool.total_queued = 0;
    pthread_mutex_unlock(&pool.queue_lock);

    /* Free completed tasks */
    pthread_mutex_lock(&pool.completed_lock);
    for (task = pool.completed_head; task; task = next) {
        next = task->next;
        free(task);
    }
    pool.completed_head = NULL;
    pool.completed_tail = NULL;
    pool.completed_count = 0;
    pthread_mutex_unlock(&pool.completed_lock);

    /* Cleanup */
    free(pool.workers);
    pool.workers = NULL;

#if USE_EVENTFD
    if (pool.notify_fd >= 0) {
        close(pool.notify_fd);
        pool.notify_fd = -1;
    }
#else
    if (pool.notify_pipe[0] >= 0) {
        close(pool.notify_pipe[0]);
        close(pool.notify_pipe[1]);
        pool.notify_pipe[0] = pool.notify_pipe[1] = -1;
    }
#endif

    pthread_mutex_destroy(&pool.completed_lock);
    pthread_cond_destroy(&pool.queue_cond);
    pthread_mutex_destroy(&pool.queue_lock);

    pool.initialized = 0;

    log_module(TP_LOG, LOG_INFO, "Thread pool shutdown complete. Stats: submitted=%lu, completed=%lu, cancelled=%lu",
               pool.stats.tasks_submitted, pool.stats.tasks_completed, pool.stats.tasks_cancelled);
}

int
threadpool_is_initialized(void)
{
    return pool.initialized;
}

tp_task_t *
threadpool_submit(tp_work_func work, void *arg, tp_callback_func callback,
                  void *user_data, tp_priority_t priority)
{
    tp_task_t *task;

    if (!pool.initialized || pool.shutting_down || !work)
        return NULL;

    if (priority >= TP_PRIORITY_COUNT)
        priority = TP_PRIORITY_NORMAL;

    /* Check queue size limit */
    pthread_mutex_lock(&pool.queue_lock);
    if (pool.total_queued >= pool.config.queue_size) {
        pthread_mutex_unlock(&pool.queue_lock);
        log_module(TP_LOG, LOG_WARNING, "Thread pool queue full (%u tasks)", pool.total_queued);
        return NULL;
    }
    pthread_mutex_unlock(&pool.queue_lock);

    /* Allocate task */
    task = calloc(1, sizeof(*task));
    if (!task)
        return NULL;

    task->work = work;
    task->arg = arg;
    task->callback = callback;
    task->user_data = user_data;
    task->priority = priority;
    task->state = TP_STATE_PENDING;
    task->submit_time = time(NULL);
    task->next = NULL;

    /* Enqueue */
    pthread_mutex_lock(&pool.queue_lock);

    task->task_id = pool.next_task_id++;

    /* Add to tail of priority queue */
    if (pool.queue_tails[priority]) {
        pool.queue_tails[priority]->next = task;
    } else {
        pool.queues[priority] = task;
    }
    pool.queue_tails[priority] = task;
    pool.queue_depths[priority]++;
    pool.total_queued++;
    pool.stats.tasks_submitted++;

    /* Update high water mark */
    if (pool.total_queued > pool.stats.queue_high_water)
        pool.stats.queue_high_water = pool.total_queued;

    /* Wake a worker */
    pthread_cond_signal(&pool.queue_cond);

    pthread_mutex_unlock(&pool.queue_lock);

    return task;
}

int
threadpool_cancel(tp_task_t *task)
{
    tp_task_t *t, *prev;
    int i;

    if (!task || !pool.initialized)
        return 0;

    pthread_mutex_lock(&pool.queue_lock);

    /* Can only cancel pending tasks */
    if (task->state != TP_STATE_PENDING) {
        pthread_mutex_unlock(&pool.queue_lock);
        return 0;
    }

    /* Find and remove from queue */
    for (i = 0; i < TP_PRIORITY_COUNT; i++) {
        prev = NULL;
        for (t = pool.queues[i]; t; prev = t, t = t->next) {
            if (t == task) {
                /* Remove from queue */
                if (prev) {
                    prev->next = task->next;
                } else {
                    pool.queues[i] = task->next;
                }
                if (pool.queue_tails[i] == task) {
                    pool.queue_tails[i] = prev;
                }
                pool.queue_depths[i]--;
                pool.total_queued--;
                task->state = TP_STATE_CANCELLED;
                pool.stats.tasks_cancelled++;

                pthread_mutex_unlock(&pool.queue_lock);

                /* Call callback if provided */
                if (task->callback) {
                    task->callback(NULL, task->user_data, TP_STATE_CANCELLED);
                }

                free(task);
                return 1;
            }
        }
    }

    pthread_mutex_unlock(&pool.queue_lock);
    return 0;
}

tp_state_t
threadpool_task_state(tp_task_t *task)
{
    if (!task)
        return TP_STATE_FAILED;
    return task->state;
}

int
threadpool_process_callbacks(unsigned int max_callbacks)
{
    tp_task_t *task;
    unsigned int processed = 0;

    if (!pool.initialized)
        return 0;

    /* Clear notification */
    clear_notification();

    while (1) {
        pthread_mutex_lock(&pool.completed_lock);

        if (!pool.completed_head || (max_callbacks > 0 && processed >= max_callbacks)) {
            pthread_mutex_unlock(&pool.completed_lock);
            break;
        }

        /* Pop from completed queue */
        task = pool.completed_head;
        pool.completed_head = task->next;
        if (!pool.completed_head)
            pool.completed_tail = NULL;
        pool.completed_count--;

        pthread_mutex_unlock(&pool.completed_lock);

        /* Invoke callback */
        if (task->callback) {
            task->callback(task->result, task->user_data, task->state);
        }

        free(task);
        processed++;
    }

    return processed;
}

int
threadpool_get_notify_fd(void)
{
#if USE_EVENTFD
    return pool.notify_fd;
#else
    return pool.notify_pipe[0];
#endif
}

void
threadpool_get_stats(struct tp_stats *stats)
{
    if (!stats)
        return;

    pthread_mutex_lock(&pool.queue_lock);
    stats->tasks_submitted = pool.stats.tasks_submitted;
    stats->tasks_completed = pool.stats.tasks_completed;
    stats->tasks_cancelled = pool.stats.tasks_cancelled;
    stats->tasks_failed = pool.stats.tasks_failed;
    stats->total_wait_time_ms = pool.stats.total_wait_time_ms;
    stats->total_exec_time_ms = pool.stats.total_exec_time_ms;
    stats->queue_depth = pool.total_queued;
    stats->queue_high_water = pool.stats.queue_high_water;
    stats->active_threads = pool.active_workers;
    stats->idle_threads = pool.num_workers - pool.active_workers;
    pthread_mutex_unlock(&pool.queue_lock);
}

/* Worker thread function */
static void *
worker_thread(void *arg)
{
    struct worker *worker = arg;
    tp_task_t *task;
    int i;
    struct timeval start, end;
    long wait_ms, exec_ms;

    log_module(TP_LOG, LOG_DEBUG, "Worker %u started", worker->id);

    while (1) {
        pthread_mutex_lock(&pool.queue_lock);

        /* Wait for work */
        while (!pool.shutting_down && pool.total_queued == 0) {
            worker->idle_since = time(NULL);
            pthread_cond_wait(&pool.queue_cond, &pool.queue_lock);
        }

        if (pool.shutting_down) {
            pthread_mutex_unlock(&pool.queue_lock);
            break;
        }

        /* Find highest priority task */
        task = NULL;
        for (i = TP_PRIORITY_COUNT - 1; i >= 0; i--) {
            if (pool.queues[i]) {
                task = pool.queues[i];
                pool.queues[i] = task->next;
                if (!pool.queues[i])
                    pool.queue_tails[i] = NULL;
                pool.queue_depths[i]--;
                pool.total_queued--;
                break;
            }
        }

        if (!task) {
            pthread_mutex_unlock(&pool.queue_lock);
            continue;
        }

        /* Calculate wait time */
        gettimeofday(&start, NULL);
        wait_ms = (start.tv_sec - task->submit_time) * 1000;
        pool.stats.total_wait_time_ms += wait_ms;

        task->state = TP_STATE_RUNNING;
        task->start_time = start.tv_sec;
        pool.active_workers++;

        pthread_mutex_unlock(&pool.queue_lock);

        /* Execute task */
        task->result = task->work(task->arg);

        gettimeofday(&end, NULL);
        exec_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;

        pthread_mutex_lock(&pool.queue_lock);
        pool.active_workers--;
        pool.stats.total_exec_time_ms += exec_ms;

        if (task->result || task->callback) {
            task->state = TP_STATE_COMPLETED;
            pool.stats.tasks_completed++;
        } else {
            task->state = TP_STATE_FAILED;
            pool.stats.tasks_failed++;
        }
        task->complete_time = end.tv_sec;
        pthread_mutex_unlock(&pool.queue_lock);

        /* Add to completed queue if callback needed */
        if (task->callback) {
            pthread_mutex_lock(&pool.completed_lock);
            task->next = NULL;
            if (pool.completed_tail) {
                pool.completed_tail->next = task;
            } else {
                pool.completed_head = task;
            }
            pool.completed_tail = task;
            pool.completed_count++;
            pthread_mutex_unlock(&pool.completed_lock);

            /* Notify main thread */
            notify_main_thread();
        } else {
            free(task);
        }
    }

    worker->running = 0;
    log_module(TP_LOG, LOG_DEBUG, "Worker %u exiting", worker->id);
    return NULL;
}

static void
notify_main_thread(void)
{
#if USE_EVENTFD
    uint64_t val = 1;
    write(pool.notify_fd, &val, sizeof(val));
#else
    char c = 1;
    write(pool.notify_pipe[1], &c, 1);
#endif
}

static void
clear_notification(void)
{
#if USE_EVENTFD
    uint64_t val;
    read(pool.notify_fd, &val, sizeof(val));
#else
    char buf[16];
    while (read(pool.notify_pipe[0], buf, sizeof(buf)) > 0)
        ;
#endif
}

#endif /* HAVE_PTHREAD_H */
