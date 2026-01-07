extern FILE *replay_file;

#include "mempool.h"
#include "threadpool.h"

time_t boot_time;
time_t burst_begin;
time_t now;
time_t burst_length;
struct log_type *MAIN_LOG;

int quit_services;
int max_cycles;

char *services_config = "x3.conf";

char **services_argv;
int services_argc;

struct cManagerNode cManager;

/* Non-blocking reconnect support */
int reconnect_pending = 0;
int uplink_connect(void);  /* Forward declaration for callback */
static void uplink_reconnect_callback(void *data);  /* Forward declaration */

struct policer_params *oper_policer_params, *luser_policer_params, *god_policer_params;

static const struct message_entry msgtab[] = {
    { "MSG_NONE", "None" },
    { "MSG_ON", "On" },
    { "MSG_OFF", "Off" },
    { "MSG_NEVER", "Never" },
    { "MSG_SERVICE_IMMUNE", "$b%s$b may not be kicked, killed, banned, or deopped." },
    { "MSG_SERVICE_PRIVILEGED", "$b%s$b is a privileged service." },
    { "MSG_NOT_A_SERVICE", "$b%s$b is not a service bot." },
    { "MSG_COMMAND_UNKNOWN", "$b%s$b is an unknown command." },
    { "MSG_COMMAND_PRIVILEGED", "$b%s$b is a privileged command." },
    { "MSG_COMMAND_DISABLED", "$b%s$b is a disabled command." },
    { "MSG_SETTING_PRIVILEGED", "$b%s$b is a privileged setting." },
    { "MSG_AUTHENTICATE", "You must first authenticate with $b$N$b." },
    { "MSG_USER_AUTHENTICATE", "%s must first authenticate with $b$N$b." },
    { "MSG_SET_EMAIL_ADDR", "You must first set your account's email address.  (Contact network staff if you cannot auth to your account.)" },
    { "MSG_HANDLE_UNKNOWN", "Account $b%s$b has not been registered." },
    { "MSG_NICK_UNKNOWN", "User with nick $b%s$b does not exist." },
    { "MSG_CHANNEL_UNKNOWN", "Channel with name $b%s$b does not exist." },
    { "MSG_SERVER_UNKNOWN", "Server with name $b%s$b does not exist or is not linked." },
    { "MSG_MODULE_UNKNOWN", "No module has been registered with name $b%s$b." },
    { "MSG_INVALID_MODES", "$b%s$b is an invalid set of channel modes." },
    { "MSG_INVALID_GLINE", "Invalid G-line '%s'." },
    { "MSG_INVALID_DURATION", "Invalid time span '%s'." },
    { "MSG_NOT_TARGET_NAME", "You must provide the name of a channel or user." },
    { "MSG_NOT_CHANNEL_NAME", "The channel name you specified is not a valid channel name." },
    { "MSG_INVALID_CHANNEL", "The channel name you specified does not exist." },
    { "MSG_CHANNEL_ABSENT", "You aren't currently in $b%s$b." },
    { "MSG_CHANNEL_USER_ABSENT", "$b%s$b isn't currently in $b%s$b." },
    { "MSG_MISSING_PARAMS", "$b%s$b requires more parameters." },
    { "MSG_DEPRECATED_COMMAND", "The $b%s$b command has been deprecated, and will be removed in the future; please use $b%s$b instead." },
    { "MSG_OPER_SUSPENDED", "Your $b$O$b access has been suspended." },
    { "MSG_USER_OUTRANKED", "$b%s$b outranks you (command has no effect)." },
    { "MSG_STUPID_ACCESS_CHANGE", "Please ask someone $belse$b to demote you." },
    { "MSG_NO_SEARCH_ACCESS", "You do not have enough access to search based on $b%s$b." },
    { "MSG_INVALID_CRITERIA", "$b%s$b is an invalid search criteria." },
    { "MSG_MATCH_COUNT", "Found $b%u$b matches." },
    { "MSG_NO_MATCHES", "Nothing matched the criteria of your search." },
    { "MSG_TOPIC_UNKNOWN", "No help on that topic." },
    { "MSG_INVALID_BINARY", "$b%s$b is an invalid binary value." },
    { "MSG_INTERNAL_FAILURE", "Your command could not be processed due to an internal failure." },
    { "MSG_DB_UNKNOWN", "I do not know of a database named %s." },
    { "MSG_DB_IS_MONDO", "Database %s is in the \"mondo\" database and cannot be written separately." },
    { "MSG_DB_WRITE_ERROR", "Error while writing database %s." },
    { "MSG_DB_WROTE_DB", "Wrote database %s (in %lu.%06lu seconds)." },
    { "MSG_DB_WROTE_ALL", "Wrote all databases (in %lu.%06lu seconds)." },
    { "MSG_AND", "," },
    { "MSG_0_SECONDS", "0 seconds" },
    { "MSG_YEAR", "y" },
    { "MSG_YEARS", "y" },
    { "MSG_WEEK", "w" },
    { "MSG_WEEKS", "w" },
    { "MSG_DAY", "d" },
    { "MSG_DAYS", "d" },
    { "MSG_HOUR", "h" },
    { "MSG_HOURS", "h" },
    { "MSG_MINUTE", "m" },
    { "MSG_MINUTES", "m" },
    { "MSG_SECOND", "s" },
    { "MSG_SECONDS", "s" },
    { "MSG_BAR", "----------------------------------------" },
    { "MSG_INVALID_SHUN", "Invalid Shun '%s'." },
    { "MSG_MATCH_COUNT", "-----------Found $b%3u$b Matches------------" },
    { NULL, NULL }
};

int uplink_select(char *name);

static int
uplink_insert(const char *key, void *data, UNUSED_ARG(void *extra))
{
    struct uplinkNode *uplink = malloc(sizeof(struct uplinkNode));
    struct record_data *rd = data;
    struct addrinfo hints, *ai;
    int enabled = 1;
    char *str;

    if(!uplink)
    {
        return 0;
    }

    uplink->name = (char *)key;
    uplink->host = database_get_data(rd->d.object, "address", RECDB_QSTRING);

    str = database_get_data(rd->d.object, "port", RECDB_QSTRING);
    uplink->port = str ? atoi(str) : 6667;
    uplink->password = database_get_data(rd->d.object, "password", RECDB_QSTRING);
    uplink->their_password = database_get_data(rd->d.object, "uplink_password", RECDB_QSTRING);

    str = database_get_data(rd->d.object, "enabled", RECDB_QSTRING);
    if(str)
    {
        enabled = atoi(str) ? 1 : 0;
    }

    cManager.enabled += enabled;

    str = database_get_data(rd->d.object, "max_tries", RECDB_QSTRING);
    uplink->max_tries = str ? atoi(str) : 3;
    uplink->flags = enabled ? 0 : UPLINK_UNAVAILABLE;
    uplink->state = DISCONNECTED;
    uplink->tries = 0;

    str = database_get_data(rd->d.object, "bind_address", RECDB_QSTRING);
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    if (!getaddrinfo(str, NULL, &hints, &ai))
    {
        uplink->bind_addr_len = ai->ai_addrlen;
        uplink->bind_addr = calloc(1, ai->ai_addrlen);
        memcpy(uplink->bind_addr, ai->ai_addr, ai->ai_addrlen);
        freeaddrinfo(ai);
    }
    else
    {
        uplink->bind_addr = NULL;
        uplink->bind_addr_len = 0;
    }

    /* SSL/TLS configuration */
    str = database_get_data(rd->d.object, "ssl", RECDB_QSTRING);
    uplink->ssl = str ? atoi(str) : 0;
    uplink->ssl_cert = database_get_data(rd->d.object, "ssl_cert", RECDB_QSTRING);
    uplink->ssl_key = database_get_data(rd->d.object, "ssl_key", RECDB_QSTRING);
    uplink->ssl_ca = database_get_data(rd->d.object, "ssl_ca", RECDB_QSTRING);
    str = database_get_data(rd->d.object, "ssl_verify", RECDB_QSTRING);
    uplink->ssl_verify = str ? atoi(str) : 0;
    uplink->ssl_fingerprint = database_get_data(rd->d.object, "ssl_fingerprint", RECDB_QSTRING);

    uplink->next = cManager.uplinks;
    uplink->prev = NULL;

    if(cManager.uplinks)
    {
        cManager.uplinks->prev = uplink;
    }

    cManager.uplinks = uplink;

    /* If the configuration is being reloaded, set the current uplink
       to the reloaded equivalent, if possible. */
    if(cManager.uplink
       && enabled
       && !irccasecmp(uplink->host, cManager.uplink->host)
       && uplink->port == cManager.uplink->port)
    {
        uplink->state = cManager.uplink->state;
        uplink->tries = cManager.uplink->tries;
        cManager.uplink = uplink;
    }

    return 0;
}

static void
uplink_compile(void)
{
    const char *cycles;
    dict_t conf_node;
    struct uplinkNode *oldUplinks = NULL, *oldUplink = NULL;

    /* Save the old uplinks, we'll remove them later. */
    oldUplink = cManager.uplink;
    oldUplinks = cManager.uplinks;

    cycles = conf_get_data("server/max_cycles", RECDB_QSTRING);
    max_cycles = cycles ? atoi(cycles) : 30;
    if(!(conf_node = conf_get_data("uplinks", RECDB_OBJECT)))
    {
        log_module(MAIN_LOG, LOG_FATAL, "No uplinks configured; giving up.");
        exit(1);
    }

    cManager.enabled = 0;
    dict_foreach(conf_node, uplink_insert, NULL);

    /* Remove the old uplinks, if any. It doesn't matter if oldUplink (below)
       is a reference to one of these, because it won't get dereferenced. */
    if(oldUplinks)
    {
        struct uplinkNode *uplink, *next;

        oldUplinks->prev->next = NULL;

        for(uplink = oldUplinks; uplink; uplink = next)
        {
            next = uplink->next;
            free(uplink->bind_addr);
            free(uplink);
        }
    }

    /* If the uplink hasn't changed, it's either NULL or pointing at
       an uplink that was just deleted, select a new one. */
    if(cManager.uplink == oldUplink)
    {
        int select_result;

        if(oldUplink)
        {
            irc_squit(self, "Uplinks updated; selecting new uplink.", NULL);
        }

        cManager.uplink = NULL;
        select_result = uplink_select(NULL);
        if (select_result < 0) {
            log_module(MAIN_LOG, LOG_FATAL, "No valid uplinks after config reload.");
            /* Don't exit here - let the normal flow handle it */
        } else if (select_result > 0) {
            /* Schedule reconnect after delay */
            reconnect_pending = 1;
            timeq_add(now + select_result, uplink_reconnect_callback, NULL);
        }
    }
}

struct uplinkNode *
uplink_find(char *name)
{
    struct uplinkNode *uplink;

    if(!cManager.enabled || !cManager.uplinks)
    {
        return NULL;
    }

    for(uplink = cManager.uplinks; uplink; uplink = uplink->next)
    {
        if(!strcasecmp(uplink->name, name))
        {
            return uplink;
        }
    }

    return NULL;
}

/**
 * Select an uplink to connect to.
 * @param name Specific uplink name to select, or NULL to auto-select
 * @return 0 on success (uplink selected), positive value = delay seconds needed, -1 on fatal error
 */
int
uplink_select(char *name)
{
    struct uplinkNode *start, *uplink, *next;
    int stop;

    if(!cManager.enabled || !cManager.uplinks)
    {
        log_module(MAIN_LOG, LOG_FATAL, "No uplinks enabled; giving up.");
        return -1;  /* Fatal - caller should exit */
    }

    if(!cManager.uplink)
    {
        start = cManager.uplinks;
    }
    else
    {
        start = cManager.uplink->next;
        if(!start)
        {
            start = cManager.uplinks;
        }
    }

    stop = 0;
    for(uplink = start; uplink; uplink = next)
    {
        next = uplink->next ? uplink->next : cManager.uplinks;

        if(stop)
        {
            uplink = NULL;
            break;
        }

        /* Skip bad uplinks first, before checking for wrap-around */
        if(uplink->flags & UPLINK_UNAVAILABLE)
        {
            continue;
        }

        /* We've wrapped around the list - all uplinks have been tried */
        if(next == start)
        {
            /* Check if current uplink is usable before declaring failure */
            if(!(uplink->flags & UPLINK_UNAVAILABLE) &&
               (!name || !irccasecmp(uplink->name, name)))
            {
                /* Current uplink is usable, select it */
                break;
            }

            /*
             * All uplinks tried - instead of blocking with sleep(), return delay.
             * Caller should schedule a retry via timeq.
             * Delay formula: (cycles >> 1) * 5 seconds, i.e. 0, 5, 10, 15, ...
             */
            time_t delay = (cManager.cycles >> 1) * 5;
            if (delay < 2) delay = 2;  /* Minimum 2 second delay */
            if (delay > 120) delay = 120;  /* Cap at 2 minutes */

            cManager.cycles++;

            if(max_cycles && (cManager.cycles >= max_cycles))
            {
                log_module(MAIN_LOG, LOG_ERROR, "Maximum uplink list cycles exceeded; giving up.");
                return -1;  /* Fatal */
            }

            log_module(MAIN_LOG, LOG_INFO,
                       "All uplinks tried, need to wait %ld seconds before retry (cycle %d).",
                       (long)delay, cManager.cycles);

            return (int)delay;  /* Caller should schedule retry */
        }

        if(name && irccasecmp(uplink->name, name))
        {
            /* If we were told to connect to a specific uplink, don't stop
               until we find it.
            */
            continue;
        }

        /* It would be possible to track uplink health through a variety
           of statistics and only break on the best uplink. For now, break
           on the first available one.
        */

        break;
    }

    if(!uplink)
    {
        /* We are shit outta luck if every single uplink has been passed
           over. Use the current uplink if possible. */
        if(!cManager.uplink || cManager.uplink->flags & UPLINK_UNAVAILABLE)
        {
            log_module(MAIN_LOG, LOG_ERROR, "All available uplinks exhausted; giving up.");
            return -1;  /* Fatal */
        }

        return 0;  /* Keep current uplink */
    }

    cManager.uplink = uplink;
    return 0;  /* Success */
}

/**
 * Callback for deferred uplink reconnection.
 * Called by timeq after the reconnect delay has elapsed.
 */
static void
uplink_reconnect_callback(UNUSED_ARG(void *data))
{
    reconnect_pending = 0;
    log_module(MAIN_LOG, LOG_DEBUG, "Reconnect timer fired, attempting connection.");
    uplink_connect();
}

int
uplink_connect(void)
{
    struct uplinkNode *uplink = cManager.uplink;
    int select_result;

    /* If a reconnect is already scheduled, don't duplicate */
    if(reconnect_pending)
    {
        return 0;
    }

    if(uplink->state != DISCONNECTED)
    {
        return 0;
    }

    if(uplink->flags & UPLINK_UNAVAILABLE)
    {
        select_result = uplink_select(NULL);
        if (select_result < 0) {
            /* Fatal error - all uplinks exhausted */
            exit(1);
        }
        if (select_result > 0) {
            /* Need to wait before retrying uplink list */
            log_module(MAIN_LOG, LOG_INFO,
                       "Scheduling uplink selection retry in %d seconds.",
                       select_result);
            reconnect_pending = 1;
            timeq_add(now + select_result, uplink_reconnect_callback, NULL);
            return 0;
        }
        uplink = cManager.uplink;
    }

    if(uplink->tries)
    {
        /*
         * Instead of blocking with sleep(), schedule a callback.
         * This allows the event loop to continue processing other events.
         * Delay scales with number of tries: 2s, 4s, 8s, ... capped at 60s.
         */
        time_t delay = 2 << (uplink->tries > 4 ? 4 : uplink->tries - 1);
        if (delay > 60) delay = 60;
        log_module(MAIN_LOG, LOG_INFO, "Scheduling reconnect in %ld seconds (attempt %d).",
                   (long)delay, uplink->tries + 1);
        reconnect_pending = 1;
        timeq_add(now + delay, uplink_reconnect_callback, NULL);
        return 0;
    }

    if(!create_socket_client(uplink))
    {
        if(uplink->max_tries && (uplink->tries >= uplink->max_tries))
        {
            /* This is a bad uplink, move on. */
            uplink->flags |= UPLINK_UNAVAILABLE;
            select_result = uplink_select(NULL);
            if (select_result < 0) {
                exit(1);
            }
            if (select_result > 0) {
                reconnect_pending = 1;
                timeq_add(now + select_result, uplink_reconnect_callback, NULL);
            }
        }

        return 0;
    }
    else
    {
        uplink->state = AUTHENTICATING;
        irc_introduce(uplink->password);
    }

    return 1;
}

void
received_ping(void)
{
    /* This function is called when a ping is received. Take it as
       a sign of link health and reset the connection manager
       information. */

    cManager.cycles = 0;
}

static exit_func_t *ef_list;
static void **ef_list_extra;
static unsigned int ef_size = 0, ef_used = 0;

void reg_exit_func(exit_func_t handler, void *extra)
{
    if (ef_used == ef_size) {
        if (ef_size) {
            ef_size <<= 1;
            ef_list = realloc(ef_list, ef_size*sizeof(exit_func_t));
            ef_list_extra = realloc(ef_list_extra, ef_size*sizeof(void*));
        } else {
            ef_size = 8;
            ef_list = malloc(ef_size*sizeof(exit_func_t));
            ef_list_extra = malloc(ef_size*sizeof(void*));
        }
    }
    ef_list[ef_used] = handler;
    ef_list_extra[ef_used++] = extra;
}

void call_exit_funcs(void)
{
    unsigned int n = ef_used;

    /* Call them in reverse order because we initialize logs, then
     * nickserv, then chanserv, etc., and they register their exit
     * funcs in that order, and there are some dependencies (for
     * example, ChanServ requires NickServ to not have cleaned up).
     */

    while (n > 0) {
        --n;
        ef_list[n](ef_list_extra[n]);
    }
    free(ef_list);
    free(ef_list_extra);
    ef_used = ef_size = 0;
}

int
set_policer_param(const char *param, void *data, void *extra)
{
    struct record_data *rd = data;
    const char *str = GET_RECORD_QSTRING(rd);
    if (str) {
        policer_params_set(extra, param, str);
    }
    return 0;
}

static void
conf_globals(void)
{
    const char *info;
    dict_t dict;

    /* Initialize SSL library early (needed for crypto operations like webpush) */
    x3_ssl_init();

#ifdef WITH_LMDB
    /* Initialize LMDB early so other modules can use it */
    init_x3_lmdb();
#endif

    info = conf_get_data("services/opserv/nick", RECDB_QSTRING);
    if (info && (info[0] == '.'))
        info = NULL;
    init_opserv(info);

    info = conf_get_data("services/global/nick", RECDB_QSTRING);
    if (info && (info[0] == '.'))
        info = NULL;
    init_global(info);

    info = conf_get_data("services/nickserv/nick", RECDB_QSTRING);
    if (info && (info[0] == '.'))
        info = NULL;
    init_nickserv(info);

    info = conf_get_data("services/chanserv/nick", RECDB_QSTRING);
    if (info && (info[0] == '.'))
        info = NULL;
    init_chanserv(info);

    god_policer_params = policer_params_new();
    if ((dict = conf_get_data("policers/commands-god", RECDB_OBJECT))) {
        dict_foreach(dict, set_policer_param, god_policer_params);
    } else {
        policer_params_set(god_policer_params, "size", "30");
        policer_params_set(god_policer_params, "drain-rate", "1");
    }
    oper_policer_params = policer_params_new();
    if ((dict = conf_get_data("policers/commands-oper", RECDB_OBJECT))) {
        dict_foreach(dict, set_policer_param, oper_policer_params);
    } else {
        policer_params_set(oper_policer_params, "size", "10");
        policer_params_set(oper_policer_params, "drain-rate", "1");
    }
    luser_policer_params = policer_params_new();
    if ((dict = conf_get_data("policers/commands-luser", RECDB_OBJECT))) {
        dict_foreach(dict, set_policer_param, luser_policer_params);
    } else {
        policer_params_set(luser_policer_params, "size", "5");
        policer_params_set(luser_policer_params, "drain-rate", "0.50");
    }

    info = conf_get_data("services/spamserv/nick", RECDB_QSTRING);
    if (info && (info[0] == '.'))
        info = NULL;
    init_spamserv(info);
}

#ifdef HAVE_SYS_RESOURCE_H

static int
set_item_rlimit(const char *name, void *data, void *extra)
{
    long rsrc;
    int found;
    struct record_data *rd = data;
    struct rlimit rlim;
    const char *str;

    rsrc = (long)dict_find(extra, name, &found);
    if (!found) {
        log_module(MAIN_LOG, LOG_ERROR, "Invalid rlimit \"%s\" in rlimits section.", name);
        return 0;
    }
    if (!(str = GET_RECORD_QSTRING(rd))) {
        log_module(MAIN_LOG, LOG_ERROR, "Missing or invalid parameter type for rlimit \"%s\".", name);
        return 0;
    }
    if (getrlimit(rsrc, &rlim) < 0) {
        log_module(MAIN_LOG, LOG_ERROR, "Couldn't get rlimit \"%s\": errno %d: %s", name, errno, strerror(errno));
        return 0;
    }
    rlim.rlim_cur = ParseVolume(str);
    if (setrlimit(rsrc, &rlim) < 0) {
        log_module(MAIN_LOG, LOG_ERROR, "Couldn't set rlimit \"%s\": errno %d: %s", name, errno, strerror(errno));
    }
    return 0;
}

static void
conf_rlimits(void)
{
    dict_t dict, values;

    values = dict_new();
    dict_insert(values, "data", (void*)RLIMIT_DATA);
    dict_insert(values, "stack", (void*)RLIMIT_STACK);
#ifdef RLIMIT_VMEM
    dict_insert(values, "vmem", (void*)RLIMIT_VMEM);
#else
#ifdef RLIMIT_AS
    dict_insert(values, "vmem", (void*)RLIMIT_AS);
#endif
#endif
    if ((dict = conf_get_data("rlimits", RECDB_OBJECT))) {
        dict_foreach(dict, set_item_rlimit, values);
    }
    dict_delete(values);
}

#else

static void
conf_rlimits(void)
{
}

#endif

static void
usage(char *exe_name)
{
    /* We can assume we have getopt_long(). */
    printf("Usage: %s [-c config] [-r log] [-d] [-f] [-v|-h]\n"
           " -c, --config         selects a different configuration file.\n"
           " -d, --debug          enables debug mode.\n"
           " -f, --foreground     run X3 in the foreground.\n"
           " -h, --help           prints this usage message.\n"
           " -k, --check          checks the configuration file's syntax.\n"
           " -r, --replay         replay a log file (for debugging).\n"
           " -v, --version        prints this program's version.\n"
           , exe_name);
}

static void
version(void)
{
    printf("    --------------------------------------------------\n"
           "    - "PACKAGE_STRING", Built: " __DATE__ ", " __TIME__".\n"
           "    - Copyright (C) 2000 - 2005, srvx Development Team\n"
           "    - Copyright (C) 2004 - 2005, X3 Development Team\n"
           "    --------------------------------------------------\n");
}

static void
license(void)
{
    printf("\n"
           "This program is free software; you can redistribute it and/or modify\n"
           "it under the terms of the GNU General Public License as published by\n"
           "the Free Software Foundation; either version 3 of the License, or\n"
           "(at your option) any later version.\n"
           "\n"
           "This program is distributed in the hope that it will be useful,\n"
           "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
           "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
           "GNU General Public License for more details.\n"
           "\n"
           "You should have received a copy of the GNU General Public License\n"
           "along with this program; if not, write to the Free Software\n"
           "Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n\n");
}

static void main_shutdown(UNUSED_ARG(void *extra))
{
    struct uplinkNode *ul, *ul_next;

    /* Shutdown thread pool first (waits for running tasks) */
    threadpool_shutdown(5000);

    ioset_cleanup();
    for (ul = cManager.uplinks; ul; ul = ul_next) {
        ul_next = ul->next;
        free(ul->bind_addr);
        free(ul);
    }
    tools_cleanup();
    conf_close();
#if defined(PID_FILE)
    remove(PID_FILE);
#endif
    policer_params_delete(god_policer_params);
    policer_params_delete(oper_policer_params);
    policer_params_delete(luser_policer_params);
    if (replay_file)
        fclose(replay_file);

    /* Cleanup memory pools last (other modules may have used them) */
    mempool_cleanup_global();
}
