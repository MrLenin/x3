/* mod-histserv.c - HistServ module for X3
 * Copyright 2026 Afternet Development Team
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
 *
 * You should have received a copy of the GNU General Public License
 * along with srvx; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

/*
 * HistServ provides PRIVMSG-based access to chat history for clients
 * that don't support the IRCv3 CHATHISTORY capability.
 *
 * Commands:
 *   LATEST <#channel> [count|duration]  - Get recent messages
 *   BEFORE <#channel> <time> [count]    - Messages before a time
 *   AFTER <#channel> <time> [count]     - Messages after a time
 *   AROUND <#channel> <time> [count]    - Messages around a time
 *   FETCH <#channel> <msgid>            - Retrieve specific message by msgid
 *
 * Time formats:
 *   - Duration: 5m, 1h, 30m, 2d (minutes, hours, days)
 *   - Unix epoch: 1704067200
 *   - Relative: -5m (5 minutes ago), -1h (1 hour ago)
 */

#include "chanserv.h"
#include "conf.h"
#include "modcmd.h"
#include "nickserv.h"
#include "proto.h"
#include "hash.h"

#include <ctype.h>

#define HISTSERV_CONF_NAME "modules/histserv"

static const struct message_entry msgtab[] = {
    { "HSMSG_NOT_IN_CHANNEL", "You must be in $b%s$b to view its history." },
    { "HSMSG_NO_SUCH_CHANNEL", "Channel $b%s$b does not exist." },
    { "HSMSG_NO_SUCH_NICK", "User $b%s$b is not online." },
    { "HSMSG_NO_HISTORY_FOUND", "No messages found matching your query." },
    { "HSMSG_FETCH_HEADER", "=== Message %s in %s ===" },
    { "HSMSG_FETCH_LINE", "<%s> %s" },
    { "HSMSG_FETCH_FOOTER", "=== End of message ===" },
    { "HSMSG_HISTORY_HEADER", "=== Chat history for %s ===" },
    { "HSMSG_DM_HISTORY_HEADER", "=== DM history with %s ===" },
    { "HSMSG_HISTORY_LINE", "[%s] <%s> %s" },
    { "HSMSG_HISTORY_FOOTER", "=== End of history (%d messages) ===" },
    { "HSMSG_INVALID_TIME", "$b%s$b is not a valid time format. Use: 5m, 1h, 2d, or unix timestamp." },
    { "HSMSG_REQUIRE_AUTH", "You must be authenticated to use this command." },
    { "HSMSG_DM_REQUIRE_AUTH", "You must be authenticated to view DM history." },
    { "HSMSG_DM_DISABLED", "DM history is not enabled on this server." },
    { NULL, NULL }
};

struct userNode *histserv;

#define HISTSERV_FUNC(NAME)         MODCMD_FUNC(NAME)
#define HISTSERV_SYNTAX()           svccmd_send_help_brief(user, histserv, cmd)
#define HISTSERV_MIN_PARAMS(N)      if(argc < (N)) {            \
                                     reply("MSG_MISSING_PARAMS", argv[0]); \
                                     HISTSERV_SYNTAX(); \
                                     return 0; }

const char *histserv_module_deps[] = { NULL };
static struct module *histserv_module;
static struct log_type *HS_LOG;

static struct {
    struct userNode *bot;
    int max_results;
    int default_results;
    int require_account;
    int require_channel_access;
    int dm_history_enabled;
    const char *timestamp_format;
} histserv_conf;

/* Query types for context */
enum histserv_query_type {
    QUERY_LATEST,
    QUERY_BEFORE,
    QUERY_AFTER,
    QUERY_AROUND,
    QUERY_FETCH
};

/* Pending query context for async callback */
struct histserv_query_ctx {
    struct userNode *user;
    char target[CHANNELLEN + 1];
    char ref[128];
    enum histserv_query_type type;
    int is_dm;  /* 1 if DM query, 0 if channel */
};

/* Parse duration string (5m, 1h, 2d) to seconds.
 * Returns 0 on parse failure. */
static time_t
parse_duration(const char *str)
{
    char *end;
    long val;
    time_t multiplier;

    if (!str || !*str)
        return 0;

    val = strtol(str, &end, 10);
    if (val <= 0 || end == str)
        return 0;

    switch (tolower((unsigned char)*end)) {
    case 's': multiplier = 1; break;
    case 'm': multiplier = 60; break;
    case 'h': multiplier = 3600; break;
    case 'd': multiplier = 86400; break;
    case 'w': multiplier = 604800; break;
    case '\0':
        /* No suffix - if large number, assume unix timestamp */
        if (val > 1000000000)
            return val;  /* Unix timestamp */
        return 0;  /* Ambiguous small number */
    default:
        return 0;
    }

    return val * multiplier;
}

/* Parse time argument to unix timestamp.
 * Accepts: duration (5m, 1h), unix timestamp, relative (-5m)
 * Returns 0 on failure. */
static time_t
parse_time_arg(const char *str)
{
    time_t duration;
    int relative = 0;

    if (!str || !*str)
        return 0;

    /* Check for relative prefix */
    if (*str == '-') {
        relative = 1;
        str++;
    }

    /* Try to parse as duration or timestamp */
    duration = parse_duration(str);
    if (duration == 0)
        return 0;

    /* If it looks like a full unix timestamp, return as-is */
    if (duration > 1000000000 && !relative)
        return duration;

    /* Otherwise it's a duration - convert to absolute time */
    return now - duration;
}

/* Format timestamp reference for CHATHISTORY query */
static void
format_timestamp_ref(char *buf, size_t buflen, time_t ts)
{
    snprintf(buf, buflen, "timestamp=%ld.000", (long)ts);
}

/* Extract nick from sender (nick!user@host format) */
static const char *
extract_nick(const char *sender)
{
    static char nick[NICKLEN + 1];
    const char *bang;

    bang = strchr(sender, '!');
    if (bang) {
        size_t len = bang - sender;
        if (len > NICKLEN)
            len = NICKLEN;
        strncpy(nick, sender, len);
        nick[len] = '\0';
    } else {
        strncpy(nick, sender, NICKLEN);
        nick[NICKLEN] = '\0';
    }
    return nick;
}

/* Format timestamp for display */
static const char *
format_timestamp(const char *ts_str)
{
    static char buf[32];
    time_t ts;
    struct tm *tm;
    char *dot;

    ts = (time_t)strtol(ts_str, NULL, 10);
    tm = localtime(&ts);

    /* Use configured format or default */
    if (histserv_conf.timestamp_format) {
        strftime(buf, sizeof(buf), histserv_conf.timestamp_format, tm);
    } else {
        strftime(buf, sizeof(buf), "%H:%M:%S", tm);
    }

    /* Remove fractional seconds from timestamp string if present */
    dot = strchr(buf, '.');
    if (dot)
        *dot = '\0';

    return buf;
}

/* Generic callback for history queries */
static void
histserv_history_callback(const char *reqid, const char *target,
                          struct chathistory_result *results, int count,
                          void *extra)
{
    struct histserv_query_ctx *ctx = extra;
    struct chathistory_result *r;
    const char *nick;
    const char *ts;

    (void)reqid;
    (void)target;

    if (!ctx || !ctx->user) {
        chathistory_result_free(results);
        free(ctx);
        return;
    }

    if (count == 0) {
        send_message(ctx->user, histserv, "HSMSG_NO_HISTORY_FOUND");
    } else {
        /* Use fetch-style headers for FETCH queries */
        if (ctx->type == QUERY_FETCH) {
            send_message(ctx->user, histserv, "HSMSG_FETCH_HEADER",
                         ctx->ref, ctx->target);

            for (r = results; r; r = r->next) {
                nick = extract_nick(r->sender);
                send_message(ctx->user, histserv, "HSMSG_FETCH_LINE",
                            nick, r->content);
            }

            send_message(ctx->user, histserv, "HSMSG_FETCH_FOOTER");
        } else {
            /* Use appropriate header for channel vs DM */
            send_message(ctx->user, histserv,
                         ctx->is_dm ? "HSMSG_DM_HISTORY_HEADER" : "HSMSG_HISTORY_HEADER",
                         ctx->target);

            for (r = results; r; r = r->next) {
                nick = extract_nick(r->sender);
                ts = format_timestamp(r->timestamp);
                send_message(ctx->user, histserv, "HSMSG_HISTORY_LINE",
                            ts, nick, r->content);
            }

            send_message(ctx->user, histserv, "HSMSG_HISTORY_FOOTER", count);
        }
    }

    chathistory_result_free(results);
    free(ctx);
}

/* Check if user has access to view channel history */
static int
can_view_channel_history(struct userNode *user, struct chanNode *channel)
{
    /* Must be in the channel */
    if (!GetUserMode(channel, user)) {
        return 0;
    }

    /* If require_channel_access is set, check ChanServ access */
    if (histserv_conf.require_channel_access) {
        struct userData *uData;
        struct chanData *cData = channel->channel_info;

        if (!cData)
            return 0;

        if (!user->handle_info)
            return 0;

        uData = GetChannelUser(cData, user->handle_info);
        if (!uData)
            return 0;
    }

    return 1;
}

/* Validate target access (channel or nick).
 * Returns 1 on success, 0 on failure.
 * Sets *is_dm to 1 if target is a nick (DM), 0 if channel.
 * For DM targets, resolves nick to account name in resolved_target. */
static int
validate_target_access(struct userNode *user, struct svccmd *cmd,
                       const char *target, int *is_dm, char *resolved_target,
                       size_t resolved_len)
{
    struct chanNode *chan;
    struct userNode *target_user;

    /* Check if target is a channel */
    if (IsChannelName(target)) {
        *is_dm = 0;
        strncpy(resolved_target, target, resolved_len - 1);
        resolved_target[resolved_len - 1] = '\0';

        /* Require authentication if configured */
        if (histserv_conf.require_account && !user->handle_info) {
            reply("HSMSG_REQUIRE_AUTH");
            return 0;
        }

        /* Check channel exists */
        chan = GetChannel(target);
        if (!chan) {
            reply("HSMSG_NO_SUCH_CHANNEL", target);
            return 0;
        }

        /* Check access */
        if (!can_view_channel_history(user, chan)) {
            reply("HSMSG_NOT_IN_CHANNEL", target);
            return 0;
        }

        return 1;
    }

    /* Target is a nick - DM history query */
    *is_dm = 1;

    /* DM history must be enabled */
    if (!histserv_conf.dm_history_enabled) {
        reply("HSMSG_DM_DISABLED");
        return 0;
    }

    /* User must be authenticated for DM history */
    if (!user->handle_info) {
        reply("HSMSG_DM_REQUIRE_AUTH");
        return 0;
    }

    /* Find the target user (they should be online, or we use account name) */
    target_user = GetUserH(target);
    if (target_user && target_user->handle_info) {
        /* Use their account name for the query */
        snprintf(resolved_target, resolved_len, "%s",
                 target_user->handle_info->handle);
    } else {
        /* Target not online or not authed - try as account name directly */
        strncpy(resolved_target, target, resolved_len - 1);
        resolved_target[resolved_len - 1] = '\0';
    }

    return 1;
}

/* LATEST <#channel|nick> [count|duration]
 * Get recent messages. If count is a number, return that many messages.
 * If it's a duration (5m, 1h), return messages from that time period. */
static HISTSERV_FUNC(cmd_latest)
{
    struct histserv_query_ctx *ctx;
    const char *target;
    const char *arg;
    int count, is_dm;
    time_t duration;
    char ref[128];
    char resolved_target[CHANNELLEN + 1];

    HISTSERV_MIN_PARAMS(2);

    target = argv[1];
    arg = (argc > 2) ? argv[2] : NULL;

    if (!validate_target_access(user, cmd, target, &is_dm, resolved_target, sizeof(resolved_target)))
        return 0;

    /* Parse optional count/duration argument */
    count = histserv_conf.default_results;
    strcpy(ref, "*");  /* Default: from now */

    if (arg) {
        /* Check if it's a duration (has letter suffix) */
        duration = parse_duration(arg);
        if (duration > 0 && duration < 1000000000) {
            /* It's a duration - use AFTER with timestamp */
            format_timestamp_ref(ref, sizeof(ref), now - duration);
            count = histserv_conf.max_results;  /* Get all in time range */
        } else {
            /* Try as count */
            count = atoi(arg);
            if (count < 1)
                count = histserv_conf.default_results;
        }
    }

    /* Clamp count */
    if (count > histserv_conf.max_results)
        count = histserv_conf.max_results;

    /* Create query context */
    ctx = calloc(1, sizeof(*ctx));
    ctx->user = user;
    strncpy(ctx->target, resolved_target, sizeof(ctx->target) - 1);
    strncpy(ctx->ref, ref, sizeof(ctx->ref) - 1);
    ctx->type = QUERY_LATEST;
    ctx->is_dm = is_dm;

    /* Send CHATHISTORY LATEST query */
    send_chathistory_query(resolved_target, 'L', ref, count, histserv_history_callback, ctx);

    return 1;
}

/* BEFORE <#channel|nick> <time> [count]
 * Get messages before a specific time. */
static HISTSERV_FUNC(cmd_before)
{
    struct histserv_query_ctx *ctx;
    const char *target;
    const char *timearg;
    time_t ts;
    int count, is_dm;
    char ref[128];
    char resolved_target[CHANNELLEN + 1];

    HISTSERV_MIN_PARAMS(3);

    target = argv[1];
    timearg = argv[2];
    count = (argc > 3) ? atoi(argv[3]) : histserv_conf.default_results;

    if (!validate_target_access(user, cmd, target, &is_dm, resolved_target, sizeof(resolved_target)))
        return 0;

    /* Parse time argument */
    ts = parse_time_arg(timearg);
    if (ts == 0) {
        reply("HSMSG_INVALID_TIME", timearg);
        return 0;
    }

    format_timestamp_ref(ref, sizeof(ref), ts);

    /* Clamp count */
    if (count < 1)
        count = histserv_conf.default_results;
    if (count > histserv_conf.max_results)
        count = histserv_conf.max_results;

    /* Create query context */
    ctx = calloc(1, sizeof(*ctx));
    ctx->user = user;
    strncpy(ctx->target, resolved_target, sizeof(ctx->target) - 1);
    strncpy(ctx->ref, ref, sizeof(ctx->ref) - 1);
    ctx->type = QUERY_BEFORE;
    ctx->is_dm = is_dm;

    /* Send CHATHISTORY BEFORE query */
    send_chathistory_query(resolved_target, 'B', ref, count, histserv_history_callback, ctx);

    return 1;
}

/* AFTER <#channel|nick> <time> [count]
 * Get messages after a specific time. */
static HISTSERV_FUNC(cmd_after)
{
    struct histserv_query_ctx *ctx;
    const char *target;
    const char *timearg;
    time_t ts;
    int count, is_dm;
    char ref[128];
    char resolved_target[CHANNELLEN + 1];

    HISTSERV_MIN_PARAMS(3);

    target = argv[1];
    timearg = argv[2];
    count = (argc > 3) ? atoi(argv[3]) : histserv_conf.default_results;

    if (!validate_target_access(user, cmd, target, &is_dm, resolved_target, sizeof(resolved_target)))
        return 0;

    /* Parse time argument */
    ts = parse_time_arg(timearg);
    if (ts == 0) {
        reply("HSMSG_INVALID_TIME", timearg);
        return 0;
    }

    format_timestamp_ref(ref, sizeof(ref), ts);

    /* Clamp count */
    if (count < 1)
        count = histserv_conf.default_results;
    if (count > histserv_conf.max_results)
        count = histserv_conf.max_results;

    /* Create query context */
    ctx = calloc(1, sizeof(*ctx));
    ctx->user = user;
    strncpy(ctx->target, resolved_target, sizeof(ctx->target) - 1);
    strncpy(ctx->ref, ref, sizeof(ctx->ref) - 1);
    ctx->type = QUERY_AFTER;
    ctx->is_dm = is_dm;

    /* Send CHATHISTORY AFTER query */
    send_chathistory_query(resolved_target, 'A', ref, count, histserv_history_callback, ctx);

    return 1;
}

/* AROUND <#channel|nick> <time> [count]
 * Get messages around a specific time. */
static HISTSERV_FUNC(cmd_around)
{
    struct histserv_query_ctx *ctx;
    const char *target;
    const char *timearg;
    time_t ts;
    int count, is_dm;
    char ref[128];
    char resolved_target[CHANNELLEN + 1];

    HISTSERV_MIN_PARAMS(3);

    target = argv[1];
    timearg = argv[2];
    count = (argc > 3) ? atoi(argv[3]) : histserv_conf.default_results;

    if (!validate_target_access(user, cmd, target, &is_dm, resolved_target, sizeof(resolved_target)))
        return 0;

    /* Parse time argument */
    ts = parse_time_arg(timearg);
    if (ts == 0) {
        reply("HSMSG_INVALID_TIME", timearg);
        return 0;
    }

    format_timestamp_ref(ref, sizeof(ref), ts);

    /* Clamp count */
    if (count < 1)
        count = histserv_conf.default_results;
    if (count > histserv_conf.max_results)
        count = histserv_conf.max_results;

    /* Create query context */
    ctx = calloc(1, sizeof(*ctx));
    ctx->user = user;
    strncpy(ctx->target, resolved_target, sizeof(ctx->target) - 1);
    strncpy(ctx->ref, ref, sizeof(ctx->ref) - 1);
    ctx->type = QUERY_AROUND;
    ctx->is_dm = is_dm;

    /* Send CHATHISTORY AROUND query */
    send_chathistory_query(resolved_target, 'R', ref, count, histserv_history_callback, ctx);

    return 1;
}

/* FETCH <#channel|nick> <msgid>
 * Retrieve a specific message by msgid (for multiline fallback). */
static HISTSERV_FUNC(cmd_fetch)
{
    struct histserv_query_ctx *ctx;
    const char *target;
    const char *msgid;
    int is_dm;
    char ref[128];
    char resolved_target[CHANNELLEN + 1];

    HISTSERV_MIN_PARAMS(3);

    target = argv[1];
    msgid = argv[2];

    if (!validate_target_access(user, cmd, target, &is_dm, resolved_target, sizeof(resolved_target)))
        return 0;

    /* Format msgid reference */
    snprintf(ref, sizeof(ref), "msgid=%s", msgid);

    /* Create query context */
    ctx = calloc(1, sizeof(*ctx));
    ctx->user = user;
    strncpy(ctx->target, resolved_target, sizeof(ctx->target) - 1);
    strncpy(ctx->ref, msgid, sizeof(ctx->ref) - 1);
    ctx->type = QUERY_FETCH;
    ctx->is_dm = is_dm;

    /* Send CHATHISTORY AROUND query with msgid */
    send_chathistory_query(resolved_target, 'R', ref, 50, histserv_history_callback, ctx);

    return 1;
}

static void
histserv_conf_read(void)
{
    dict_t conf_node;
    const char *str;

    conf_node = conf_get_data(HISTSERV_CONF_NAME, RECDB_OBJECT);
    if (!conf_node)
        return;

    str = database_get_data(conf_node, "max_results", RECDB_QSTRING);
    histserv_conf.max_results = str ? atoi(str) : 100;

    str = database_get_data(conf_node, "default_results", RECDB_QSTRING);
    histserv_conf.default_results = str ? atoi(str) : 10;

    str = database_get_data(conf_node, "require_account", RECDB_QSTRING);
    histserv_conf.require_account = str ? enabled_string(str) : 1;

    str = database_get_data(conf_node, "require_channel_access", RECDB_QSTRING);
    histserv_conf.require_channel_access = str ? enabled_string(str) : 0;

    str = database_get_data(conf_node, "dm_history", RECDB_QSTRING);
    histserv_conf.dm_history_enabled = str ? enabled_string(str) : 0;

    histserv_conf.timestamp_format = database_get_data(conf_node, "timestamp_format", RECDB_QSTRING);
}

static void
histserv_cleanup(UNUSED_ARG(void *extra))
{
    /* Nothing to clean up currently */
}

int
histserv_init(void)
{
    HS_LOG = log_register_type("HistServ", "file:histserv.log");

    conf_register_reload(histserv_conf_read);
    reg_exit_func(histserv_cleanup, NULL);

    /* Set defaults */
    histserv_conf.max_results = 100;
    histserv_conf.default_results = 10;
    histserv_conf.require_account = 1;
    histserv_conf.require_channel_access = 0;
    histserv_conf.dm_history_enabled = 0;
    histserv_conf.timestamp_format = "%H:%M:%S";

    histserv_module = module_register("HistServ", HS_LOG, "mod-histserv.help", NULL);
    modcmd_register(histserv_module, "latest", cmd_latest, 2, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(histserv_module, "before", cmd_before, 3, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(histserv_module, "after",  cmd_after,  3, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(histserv_module, "around", cmd_around, 3, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(histserv_module, "fetch",  cmd_fetch,  3, MODCMD_REQUIRE_AUTHED, NULL);

    histserv_conf_read();

    return 1;
}

int
histserv_finalize(void)
{
    dict_t conf_node;
    dict_iterator_t it;
    struct service *service;
    struct module *module;
    struct modcmd *modcmd;
    const char *nick;
    const char *modes;

    conf_node = conf_get_data(HISTSERV_CONF_NAME, RECDB_OBJECT);
    if (!conf_node) {
        log_module(HS_LOG, LOG_INFO, "HistServ not configured, module inactive");
        return 0;
    }

    nick = database_get_data(conf_node, "nick", RECDB_QSTRING);
    if (!nick)
        nick = "HistServ";

    modes = database_get_data(conf_node, "modes", RECDB_QSTRING);
    if (!modes)
        modes = "+k";

    /* Create the HistServ bot */
    histserv = AddLocalUser(nick, nick, NULL, "Chat History Services", modes);
    if (!histserv) {
        log_module(HS_LOG, LOG_ERROR, "Failed to create HistServ bot %s", nick);
        return 0;
    }

    /* Register as a service to receive and handle commands */
    service = service_register(histserv);

    /* Bind all module commands to the service.
     * This is needed because modcmd_finalize runs before modules_finalize,
     * so create_default_binds() can't find our service when it runs. */
    for (it = dict_first(histserv_module->commands); it; it = iter_next(it)) {
        modcmd = iter_data(it);
        service_bind_modcmd(service, modcmd, iter_key(it));
    }

    /* Also bind modcmd module for help command */
    module = module_find("modcmd");
    if (module) {
        for (it = dict_first(module->commands); it; it = iter_next(it)) {
            modcmd = iter_data(it);
            service_bind_modcmd(service, modcmd, iter_key(it));
        }
    }

    histserv_conf.bot = histserv;
    log_module(HS_LOG, LOG_INFO, "HistServ bot %s created successfully", nick);
    return 1;
}
