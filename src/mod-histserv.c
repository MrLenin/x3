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
 * Primary use case: Multiline message fallback retrieval
 * - User receives truncated multiline message with msgid hint
 * - User sends: /msg HistServ FETCH #channel <msgid>
 * - HistServ queries IRCd via P10 CHATHISTORY and returns results
 *
 * Commands:
 *   FETCH <#channel|nick> <msgid>     - Retrieve message by msgid
 *   LATEST <#channel|nick> [count]    - Get recent messages
 *   HELP [command]                    - Command help
 */

#include "chanserv.h"
#include "conf.h"
#include "modcmd.h"
#include "nickserv.h"
#include "proto.h"
#include "hash.h"

#define HISTSERV_CONF_NAME "histserv"

static const struct message_entry msgtab[] = {
    { "HSMSG_NOT_IN_CHANNEL", "You must be in $b%s$b to view its history." },
    { "HSMSG_NO_SUCH_CHANNEL", "Channel $b%s$b does not exist." },
    { "HSMSG_NO_HISTORY_FOUND", "No messages found matching your query." },
    { "HSMSG_FETCH_HEADER", "=== Message %s in %s ===" },
    { "HSMSG_FETCH_LINE", "<%s> %s" },
    { "HSMSG_FETCH_FOOTER", "=== End of message ===" },
    { "HSMSG_LATEST_HEADER", "=== Recent messages in %s ===" },
    { "HSMSG_LATEST_LINE", "[%s] <%s> %s" },
    { "HSMSG_LATEST_FOOTER", "=== End of history (%d messages) ===" },
    { "HSMSG_INVALID_TARGET", "$b%s$b is not a valid channel or nick." },
    { "HSMSG_QUERY_PENDING", "A history query is already in progress. Please wait." },
    { "HSMSG_REQUIRE_AUTH", "You must be authenticated to use this command." },
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
    const char *timestamp_format;
} histserv_conf;

/* Pending query context for async callback */
struct histserv_query_ctx {
    struct userNode *user;
    char target[CHANNELLEN + 1];
    char msgid[64];
    int is_fetch;  /* 1 for FETCH, 0 for LATEST */
};

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

/* Callback for FETCH command */
static void
histserv_fetch_callback(const char *reqid, const char *target,
                        struct chathistory_result *results, int count,
                        void *extra)
{
    struct histserv_query_ctx *ctx = extra;
    struct chathistory_result *r;
    const char *nick;

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
        send_message(ctx->user, histserv, "HSMSG_FETCH_HEADER",
                     ctx->msgid, ctx->target);

        for (r = results; r; r = r->next) {
            nick = extract_nick(r->sender);
            send_message(ctx->user, histserv, "HSMSG_FETCH_LINE",
                        nick, r->content);
        }

        send_message(ctx->user, histserv, "HSMSG_FETCH_FOOTER");
    }

    chathistory_result_free(results);
    free(ctx);
}

/* Callback for LATEST command */
static void
histserv_latest_callback(const char *reqid, const char *target,
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
        send_message(ctx->user, histserv, "HSMSG_LATEST_HEADER", ctx->target);

        for (r = results; r; r = r->next) {
            nick = extract_nick(r->sender);
            ts = format_timestamp(r->timestamp);
            send_message(ctx->user, histserv, "HSMSG_LATEST_LINE",
                        ts, nick, r->content);
        }

        send_message(ctx->user, histserv, "HSMSG_LATEST_FOOTER", count);
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

static HISTSERV_FUNC(cmd_fetch)
{
    struct chanNode *chan;
    struct histserv_query_ctx *ctx;
    const char *target;
    const char *msgid;

    HISTSERV_MIN_PARAMS(3);

    target = argv[1];
    msgid = argv[2];

    /* Require authentication if configured */
    if (histserv_conf.require_account && !user->handle_info) {
        reply("HSMSG_REQUIRE_AUTH");
        return 0;
    }

    /* Validate target is a channel */
    if (!IsChannelName(target)) {
        reply("HSMSG_INVALID_TARGET", target);
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

    /* Create query context */
    ctx = calloc(1, sizeof(*ctx));
    ctx->user = user;
    strncpy(ctx->target, target, sizeof(ctx->target) - 1);
    strncpy(ctx->msgid, msgid, sizeof(ctx->msgid) - 1);
    ctx->is_fetch = 1;

    /* Send CHATHISTORY AROUND query */
    send_chathistory_query(target, 'R', msgid, 50, histserv_fetch_callback, ctx);

    return 1;
}

static HISTSERV_FUNC(cmd_latest)
{
    struct chanNode *chan;
    struct histserv_query_ctx *ctx;
    const char *target;
    int count;

    HISTSERV_MIN_PARAMS(2);

    target = argv[1];
    count = (argc > 2) ? atoi(argv[2]) : histserv_conf.default_results;

    /* Clamp count */
    if (count < 1)
        count = 1;
    if (count > histserv_conf.max_results)
        count = histserv_conf.max_results;

    /* Require authentication if configured */
    if (histserv_conf.require_account && !user->handle_info) {
        reply("HSMSG_REQUIRE_AUTH");
        return 0;
    }

    /* Validate target is a channel */
    if (!IsChannelName(target)) {
        reply("HSMSG_INVALID_TARGET", target);
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

    /* Create query context */
    ctx = calloc(1, sizeof(*ctx));
    ctx->user = user;
    strncpy(ctx->target, target, sizeof(ctx->target) - 1);
    ctx->is_fetch = 0;

    /* Send CHATHISTORY LATEST query */
    send_chathistory_query(target, 'L', "*", count, histserv_latest_callback, ctx);

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
    histserv_conf.timestamp_format = "[%H:%M:%S]";

    histserv_module = module_register("HistServ", HS_LOG, "mod-histserv.help", NULL);
    modcmd_register(histserv_module, "fetch",  cmd_fetch,  3, MODCMD_REQUIRE_AUTHED, NULL);
    modcmd_register(histserv_module, "latest", cmd_latest, 2, MODCMD_REQUIRE_AUTHED, NULL);

    histserv_conf_read();

    return 1;
}

int
histserv_finalize(void)
{
    dict_t conf_node;
    const char *nick;

    conf_node = conf_get_data(HISTSERV_CONF_NAME, RECDB_OBJECT);
    if (!conf_node)
        return 0;

    nick = database_get_data(conf_node, "nick", RECDB_QSTRING);
    if (!nick)
        nick = "HistServ";

    if (!(histserv = GetUserH(nick))) {
        log_module(HS_LOG, LOG_INFO, "HistServ bot %s not found, module inactive", nick);
        return 0;
    }

    histserv_conf.bot = histserv;
    return 1;
}
