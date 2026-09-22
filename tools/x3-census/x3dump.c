/* x3dump — dump X3 saxdb NickServ handles as JSON, using X3's own recdb parser.
 * Exact by construction: no hand-rolled parsing of quoting, nested blocks or lists.
 *
 * Emits one JSON object per handle: handle, register, lastseen, ldap_uuid,
 * opserv_level, flags, has_passwd, sslfp_count.
 *
 * It deliberately never emits the password hash itself -- only whether one is
 * stored. X3 keeps unsalted md5 of real passwords in saxdb (the same hash it
 * writes to LDAP at registration), so the hash is crackable and must not end
 * up in a JSON file that gets copied around. Blank vs present is all the
 * census needs: blank means X3 never saw the password.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "recdb.h"
#include "dict.h"

extern void tools_init(void);

/* --- stubs: recdb.c only needs these two --- */
#include "log.h"
struct log_type *MAIN_LOG = NULL;
void log_module(struct log_type *type, enum log_severity sev, const char *format, ...)
{ (void)type; (void)sev; (void)format; }

/* tools.c drags these in; none are reachable from parse_database(). */
struct language *lang_C = NULL;
char hidden_host_suffix[256] = "";
struct chanNode *GetChannel(const char *name) { (void)name; return NULL; }
const char *language_find_message(struct language *lang, const char *msgid)
{ (void)lang; return msgid; }

static void json_str(const char *s)
{
    putchar('"');
    for (; s && *s; s++) {
        switch (*s) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout);  break;
        case '\r': fputs("\\r", stdout);  break;
        case '\t': fputs("\\t", stdout);  break;
        default:
            if ((unsigned char)*s < 0x20) printf("\\u%04x", (unsigned char)*s);
            else putchar(*s);
        }
    }
    putchar('"');
}

static const char *qs(dict_t obj, const char *key)
{
    struct record_data *rd = dict_find(obj, key, NULL);
    return rd ? GET_RECORD_QSTRING(rd) : NULL;
}

int main(int argc, char *argv[])
{
    dict_t db, ns;
    dict_iterator_t it;
    int first = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <x3.db>\n", argv[0]);
        return 2;
    }

    /* MUST come first.  irccasecmp() folds through a static table that
     * tools_init() populates; uninitialised it maps every byte to '\0', so
     * every dict key compares equal and the database silently collapses to a
     * single entry.  No error is raised -- you just get a wrong answer. */
    tools_init();

    db = parse_database(argv[1]);
    if (!db) {
        fprintf(stderr, "x3dump: failed to parse %s\n", argv[1]);
        return 1;
    }

    ns = database_get_data(db, "NickServ", RECDB_OBJECT);
    if (!ns) {
        fprintf(stderr, "x3dump: no NickServ section in %s\n", argv[1]);
        return 1;
    }

    puts("[");
    for (it = dict_first(ns); it; it = iter_next(it)) {
        struct record_data *rd = iter_data(it);
        dict_t h = GET_RECORD_OBJECT(rd);
        const char *reg, *seen, *uuid, *osl, *flags, *pw;
        struct record_data *fp_rd;
        struct string_list *fps;

        if (!h) continue;                       /* not a handle object */

        reg  = qs(h, "register");
        seen = qs(h, "lastseen");
        uuid = qs(h, "ldap_uuid");
        osl  = qs(h, "opserv_level");
        flags = qs(h, "flags");
        pw   = qs(h, "passwd");
        fp_rd = dict_find(h, "sslfps", NULL);
        fps  = fp_rd ? GET_RECORD_STRING_LIST(fp_rd) : NULL;

        if (!first) puts(",");
        first = 0;

        fputs("  {\"handle\": ", stdout);
        json_str(iter_key(it));
        fputs(", \"register\": ", stdout);
        printf("%s", reg ? reg : "null");
        fputs(", \"lastseen\": ", stdout);
        printf("%s", seen ? seen : "null");
        fputs(", \"ldap_uuid\": ", stdout);
        if (uuid) json_str(uuid); else fputs("null", stdout);
        fputs(", \"opserv_level\": ", stdout);
        printf("%s", osl ? osl : "null");
        fputs(", \"flags\": ", stdout);
        json_str(flags ? flags : "");
        /* presence only -- never the hash (see header) */
        printf(", \"has_passwd\": %s", (pw && *pw) ? "true" : "false");
        printf(", \"sslfp_count\": %u", fps ? fps->used : 0u);
        fputs("}", stdout);
    }
    puts("\n]");
    return 0;
}
