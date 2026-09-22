#!/usr/bin/env python3
"""Census: join X3 saxdb handles against Keycloak. READ ONLY -- writes nothing to
saxdb, LDAP or Keycloak.

Answers the questions the account-identity work needs from production:

  * Which handles have no Keycloak user, and of those, which were deleted from
    the directory (dispose) and which might be break-glass accounts (hold)?
  * Which of those carry an oper level or a certificate fingerprint?
  * How many handles have a Keycloak id to seed for the wire-carried identity?

Design: .claude/para/projects/account-timestamp-authority-2026-09.md in the
testnet repo, sections F, I and J.

The admin password is read from $KC_ADMIN_PASSWORD, or prompted for. It is
never taken on the command line, where it would land in shell history and the
process list.
"""
import argparse
import datetime
import getpass
import json
import os
import sys
import urllib.parse
import urllib.request

BACKFILL_EPOCH = 1773273600  # 2026-03-12 00:00:00Z, when the LDAP backfill (a52968b) landed

# X3's handle flags, by bit position (src/nickserv.h HANDLE_FLAGS).
FLAG_SUSPENDED = "s"
FLAG_NODELETE = "n"


def irc_fold(name):
    """Fold a name the way X3's irccasecmp() does under WITH_PROTOCOL_P10
    (src/tools.c tools_init): ASCII A-Z, then RFC 1459's []\\^ onto {|}~, then the
    Latin-1 upper ranges 0xC0-0xD6 and 0xD8-0xDE.

    Handles are compared with this fold inside X3, so the join has to use it
    too. Plain str.lower() would treat 'foo[' and 'foo{' as different names
    when X3 treats them as the same handle.
    """
    out = []
    for ch in name:
        o = ord(ch)
        if 0x41 <= o <= 0x5A:            # A-Z
            o += 0x20
        elif o in (0x5B, 0x5C, 0x5D, 0x5E):  # [ \ ] ^  ->  { | } ~
            o += 0x20
        elif 0xC0 <= o <= 0xD6 or 0xD8 <= o <= 0xDE:
            o += 0x20
        out.append(chr(o))
    return "".join(out)


def api(base, token, path, **params):
    url = base + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def get_token(base, realm, user, pw):
    data = urllib.parse.urlencode({
        "client_id": "admin-cli", "username": user,
        "password": pw, "grant_type": "password"}).encode()
    with urllib.request.urlopen(base + "/realms/%s/protocol/openid-connect/token" % realm, data) as r:
        return json.load(r)["access_token"]


def ldap_gt_to_epoch(s):
    """LDAP generalized time -> epoch seconds."""
    try:
        return int(datetime.datetime.strptime(s[:14], "%Y%m%d%H%M%S")
                   .replace(tzinfo=datetime.timezone.utc).timestamp())
    except Exception:
        return None


def fetch_all_users(base, token, realm):
    """All realm users keyed by folded username. Returns (users, collisions)."""
    users, collisions, first = {}, {}, 0
    while True:
        page = api(base, token, "/admin/realms/%s/users" % realm,
                   first=first, max=100, briefRepresentation="false")
        if not page:
            break
        for u in page:
            key = irc_fold(u["username"])
            if key in users:
                collisions.setdefault(key, [users[key]["username"]]).append(u["username"])
            else:
                users[key] = u
        first += len(page)
    return users, collisions


def day(epoch):
    return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).strftime("%Y-%m-%d")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("handles_json", help="output of x3dump")
    ap.add_argument("--base", required=True, help="Keycloak base URL")
    ap.add_argument("--realm", required=True)
    ap.add_argument("--admin-realm", default="master")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--map-out", metavar="FILE",
                    help="also write {handle: keycloak_id} for handles safe to seed")
    a = ap.parse_args()

    pw = os.environ.get("KC_ADMIN_PASSWORD") or getpass.getpass("Keycloak admin password: ")

    handles = json.load(open(a.handles_json))
    token = get_token(a.base, a.admin_realm, a.user, pw)
    kc, collisions = fetch_all_users(a.base, token, a.realm)

    resolved, seedable, uuid_mismatch, dates_saved = [], {}, [], []
    no_kc_blank, no_kc_hash = [], []

    for h in handles:
        name = h["handle"]
        u = kc.get(irc_fold(name))
        if not u:
            (no_kc_hash if h.get("has_passwd") else no_kc_blank).append(h)
            continue
        resolved.append(h)
        attrs = u.get("attributes") or {}

        # Name reuse: a stored directory identity that no longer matches.
        stored = h.get("ldap_uuid")
        live = (attrs.get("LDAP_ID") or [None])[0]
        if stored and live and stored != live:
            uuid_mismatch.append((name, stored, live))
            continue                      # never seed a reused name

        seedable[name] = u["id"]

        # Informational: saxdb still differs from the directory, so this account's
        # original registration date survives if step 1 deploys before its owner
        # next logs in.
        ct = (attrs.get("createTimestamp") or [None])[0]
        cte = ldap_gt_to_epoch(ct) if ct else None
        if h.get("register") and cte is not None and int(h["register"]) != cte:
            dates_saved.append((name, int(h["register"]), cte))

    x3names = {irc_fold(h["handle"]) for h in handles}
    kc_only = sum(1 for key in kc if key not in x3names)
    no_kc = no_kc_blank + no_kc_hash

    def flagged(rows, pred):
        return [r for r in rows if pred(r)]

    oper_no_kc = flagged(no_kc, lambda r: r.get("opserv_level"))
    cert_no_kc = flagged(no_kc, lambda r: r.get("sslfp_count"))
    # A database from an X3 that never ran the ldap_uuid binding -- production,
    # as of 2026-09 -- carries no stored identities at all. Then the mismatch
    # count is not "0 reused names", it is "cannot tell", and must say so.
    have_identities = any(h.get("ldap_uuid") for h in handles)

    print("=" * 66)
    print("X3 -> Keycloak account census (READ ONLY)")
    print("=" * 66)
    for label, n in [
        ("X3 handles in saxdb", len(handles)),
        ("resolved to a Keycloak user", len(resolved)),
        ("  seedable (Keycloak id, no identity conflict)", len(seedable)),
        ("  IDENTITY MISMATCH (stored ldap_uuid != LDAP_ID)",
         len(uuid_mismatch) if have_identities else None),
        ("NO Keycloak user", len(no_kc)),
        ("  blank password -> deleted from directory: DISPOSE", len(no_kc_blank)),
        ("  password set   -> break-glass OR deleted: HOLD", len(no_kc_hash)),
        ("    ...of which carry an oper level  (LOOK FIRST)", len(oper_no_kc)),
        ("    ...of which have a certificate fingerprint", len(cert_no_kc)),  # informational
        ("dates step 1 would still save", len(dates_saved)),
        ("Keycloak users with no X3 handle", kc_only),
        ("Keycloak usernames colliding under X3's fold", len(collisions)),
    ]:
        if n is None:
            print("%-52s %6s" % (label, "n/a"))
        else:
            print("%-52s %6d" % (label, n))
    if not have_identities:
        print("\n  n/a: no handle in this database carries a stored identity (ldap_uuid),\n"
              "  so name reuse cannot be detected here -- the count is unknown, not zero.")

    def show(title, rows, note=None):
        if not rows:
            return
        print("\n" + title + (("  -- " + note) if note else "") + ":")
        for r in sorted(rows, key=lambda r: r["handle"]):
            bits = ["registered %s" % day(r["register"])] if r.get("register") else []
            if r.get("opserv_level"):
                bits.append("opserv_level=%s" % r["opserv_level"])
            if r.get("sslfp_count"):
                bits.append("certfp x%d" % r["sslfp_count"])
            f = r.get("flags") or ""
            if FLAG_SUSPENDED in f:
                bits.append("SUSPENDED")
            if FLAG_NODELETE in f:
                bits.append("NODELETE")
            print("   %-22s %s" % (r["handle"], "  ".join(bits)))

    show("No Keycloak user, with an oper level", oper_no_kc,
         "possible break-glass/admin account; check before anything else")
    show("No Keycloak user, password set (HOLD)", no_kc_hash,
         "break-glass or deleted, indistinguishable; do not dispose blindly")
    show("No Keycloak user, blank password (DISPOSE candidates)", no_kc_blank,
         "created from the directory, since deleted")

    if uuid_mismatch:
        print("\nIdentity mismatches -- the name now belongs to a different principal; never seed:")
        for n, stored, live in sorted(uuid_mismatch):
            print("   %-22s stored=%s live=%s" % (n, stored, live))
    if collisions:
        print("\nKeycloak usernames that X3 would treat as the same handle:")
        for key, names in sorted(collisions.items()):
            print("   %s" % ", ".join(names))
    if dates_saved:
        print("\nDates step 1 would still save (saxdb differs from directory):")
        for n, reg, cte in sorted(dates_saved):
            print("   %-22s saxdb %s  vs  directory %s" % (n, day(reg), day(cte)))

    if a.map_out:
        with open(a.map_out, "w") as f:
            json.dump(seedable, f, indent=1, sort_keys=True)
        print("\nWrote %d handle -> Keycloak id entries to %s" % (len(seedable), a.map_out))


if __name__ == "__main__":
    main()
