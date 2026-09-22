#!/usr/bin/env python3
"""Dry-run census: join X3 saxdb handles against Keycloak. READ ONLY.

Reports what seeding account_created_at would do, and enumerates stranded handles
(no Keycloak user) -- the latent name-reuse takeover class.
"""
import json, sys, urllib.request, urllib.parse, datetime, argparse

BACKFILL_EPOCH = 1773273600  # 2026-03-12 00:00:00Z, when a52968b landed

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
    out, first = {}, 0
    while True:
        page = api(base, token, "/admin/realms/%s/users" % realm,
                   first=first, max=100, briefRepresentation="false")
        if not page:
            break
        for u in page:
            out[u["username"].lower()] = u
        first += len(page)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("handles_json"); ap.add_argument("--base", required=True)
    ap.add_argument("--realm", required=True); ap.add_argument("--admin-realm", default="master")
    ap.add_argument("--user", default="admin"); ap.add_argument("--password", required=True)
    a = ap.parse_args()

    handles = json.load(open(a.handles_json))
    token = get_token(a.base, a.admin_realm, a.user, a.password)
    kc = fetch_all_users(a.base, token, a.realm)

    stats = dict(total=len(handles), resolved=0, stranded=0, uuid_mismatch=0,
                 already_seeded=0, would_write=0, rescuable=0, no_register=0,
                 dormant=0, kc_only=0)
    stranded, mismatched, rescuable = [], [], []

    for h in handles:
        name, reg = h["handle"], h["register"]
        if reg is None:
            stats["no_register"] += 1
            continue
        u = kc.get(name.lower())
        if not u:
            stats["stranded"] += 1
            stranded.append((name, h.get("opserv_level"), reg))
            continue
        stats["resolved"] += 1
        attrs = u.get("attributes") or {}

        # UUID corroboration where X3 has one stored
        if h.get("ldap_uuid"):
            ldap_id = (attrs.get("LDAP_ID") or [None])[0]
            if ldap_id and ldap_id != h["ldap_uuid"]:
                stats["uuid_mismatch"] += 1
                mismatched.append((name, h["ldap_uuid"], ldap_id))

        # already seeded?
        seeded = (attrs.get("account_created_at") or [None])[0]
        if seeded is not None and str(seeded) == str(reg):
            stats["already_seeded"] += 1
        else:
            stats["would_write"] += 1

        # the rescuable cohort: saxdb still disagrees with the directory,
        # i.e. the lazy backfill has not reached this handle yet
        ct = (attrs.get("createTimestamp") or [None])[0]
        cte = ldap_gt_to_epoch(ct) if ct else None
        if cte is not None and int(reg) != cte:
            stats["rescuable"] += 1
            rescuable.append((name, int(reg), cte))

        if h.get("lastseen") and int(h["lastseen"]) < BACKFILL_EPOCH:
            stats["dormant"] += 1

    x3names = {h["handle"].lower() for h in handles}
    stats["kc_only"] = sum(1 for n in kc if n not in x3names)

    print("=" * 62)
    print("X3 -> Keycloak account census (READ ONLY)")
    print("=" * 62)
    for k, label in [
        ("total",          "X3 handles in saxdb"),
        ("no_register",    "  no register key (skipped)"),
        ("resolved",       "resolved to a Keycloak user"),
        ("stranded",       "  STRANDED (no KC user) - takeover class"),
        ("uuid_mismatch",  "  UUID MISMATCH (stored vs LDAP_ID)"),
        ("already_seeded", "already seeded, value matches"),
        ("would_write",    "would write account_created_at"),
        ("rescuable",      "RESCUABLE: saxdb still differs from directory"),
        ("dormant",        "  (corroborating) lastseen before 2026-03-12"),
        ("kc_only",        "Keycloak users with no X3 handle"),
    ]:
        print("%-46s %6d" % (label, stats[k]))

    if stranded:
        print("\nStranded handles (no Keycloak user):")
        for n, osl, reg in sorted(stranded):
            t = datetime.datetime.fromtimestamp(int(reg), datetime.timezone.utc).strftime("%Y-%m-%d")
            print("   %-22s registered %s%s" % (n, t, "  opserv_level=%s" % osl if osl else ""))
    if mismatched:
        print("\nUUID mismatches (investigate before any write):")
        for n, stored, live in mismatched:
            print("   %-22s stored=%s live=%s" % (n, stored, live))
    if rescuable:
        print("\nRescuable (seeding preserves the original date):")
        mism = {m[0] for m in mismatched}
        for n, reg, cte in sorted(rescuable):
            f = lambda e: datetime.datetime.fromtimestamp(e, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            flag = "   <-- UUID MISMATCH: DO NOT SEED, dispose instead" if n in mism else ""
            print("   %-18s saxdb %s  vs  directory %s%s" % (n, f(reg), f(cte), flag))

if __name__ == "__main__":
    main()
