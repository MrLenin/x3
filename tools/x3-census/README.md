# x3-census

Read-only census of X3 saxdb handles joined against Keycloak.

It answers what the account-identity work needs to know about a network:

- which handles have **no Keycloak user**, and of those, which were deleted from the
  directory (safe to dispose) and which might be **break-glass** accounts (hold);
- which of those carry an **oper level** or a **certificate fingerprint**;
- how many handles have a Keycloak id to **seed** for the wire-carried identity, optionally
  writing that map out.

**It writes nothing** — not to saxdb, not to LDAP, not to Keycloak. Safe to run against
production.

Background: `.claude/para/projects/account-timestamp-authority-2026-09.md` in the testnet
repo, sections F, I and J.

## Build

Must be built inside a *configured* X3 checkout — it compiles `../../src/tools.c`, whose
IRC casemapping table is `#ifdef WITH_PROTOCOL_P10`. Building against a different
`config.h` folds handle keys differently from the X3 that wrote the database.

```sh
cd x3 && ./configure          # if not already configured
cd tools/x3-census && make
```

## Run

```sh
# 1. dump handles from a COPY of the database -- never the live file
cp /path/to/x3.db ./x3.db
./x3dump x3.db > handles.json

# 2. join against Keycloak (password from the environment, or you are prompted)
export KC_ADMIN_PASSWORD='...'
python3 census.py handles.json \
    --base https://keycloak.example.net \
    --realm <realm> \
    [--map-out seedmap.json]
```

`--user` defaults to `admin`, `--admin-realm` to `master`. Python 3.8+, stdlib only.

The password is **never** accepted on the command line, where it would land in shell
history and the process list.

## Handle the database copy as secret material

X3 stores **unsalted md5 of real passwords** in saxdb — the same hash it writes to LDAP at
registration. A copy of `x3.db` is therefore a set of crackable password hashes. Delete it
when done; the `.gitignore` already refuses to commit it.

`x3dump` itself never emits a hash. It reports only whether one is present
(`has_passwd`), because that is all the census needs.

## Reading the output

| Row | Meaning | Action |
|---|---|---|
| `seedable` | resolves to a Keycloak user with no identity conflict | candidate for the identity seed (`--map-out`) |
| `IDENTITY MISMATCH` | stored `ldap_uuid` disagrees with the live `LDAP_ID`: the name now belongs to a different principal | never seed; investigate |
| `blank password -> ... DISPOSE` | no Keycloak user, and X3 never saw a password — it was created from the directory, which has since deleted it | disposal candidate |
| `password set -> ... HOLD` | no Keycloak user, but X3 holds a password: a break-glass account **or** a deleted one, and nothing in the data separates them | hold; never dispose blindly |
| `...of which carry an oper level` | the highest-value case | **look at these first** |
| `...of which have a certificate fingerprint` | break-glass accounts are certificate-based, so this is the strongest break-glass signal | protect, don't dispose |
| `dates step 1 would still save` | saxdb's registration date still differs from the directory's, so it survives if the LDAP-backfill fix deploys before the owner next logs in | informational |
| `usernames colliding under X3's fold` | Keycloak names that X3 would treat as one handle | investigate |

"Blank means X3 never saw the password" is exact, not a heuristic: autocreate registers
with a NULL password, and an unredeemed activation cookie blanks it. A failed LDAP add
never produces a blank handle — it produces no handle at all.

Handles flagged `SUSPENDED` or `NODELETE` are marked in the lists.

## Name matching

The join folds names exactly as X3's `irccasecmp()` does under P10: ASCII case, RFC 1459's
`[]\^` onto `{|}~`, and the Latin-1 upper ranges. Verified byte for byte against X3's own
folding table. Plain lower-casing would treat `foo[` and `foo{` as different names when X3
treats them as the same handle.

## Gotchas

**`x3dump` calls `tools_init()` before `parse_database()`, and must.** `irccasecmp()` folds
through a static table that `tools_init()` populates; uninitialised, every byte maps to
`'\0'`, every dict key compares equal, and the database silently collapses to a single
entry — no error, just a wrong answer.

**An X3 that does not know a saxdb key erases it on the next write.** If the database came
from an X3 build older than the one that introduced a key (such as `ldap_uuid`), that key
will be absent here even though it once existed.
