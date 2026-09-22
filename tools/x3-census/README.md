# x3-census

Read-only census of X3 saxdb handles joined against Keycloak.

Reports what seeding the `account_created_at` attribute would do, and enumerates
**stranded handles** — handles with no backing Keycloak user, the latent name-reuse
takeover class.

**It writes nothing.** Not to saxdb, not to LDAP, not to Keycloak. Safe to run against
production.

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
# 1. dump handles from a COPY of the database (never the live file)
cp /path/to/x3.db ./x3.db
./x3dump x3.db > handles.json

# 2. join against Keycloak
python3 census.py handles.json \
    --base https://keycloak.example.net \
    --realm <realm> \
    --password '<admin password>'
```

`--user` defaults to `admin`, `--admin-realm` to `master`. Python 3.8+, stdlib only.

## Reading the output

| Row | Meaning |
|---|---|
| `STRANDED (no KC user)` | handle with no Keycloak account — inheritable by whoever registers the name next |
| `UUID MISMATCH` | stored `ldap_uuid` disagrees with the live `LDAP_ID`; the name was taken by a different principal |
| `RESCUABLE` | saxdb still differs from the directory, so the lazy backfill has not reached this handle — seeding now preserves its original date |
| `would write account_created_at` | rows a seeding run would touch |
| `Keycloak users with no X3 handle` | the inverse: KC-only accounts |

**A row can be both RESCUABLE and UUID MISMATCH**, and those demand opposite actions —
the mismatch means a different principal holds the name, so its old date must *not* be
preserved. Such rows are flagged inline and must never be seeded.

Where no `ldap_uuid` is stored (all of production, as of 2026-09), RESCUABLE rows are
**ambiguous** between "same principal, directory entry recreated" and "different principal
took the name". Nothing in the data separates them. Treat the RESCUABLE list as a review
set, not as an action list.

## Gotcha

`x3dump` calls `tools_init()` before `parse_database()`. It must. `irccasecmp()` folds
through a static table that `tools_init()` populates; uninitialised, every byte maps to
`'\0'`, every dict key compares equal, and **the database silently collapses to a single
entry** — no error, just a wrong answer.

## Background

`.claude/para/projects/account-timestamp-authority-2026-09.md` in the testnet repo.
