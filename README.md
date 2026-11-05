# pgsafe

Postgres backups that are **restore-tested every time**, plus **PII-masked staging databases** for your dev team.

This repository is the open-source **agent** (`pgsafe` CLI + daemon, Apache-2.0). It runs in your
infrastructure, needs no inbound port and works fully offline; the optional hosted dashboard only
ever receives metadata (status, row counts, timings), never data or credentials.

## Install
Releases are built by GoReleaser from [`.goreleaser.yaml`](.goreleaser.yaml) for Linux and macOS
(amd64, arm64). `checksums.txt` is signed keyless with cosign (Sigstore, GitHub OIDC) and every
archive ships with an SPDX SBOM.

**Script** (Linux/macOS): verifies sha256, and the cosign signature when `cosign` is installed.
```bash
curl -fsSL https://get.pgsafe.dev | sh
# pin a version / choose the directory (default /usr/local/bin, else ~/.local/bin)
curl -fsSL https://get.pgsafe.dev | PGSAFE_VERSION=1.2.3 PGSAFE_INSTALL_DIR=$HOME/bin sh
```

**Homebrew**
```bash
brew install --cask desnarong/tap/pgsafe
```

**Docker** — `ghcr.io/desnarong/pgsafe` (amd64/arm64) includes `pg_dump`/`pg_restore` 14–18 and the
docker CLI. `verify.runtime: docker` starts the scratch Postgres on the host, so mount the host
socket (that grants the container control of the host's Docker); otherwise set `verify.runtime: server`.
```bash
docker run --rm -v "$PWD:/work" -w /work --env-file pgsafe.env \
  -v /var/run/docker.sock:/var/run/docker.sock --group-add "$(stat -c %g /var/run/docker.sock)" \
  ghcr.io/desnarong/pgsafe:latest verify
```

**deb / rpm** — from the [releases page](https://github.com/desnarong/pgsafe/releases). The package
installs `/usr/bin/pgsafe`, the `pgsafe` system user and `pgsafe.service` (not enabled); examples are in
`/usr/share/doc/pgsafe/`.
```bash
sudo apt install ./pgsafe_1.2.3_amd64.deb      # or: sudo dnf install ./pgsafe-1.2.3-1.x86_64.rpm
```

**Verify a download yourself**
```bash
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/desnarong/pgsafe/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --ignore-missing -c checksums.txt
cosign verify ghcr.io/desnarong/pgsafe:1.2.3 \
  --certificate-identity-regexp '^https://github.com/desnarong/pgsafe/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
Maintainers: `make release-check` builds a local snapshot into `dist/` (nothing is published),
`make install-test` tests `install.sh` against it, and pushing a `v*` tag runs
[`release.yml`](.github/workflows/release.yml) (needs the `HOMEBREW_TAP_TOKEN` secret).

## Quickstart
```bash
export DATABASE_URL='postgres://pgsafe_ro:…@db.internal:5432/app'   # credentials from env only
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…

pgsafe init --generate-key --db-name app --bucket my-backups --prefix app/
export PGSAFE_AGE_IDENTITY_FILE=$PWD/keys/backup.key   # then store this key somewhere safe
pgsafe backup && pgsafe verify
pgsafe list backups
```
`verify` restores the newest backup into a throwaway Postgres (Docker, or a database on
`verify.server_url`) and checks: sha256, decrypt, `pg_restore` errors, every table present,
row counts (exact or within tolerance), non-empty tables, schema hash and your own SQL checks.
The measured restore time is your real RTO. See [pgsafe.example.yaml](pgsafe.example.yaml).

Every command supports `--json`. Exit codes: `0` ok, `1` failed, `2` config error, `3` blocked by PII review.

## Masked staging
```bash
export PGSAFE_MASK_SALT=$(openssl rand -hex 32)   # keep it stable: same salt → same fake values
pgsafe scan                 # finds PII (Thai ID, phone, names, addresses, cards, IP, JSON keys, free text)
                            # and writes pgsafe.masking.yaml with reviewed: false
$EDITOR pgsafe.masking.yaml # review each rule, set reviewed: true (strategy: keep for non-PII)
pgsafe stage                # masks the newest backup in a scratch DB and replaces the staging DB
pgsafe pull --staging --to postgres://localhost/app_dev   # on a developer machine
```
- **Fail closed:** an unreviewed rule, or a new column that looks like PII (e.g. someone adds
  `line_id`), stops `mask`/`stage` with exit code 3 and adds a suggestion to the rules file.
- **Deterministic:** the same value always masks to the same fake value under one salt, so joins
  (`orders.customer_email` ↔ `customers.email`) and unique constraints survive. Thai IDs, phones and
  cards use format-preserving encryption: valid checksums, never collide.
- **In SQL only:** masking runs inside the scratch database; data never passes through pgsafe.
  Big tables (> `large_table_rows`) use a CTAS path instead of `UPDATE`. Measured on a Windows
  dev laptop (Docker Desktop): 10M rows × 3 columns (email, phone, Thai name) in 1m15s (`make e2e-perf`).
- **Checked:** foreign keys are re-validated and a sample of rows is re-checked; a failure stops publishing.
- Masked dumps should be encrypted with a separate dev-team key (`staging.encryption`) — never the backup key.
- The scratch role must be a superuser (`session_replication_role`); the Docker runtime is.
  With `verify.runtime: server`, use a dedicated scratch server.

## Running on a schedule
```bash
pgsafe run --print-schedule     # next run times
pgsafe run                      # daemon: backup → verify (after_backup) → stage (after_verify, only if verify passed)
pgsafe run --once               # one full cycle now, then exit (system cron / CI)
```
- One daemon per `state_dir` and one run per database at a time (file locks); a second
  `pgsafe backup` while the daemon backs up the same database exits 1.
- At start it removes leftovers of interrupted runs (scratch containers, `pgsafe_verify_*` and
  half-built staging databases) and runs a backup it missed while the machine was down.
  `verify`, `scan`, `mask` and `stage` clean their own database's leftovers too; `pgsafe cleanup` does it on demand.
- `notify:` webhooks get a JSON event (`backup.passed`, `verify.failed`, `stage.blocked`, …) with metadata only.
- Linux service: [deploy/systemd/pgsafe.service](deploy/systemd/pgsafe.service) — secrets go in
  `/etc/pgsafe/pgsafe.env` ([example](deploy/systemd/pgsafe.env.example)), logs as JSON in journald.

## Restoring (real recovery)
```bash
pgsafe list backups
pgsafe restore --backup bk_01J… --to postgres://admin@db/app_restored          # asks you to type "app_restored"
pgsafe restore --backup latest --to … --yes --confirm-db=app_restored         # automation
pgsafe restore --backup bk_01J… --to postgres://admin@db/app --replace        # swap in; old DB kept as app_pgsafe_old_…
```
By default the target must be a new database — switch your application over yourself. The sha256
is checked first, the restored database is checked against the manifest afterwards, the equivalent
manual commands are printed, and every restore is appended to `state_dir/audit.jsonl`.

### Restore without pgsafe
Backups are plain `pg_dump` custom-format archives encrypted with [age](https://age-encryption.org):
```bash
aws s3 cp s3://my-backups/app/backups/app/<backup_id>/dump.pgc.age .
sha256sum dump.pgc.age                         # compare with manifest.json
age -d -i backup.key dump.pgc.age > dump.pgc
pg_restore --no-owner -d postgres://…/app_restored dump.pgc
```

### pg_dump / pg_restore
pgsafe uses a client whose major version equals the server's. `pg_client: auto` looks for a local
install (`PGSAFE_PG_BIN_DIR`, `/usr/lib/postgresql/<N>/bin`, `/usr/pgsql-<N>/bin`, `PATH`) and falls back
to the `postgres:<N>` Docker image. On a Linux server, install `postgresql-client-14…18` from the
PGDG repository for the fastest path; without Docker there, use `verify.runtime: server`.

## Hosted dashboard (optional)
`pgsafe login` connects the agent to the hosted control plane (schedules, alerts by email, LINE,
Slack or webhook, PII review, audit report PDF). The agent stays complete and free without it.

## Layout
| Path | What |
|---|---|
| `agent/` | `pgsafe` CLI + daemon |
| `shared/apitypes/` | wire types of the agent ↔ dashboard API |
| `deploy/` | dev compose, seed data, agent image, packages, install script |
| `e2e/` | integration tests against the dev env |

## Dev environment
Requirements: Go 1.23+, Docker (Docker Desktop with WSL2 on Windows).

| Service | Port | Notes |
|---|---|---|
| pg-source-14 / 16 / 18 | 5414 / 5416 / 5418 | DB `shop`, seeded Thai shop data (100,000 rows) |
| pg-staging | 5433 | DB `shop_staging`, empty |
| minio | 9000 (S3), 9001 (console) | bucket `pgsafe-dev` |

Dev credentials: see [.env.example](.env.example) (`pgsafe`/`pgsafe`, `pgsafeminio`/`pgsafeminio`).

Linux / macOS / VPS:
```bash
make dev-up      # start everything and wait until seeded + healthy
make test        # go vet + unit tests
make e2e         # integration tests (needs dev-up)
make build       # bin/pgsafe
make dev-reset   # wipe and re-seed
```

Windows (PowerShell):
```powershell
.\make.ps1 dev-up
.\make.ps1 test
.\make.ps1 e2e
```

### Windows notes
- Line endings are LF for everything except `*.ps1` (enforced by `.gitattributes`); set `git config core.autocrlf false`.
- If builds fail with `compile: version "go1.x" does not match go tool version`, a stale `GOROOT`
  environment variable points at an old Go install. Remove it (`make.ps1` ignores it automatically).

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under [Apache-2.0](LICENSE).
