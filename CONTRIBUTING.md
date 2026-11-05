# Contributing to pgsafe

Thanks for helping. Issues and pull requests are welcome here.

- This repository is published from the maintainers' main repository, which also holds the hosted
  dashboard. Accepted pull requests are applied there and appear here with the next sync, credited
  to you (`Co-authored-by`). Your PR is closed as merged at that point.
- Contributions are licensed under [Apache-2.0](LICENSE).

## Ground rules
- Customer data and credentials never go to a server or into a log.
- Masking is fail closed: an unreviewed PII column stops staging.
- A backup must restore with a stock `pg_restore`.
- Scratch databases and containers are always removed, even on error.
- Masking runs in SQL on the scratch database — data is never pulled into Go.
- Stream everything (dump / encrypt / upload); never load a whole file into memory.
- Every command supports `--json` and the exit codes in `agent/internal/exitcode`.

## Checks
```bash
make dev-up   # Postgres 14/16/18 + MinIO with seeded Thai shop data
make test     # go vet + unit tests
make e2e      # integration tests (needs dev-up)
```
Every detector and masking strategy needs a unit test. A change to masking logic must pass the
"no real values left" test (`make e2e`). On Windows use `.\make.ps1 <target>`.
