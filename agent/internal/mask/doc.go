// Package mask applies pgsafe.masking.yaml inside the scratch database with
// SQL only — data is never pulled into Go (design §3.6–3.7). It is fail
// closed: unreviewed PII blocks the run.
package mask
