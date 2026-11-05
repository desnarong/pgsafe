-- Scratch-only helper schema for masking. Dropped before the masked dump.
CREATE SCHEMA pgsafe_mask;

-- Hashes of sampled original values, for the post-check. Never values themselves.
CREATE TABLE pgsafe_mask.orig_sample (tbl text NOT NULL, col text NOT NULL, row_key text, value_hash bytea NOT NULL);
