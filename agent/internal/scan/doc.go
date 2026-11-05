// Package scan detects PII columns from column names, Thai comments and sampled
// values (design §3.5). Sampled values never leave memory; findings carry no data.
package scan
