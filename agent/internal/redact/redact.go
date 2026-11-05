// Package redact removes credentials from strings before they are logged,
// printed or wrapped into errors. Customer credentials must never leave the
// machine or reach a log (design doc §1, CLAUDE.md).
package redact

import (
	"net/url"
	"regexp"
	"strings"
)

const mask = "xxxxx"

var (
	// scheme://user:password@host — covers postgres://, s3:// and friends.
	urlUserinfo = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]*):([^@\s]*)@`)
	// key=value DSNs: password=secret or password='se cret'.
	dsnPassword = regexp.MustCompile(`(?i)(password\s*=\s*)('[^']*'|\S+)`)
	// ?password=... in a URL query string.
	queryPassword = regexp.MustCompile(`(?i)([?&]password=)[^&\s]*`)
)

// String scrubs passwords embedded in URLs or DSNs inside s, and every
// occurrence of the given extra secrets (e.g. a password read from env).
func String(s string, secrets ...string) string {
	s = urlUserinfo.ReplaceAllString(s, "${1}:"+mask+"@")
	s = dsnPassword.ReplaceAllString(s, "${1}"+mask)
	s = queryPassword.ReplaceAllString(s, "${1}"+mask)
	for _, sec := range secrets {
		if len(sec) >= 4 { // avoid shredding output on trivially short values
			s = strings.ReplaceAll(s, sec, mask)
		}
	}
	return s
}

// URL returns raw with its password (userinfo or ?password=) masked. Invalid
// URLs fall back to String.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return String(raw)
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), mask)
		}
	}
	q := u.Query()
	if q.Has("password") {
		q.Set("password", mask)
		u.RawQuery = q.Encode()
	}
	return u.String()
}
