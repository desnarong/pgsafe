// Package exitcode defines the process exit codes every pgsafe command uses
// (design doc §3.1). CI pipelines rely on these values, so they must not change.
package exitcode

import "errors"

const (
	OK          = 0 // success
	Failure     = 1 // the operation ran and failed (backup error, verify check failed, ...)
	ConfigError = 2 // invalid config, flags or environment
	PIIBlocked  = 3 // staging blocked: unreviewed PII columns need review
)

// Error carries an exit code alongside the underlying error.
type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Config wraps err as a configuration error (exit 2).
func Config(err error) error { return &Error{Code: ConfigError, Err: err} }

// Blocked wraps err as a PII-review block (exit 3).
func Blocked(err error) error { return &Error{Code: PIIBlocked, Err: err} }

// ErrReported marks a failure whose details the command already printed;
// main exits with the code without printing it again.
var ErrReported = errors.New("failure already reported")

// Reported returns an error carrying code that main will not print.
func Reported(code int) error { return &Error{Code: code, Err: ErrReported} }

// From returns the exit code for err: 0 for nil, the wrapped code if err
// (or anything it wraps) is an *Error, otherwise Failure.
func From(err error) int {
	if err == nil {
		return OK
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return Failure
}
