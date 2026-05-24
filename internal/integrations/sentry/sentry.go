// Package sentry wraps github.com/getsentry/sentry-go behind a DSN-gated
// Init/Capture/Recover surface. With an empty DSN the package is a no-op,
// so callers can wire it unconditionally and only the user controls activation.
package sentry

import (
	"time"

	"github.com/getsentry/sentry-go"
)

var enabled bool

// Init configures Sentry. An empty dsn disables the package; subsequent
// Capture/Recover calls become no-ops. Safe to call once at program start.
func Init(dsn string, release string) error {
	if dsn == "" {
		enabled = false
		return nil
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Release:          release,
		TracesSampleRate: 0,
		AttachStacktrace: true,
	})
	if err != nil {
		return err
	}
	enabled = true
	return nil
}

// IsEnabled reports whether Sentry is currently sending events.
func IsEnabled() bool { return enabled }

// Capture sends an error if enabled.
func Capture(err error) {
	if !enabled || err == nil {
		return
	}
	sentry.CaptureException(err)
}

// CaptureMessage sends a free-form message, e.g. for high-severity anomalies.
func CaptureMessage(msg string) {
	if !enabled {
		return
	}
	sentry.CaptureMessage(msg)
}

// Recover installs a deferred recover() that forwards panics to Sentry then
// re-panics. Use it in goroutines whose crashes you want surfaced.
func Recover() {
	if !enabled {
		return
	}
	if r := recover(); r != nil {
		sentry.CurrentHub().Recover(r)
		sentry.Flush(2 * time.Second)
		panic(r)
	}
}

// Flush blocks up to 2s for in-flight events. Call before clean shutdown.
func Flush() {
	if !enabled {
		return
	}
	sentry.Flush(2 * time.Second)
}
