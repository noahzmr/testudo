// Package collectors gathers telemetry from the network stack and publishes
// it as events on the bus. Each collector runs its own goroutine and respects
// context cancellation for shutdown.
package collectors

import (
	"context"

	"github.com/noahzmr/testudo/internal/events"
)

// Collector is the unit of telemetry production. Run blocks until ctx ends.
type Collector interface {
	Name() string
	Run(ctx context.Context, bus *events.Bus) error
}
