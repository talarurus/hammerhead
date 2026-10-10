// Package reporter defines the Reporter interface and provides output formatters.
package reporter

import (
	"github.com/talarurus/hammerhead/internal/engine"
)

// Reporter formats and outputs scan results.
type Reporter interface {
	// Report writes the scan results to the configured output.
	Report(result *engine.ScanResult) error
}
