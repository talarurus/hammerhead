// Package reporter defines the Reporter interface and provides output formatters.
package reporter

import (
	"github.com/talarurus/hammerhead/internal/engine"
)

// Reporter formats and outputs scan results.
type Reporter interface {
	// Report writes the scan results and returns any write/short-write/flush
	// failure. Output errors do not change the underlying scan result.
	Report(result *engine.ScanResult) error
}
