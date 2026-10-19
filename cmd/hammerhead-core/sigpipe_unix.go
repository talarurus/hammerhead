//go:build unix || darwin || linux

package main

import (
	"os/signal"
	"syscall"
)

func configureOutputSignals() {
	// Go's os.File.Write explicitly raises SIGPIPE for EPIPE on fd 1 or 2.
	// Ignore it before any CLI output so checked writes return EPIPE and the
	// CLI can choose operational exit 2, even when stderr is also broken.
	// Keep this process-wide policy out of the embeddable cli.Run API.
	signal.Ignore(syscall.SIGPIPE)
}
