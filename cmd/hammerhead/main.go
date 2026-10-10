package main

import (
	"context"
	"os"

	"github.com/talarurus/hammerhead/internal/cli"
)

func main() {
	configureOutputSignals()
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
