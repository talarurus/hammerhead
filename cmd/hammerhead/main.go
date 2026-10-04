// Hammerhead is a developer-security CLI for repository inspection.
//
// Usage:
//
//	hammerhead audit [path]     Run security checks against a repository
//	hammerhead version          Print version information
package main

import (
	"github.com/ammaarrehman/hammerhead/internal/cli"
)

func main() {
	cli.Execute()
}
