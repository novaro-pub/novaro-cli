// Command novaro is the NovaroPay CLI: it pairs with an account, forwards
// test-mode webhook events to a local server, triggers test payments and
// reads or resends events.
package main

import (
	"os"

	"novaro-cli/internal/cmd"
)

// Set by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(cmd.Execute(cmd.Build{Version: version, Commit: commit, Date: date}))
}
