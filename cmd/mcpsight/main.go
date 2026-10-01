// Command mcpsight is an X-ray machine for MCP servers: it inspects a server's
// token cost, capability surface, and change history before you trust it.
// A Greyquill Software open-source project.
package main

import (
	"os"

	"github.com/greyquill/mcpsight/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}
