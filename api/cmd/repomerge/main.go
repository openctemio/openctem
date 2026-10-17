// Command repomerge: see internal/tools/repomerge. The API image ships it as a link
// to the server binary (cmd/server/tools.go), not as a binary of its own.
package main

import "github.com/openctemio/openctem/api/internal/tools/repomerge"

func main() { repomerge.Main() }
