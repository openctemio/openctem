// Command provider-addresses: see internal/tools/provideraddrcmd. The API image ships it as a link
// to the server binary (internal/server/tools.go), not as a binary of its own.
package main

import "github.com/openctemio/openctem/server/internal/tools/provideraddrcmd"

func main() { provideraddrcmd.Main() }
