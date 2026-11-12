// Command asset-canonical: see internal/tools/assetcanoncmd. The API image ships it as a link
// to the server binary (internal/server/tools.go), not as a binary of its own.
package main

import "github.com/openctemio/openctem/api/internal/tools/assetcanoncmd"

func main() { assetcanoncmd.Main() }
