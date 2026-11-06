// Package server is the public entry point of the API server.
//
// The stock binary (cmd/server) calls Main from its own main function. A
// custom build may do the same: a separate Go module imports this package and
// calls Main from its own main package with the extensions it builds in
// (api/pkg/extension). Go's internal-package rule then limits that module to
// the public packages under api/pkg; everything under api/internal stays
// unimportable from outside this module.
//
//	func main() { server.Main(myext.Extension()) }
package server

import (
	internalserver "github.com/openctemio/openctem/api/internal/server"
	"github.com/openctemio/openctem/api/pkg/extension"
)

// Main runs the API server (or one of its bundled command-line tools, chosen
// by the name the binary was invoked as) with the given extensions, and exits
// the process when it stops. The Community build passes none. An invalid
// set of extensions stops the start before anything else runs.
func Main(exts ...extension.Extension) { internalserver.Main(exts...) }
