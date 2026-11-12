// Package server is the public entry point of the API server.
//
// The stock binary (cmd/server) calls Main from its own main function. A
// custom build may do the same: a separate Go module imports this package and
// calls Main from its own main package. Go's internal-package rule then limits
// that module to the public packages under api/pkg; everything under
// api/internal stays unimportable from outside this module.
package server

import internalserver "github.com/openctemio/openctem/api/internal/server"

// Main runs the API server (or one of its bundled command-line tools, chosen
// by the name the binary was invoked as) and exits the process when it stops.
func Main() { internalserver.Main() }
