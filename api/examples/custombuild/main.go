// Command custombuild is a complete custom build of the OpenCTEM server: the
// stock server plus the example extension (pkg/extension/example). A build in
// another Go module looks the same: require github.com/openctemio/openctem/api,
// import the extensions, and pass them to server.Main. Core CI builds this
// binary so the public entry point and the extension API stay usable from
// outside.
package main

import (
	"github.com/openctemio/openctem/api/pkg/extension/example"
	"github.com/openctemio/openctem/api/pkg/server"
)

func main() { server.Main(example.Extension()) }
