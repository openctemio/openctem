package main

import (
	"path/filepath"

	"github.com/openctemio/openctem/api/internal/tools/bootstrapadmin"
	"github.com/openctemio/openctem/api/internal/tools/citrustscopeplan"
	"github.com/openctemio/openctem/api/internal/tools/refingerprintcmd"
	"github.com/openctemio/openctem/api/internal/tools/repomerge"
)

// The operator commands of the API image are links to this binary, so the
// image carries one copy of the packages they share with the server instead
// of one static binary each (each linked most of the API, about 20 MB). The
// name the binary was started under picks the command; each command keeps
// its own flags and exits when done. The commands run with the privileges of
// whoever starts them: this changes how they are packaged, not who may run
// them.
var tools = map[string]func(){
	"bootstrap-admin":     bootstrapadmin.Main,
	"refingerprint":       refingerprintcmd.Main,
	"repomerge":           repomerge.Main,
	"ci-trust-scope-plan": citrustscopeplan.Main,
}

// toolFor returns the command named by argv0, or nil for the server.
func toolFor(argv0 string) func() {
	return tools[filepath.Base(argv0)]
}
