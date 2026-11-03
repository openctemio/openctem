package server_test

import (
	"flag"
	"testing"

	"github.com/openctemio/openctem/api/pkg/server"
)

// Main must keep the func() signature a custom build's main calls.
func TestMainIsExported(t *testing.T) {
	var f func() = server.Main
	_ = f
}

// Importing the package must not add flags to the importer's global flag set.
func TestImportRegistersNoGlobalFlags(t *testing.T) {
	for _, n := range []string{"routes", "version", "check-config", "healthcheck", "sensor-upgrade-check", "signer-ledger-export", "route-format"} {
		if flag.Lookup(n) != nil {
			t.Errorf("flag %q registered on flag.CommandLine at import time", n)
		}
	}
}
