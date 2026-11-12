package server

import (
	"flag"
	"testing"
)

func TestDefineFlagsNames(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	defineFlags(fs)
	for _, n := range []string{"routes", "route-format", "route-method", "route-path", "route-sort",
		"check-config", "sensor-upgrade-check", "healthcheck", "version", "signer-ledger-export"} {
		if fs.Lookup(n) == nil {
			t.Errorf("flag %q not defined", n)
		}
	}
	if err := fs.Parse([]string{"-version", "-route-format", "json"}); err != nil {
		t.Fatal(err)
	}
	if !*showVersion || *routeFormat != "json" {
		t.Fatalf("flags not bound to package vars: version=%v format=%q", *showVersion, *routeFormat)
	}
}

func TestImportRegistersNothingGlobally(t *testing.T) {
	if flag.Lookup("routes") != nil || flag.Lookup("version") != nil {
		t.Fatal("server flags leaked onto flag.CommandLine")
	}
}
