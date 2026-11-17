package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/diag"
)

func TestIsDiagCommand(t *testing.T) {
	for arg, want := range map[string]bool{
		"doctor": true, "support-bundle": true, "-doctor": false, "--doctor": false, "": false, "-check-config": false, "routes": false,
	} {
		if got := isDiagCommand(arg); got != want {
			t.Errorf("isDiagCommand(%q) = %v, want %v", arg, got, want)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{
		"20M": 20 << 20, "20m": 20 << 20, "20MB": 20 << 20, "20MiB": 20 << 20, "512K": 512 << 10, "1048576": 1 << 20, "200M": diag.MaxMaxSize,
	} {
		got, err := parseSize(in)
		if err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "-5M", "abc", "1K", "201M", "1G", "9999999999999G", "20 M B"} {
		if n, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) = %d, want an error", in, n)
		}
	}
}

// A wrong option is refused before anything is opened, and a configuration
// that does not load is a failed check with exit code 1, not a crash.
func TestRunDiagCommand_OptionsAndBrokenConfiguration(t *testing.T) {
	var out, errOut bytes.Buffer
	if rc := runDiagCommand(cmdDoctor, []string{"--bogus"}, nil, &out, &errOut); rc != 2 {
		t.Errorf("unknown option: exit code %d, want 2", rc)
	}
	if rc := runDiagCommand(cmdSupportBundle, []string{"extra"}, nil, &out, &errOut); rc != 2 {
		t.Errorf("stray argument: exit code %d, want 2", rc)
	}
	if rc := runDiagCommand(cmdSupportBundle, []string{"--max-size", "1"}, nil, &out, &errOut); rc != 2 {
		t.Errorf("--max-size 1: exit code %d, want 2", rc)
	}

	// A retired variable makes the configuration refuse to load.
	t.Setenv("APP_ENV", "production")
	t.Setenv("APP_ENCRYPTION_KEY", "")
	t.Setenv("DB_PASSWORD", "a-password-that-must-not-be-printed")
	out.Reset()
	errOut.Reset()
	rc := runDiagCommand(cmdDoctor, []string{"--offline"}, nil, &out, &errOut)
	if rc != 1 {
		t.Fatalf("doctor on a broken configuration: exit code %d, want 1\n%s%s", rc, out.String(), errOut.String())
	}
	table := out.String()
	for _, want := range []string{"STATUS", "FAIL", "Configuration", "fix:", "failed"} {
		if !strings.Contains(table, want) {
			t.Errorf("the table lacks %q:\n%s", want, table)
		}
	}
	if strings.Contains(table, "a-password-that-must-not-be-printed") {
		t.Error("the table prints a secret")
	}
}
