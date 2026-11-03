package extension_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/openctemio/openctem/api/pkg/extension"
	"github.com/openctemio/openctem/api/pkg/extension/example"
)

func reset(t *testing.T) {
	t.Helper()
	extension.ResetForTesting()
	t.Cleanup(extension.ResetForTesting)
}

func mustPanic(t *testing.T, want string, f func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("did not panic")
		}
		if !strings.Contains(r.(string), want) {
			t.Fatalf("panic %q does not mention %q", r, want)
		}
	}()
	f()
}

func TestCommunityHasNoExtension(t *testing.T) {
	reset(t)
	if extension.Name() != extension.Community {
		t.Fatalf("Name() = %q", extension.Name())
	}
	if _, ok := extension.Registered(); ok {
		t.Fatal("Community build has a registration")
	}
}

// The example extension, written only against the public API, registers.
func TestExampleRegisters(t *testing.T) {
	reset(t)
	extension.Register(example.Extension())
	e, ok := extension.Registered()
	if !ok || e.Name != "example" || extension.Name() != "example" || e.Schema != "example_ext" {
		t.Fatalf("registered %+v", e)
	}
	// The copy handed out cannot change the registration.
	e.ConfigKeys[0] = "CHANGED"
	if again, _ := extension.Registered(); again.ConfigKeys[0] != example.ConfigGrantAll {
		t.Fatal("Registered returned shared state")
	}
}

// An extension written for another API version must stop the build's first
// start, naming both versions.
func TestRegisterRefusesAnotherAPIVersion(t *testing.T) {
	for _, v := range []int{0, extension.APIVersion + 1, extension.APIVersion - 1} {
		reset(t)
		e := example.Extension()
		e.APIVersion = v
		mustPanic(t, "extension API", func() { extension.Register(e) })
		if extension.Name() != extension.Community {
			t.Fatal("a refused extension stayed registered")
		}
	}
}

func TestRegisterRefusesInvalidFields(t *testing.T) {
	ok := func() extension.Extension {
		return extension.Extension{APIVersion: extension.APIVersion, Name: "custom"}
	}
	cases := map[string]func(*extension.Extension){
		"empty name":         func(e *extension.Extension) { e.Name = "" },
		"community name":     func(e *extension.Extension) { e.Name = extension.Community },
		"upper-case name":    func(e *extension.Extension) { e.Name = "Custom" },
		"core schema public": func(e *extension.Extension) { e.Schema = "public" },
		"pg_ schema":         func(e *extension.Extension) { e.Schema = "pg_temp" },
		"information_schema": func(e *extension.Extension) { e.Schema = "information_schema" },
		"quoted schema":      func(e *extension.Extension) { e.Schema = `x"; drop` },
		"migrations no schema": func(e *extension.Extension) {
			e.Migrations = fstest.MapFS{"20261103120000_a.up.sql": {}, "20261103120000_a.down.sql": {}}
		},
		"bad config key":      func(e *extension.Extension) { e.ConfigKeys = []string{"lower_case"} },
		"repeated config key": func(e *extension.Extension) { e.ConfigKeys = []string{"A_B", "A_B"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			reset(t)
			e := ok()
			mutate(&e)
			defer func() {
				if recover() == nil {
					t.Fatal("Register accepted it")
				}
			}()
			extension.Register(e)
		})
	}
}

func TestRegisterRefusesASecondExtension(t *testing.T) {
	reset(t)
	extension.Register(extension.Extension{APIVersion: extension.APIVersion, Name: "one"})
	mustPanic(t, "registered after", func() {
		extension.Register(extension.Extension{APIVersion: extension.APIVersion, Name: "two"})
	})
	if extension.Name() != "one" {
		t.Fatalf("Name() = %q", extension.Name())
	}
}

func TestValidateMigrations(t *testing.T) {
	good := fstest.MapFS{
		"20261103120000_a.up.sql": {}, "20261103120000_a.down.sql": {},
		"20261103130000_b.up.sql": {}, "20261103130000_b.down.sql": {},
	}
	if err := extension.ValidateMigrations(good); err != nil {
		t.Fatalf("good set: %v", err)
	}
	if err := extension.ValidateMigrations(example.Migrations()); err != nil {
		t.Fatalf("example set: %v", err)
	}
	for name, m := range map[string]fstest.MapFS{
		"empty":           {},
		"no down":         {"20261103120000_a.up.sql": {}},
		"short version":   {"000001_a.up.sql": {}, "000001_a.down.sql": {}},
		"other file":      {"20261103120000_a.up.sql": {}, "20261103120000_a.down.sql": {}, "README.md": {}},
		"version twice":   {"20261103120000_a.up.sql": {}, "20261103120000_a.down.sql": {}, "20261103120000_b.up.sql": {}, "20261103120000_b.down.sql": {}},
		"sub directory":   {"x/20261103120000_a.up.sql": {}},
		"upper-case name": {"20261103120000_A.up.sql": {}, "20261103120000_A.down.sql": {}},
	} {
		if err := extension.ValidateMigrations(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
