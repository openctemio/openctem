package extension_test

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/openctemio/openctem/server/pkg/extension"
	"github.com/openctemio/openctem/server/pkg/extension/example"
	"github.com/openctemio/openctem/server/pkg/version"
)

func ok(name string) extension.Extension {
	return extension.Extension{APIVersion: extension.APIVersion, Name: name}
}

func noGrants(context.Context, extension.Deps) (extension.GrantProvider, error) { return nil, nil }

func TestAPIVersionMirroredInVersion(t *testing.T) {
	if extension.APIVersion != version.ExtensionAPI {
		t.Fatalf("pkg/version.ExtensionAPI = %d, want %d", version.ExtensionAPI, extension.APIVersion)
	}
	if extension.APIVersion != 1 {
		t.Fatal("the extension API stays at version 1 until the core's 1.0 release")
	}
}

func TestCommunityBuildIsValid(t *testing.T) {
	if err := extension.ValidateBuild(nil); err != nil {
		t.Fatal(err)
	}
}

func TestExampleIsValid(t *testing.T) {
	if err := extension.ValidateBuild([]extension.Extension{example.Extension()}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRefusesAnotherAPIVersion(t *testing.T) {
	for _, v := range []int{0, extension.APIVersion + 1, extension.APIVersion - 1} {
		e := example.Extension()
		e.APIVersion = v
		if err := e.Validate(); err == nil || !strings.Contains(err.Error(), "extension API") {
			t.Fatalf("API version %d: %v", v, err)
		}
	}
}

func TestValidateRefusesInvalidFields(t *testing.T) {
	cases := map[string]func(*extension.Extension){
		"empty name":          func(e *extension.Extension) { e.Name = "" },
		"upper-case name":     func(e *extension.Extension) { e.Name = "Custom" },
		"long name":           func(e *extension.Extension) { e.Name = strings.Repeat("a", 33) },
		"version with space":  func(e *extension.Extension) { e.Version = "v1 beta" },
		"core schema public":  func(e *extension.Extension) { e.Schema = "public" },
		"pg_ schema":          func(e *extension.Extension) { e.Schema = "pg_temp" },
		"information_schema":  func(e *extension.Extension) { e.Schema = "information_schema" },
		"extensions schema":   func(e *extension.Extension) { e.Schema = "extensions" },
		"quoted schema":       func(e *extension.Extension) { e.Schema = `x"; drop` },
		"bad config key":      func(e *extension.Extension) { e.ConfigKeys = []string{"lower_case"} },
		"repeated config key": func(e *extension.Extension) { e.ConfigKeys = []string{"A_B", "A_B"} },
		"migrations no schema": func(e *extension.Extension) {
			e.Migrations = fstest.MapFS{"20261103120000_a.up.sql": {}, "20261103120000_a.down.sql": {}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := ok("custom")
			mutate(&e)
			if e.Validate() == nil {
				t.Fatal("accepted")
			}
			if extension.ValidateBuild([]extension.Extension{e}) == nil {
				t.Fatal("build accepted")
			}
		})
	}
}

func TestValidateBuildAcceptsSeveralExtensions(t *testing.T) {
	a, b := ok("one"), ok("two")
	a.Schema, b.Schema = "one_ext", "two_ext"
	a.ConfigKeys, b.ConfigKeys = []string{"ONE_X"}, []string{"TWO_X"}
	if err := extension.ValidateBuild([]extension.Extension{a, b, example.Extension()}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateBuildRefusesClashes(t *testing.T) {
	cases := map[string]func(a, b *extension.Extension){
		"same name":           func(a, b *extension.Extension) { b.Name = a.Name },
		"same schema":         func(a, b *extension.Extension) { a.Schema, b.Schema = "s_ext", "s_ext" },
		"same config key":     func(a, b *extension.Extension) { a.ConfigKeys, b.ConfigKeys = []string{"K"}, []string{"K"} },
		"two grant providers": func(a, b *extension.Extension) { a.Grants, b.Grants = noGrants, noGrants },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, b := ok("one"), ok("two")
			mutate(&a, &b)
			if err := extension.ValidateBuild([]extension.Extension{a, b}); err == nil {
				t.Fatal("accepted")
			}
		})
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
