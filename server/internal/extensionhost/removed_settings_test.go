package extensionhost

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/config"
	ext "github.com/openctemio/openctem/server/pkg/extension"
)

func TestRemovedSettingsRefuseCommunity(t *testing.T) {
	env := map[string]string{"ADMIN_AUDIT_SINK": "https://siem.example.test/hook"}
	get := func(k string) string { return env[k] }
	for _, s := range []*Set{nil, build(t)} {
		err := s.CheckRemovedSettings(get)
		if err == nil || !strings.Contains(err.Error(), "ADMIN_AUDIT_SINK") || strings.Contains(err.Error(), "siem.example.test") {
			t.Fatalf("Community with a sink set: %v (must refuse and never repeat the value)", err)
		}
	}
	if err := build(t).CheckRemovedSettings(func(string) string { return "" }); err != nil {
		t.Fatalf("nothing set: %v", err)
	}
}

func TestRemovedSettingsDeclaredByAnExtension(t *testing.T) {
	s := build(t, ext.Extension{ConfigKeys: append([]string(nil), removedSettings...)})
	if err := s.CheckRemovedSettings(func(string) string { return "x" }); err != nil {
		t.Fatalf("a build whose extension declares the settings: %v", err)
	}
	other := build(t, ext.Extension{ConfigKeys: []string{"ADMIN_AUDIT_SINK"}})
	if err := other.CheckRemovedSettings(func(k string) string {
		if k == "ADMIN_AUDIT_SINK_SECRET" {
			return "x"
		}
		return ""
	}); err == nil {
		t.Fatal("a setting no extension declares must still refuse")
	}
}

// A removed setting is no longer a core setting, so an extension may
// declare it.
func TestRemovedSettingsAreNotCoreSettings(t *testing.T) {
	reg := config.Registry()
	for _, k := range removedSettings {
		if _, core := reg.Lookup(k); core {
			t.Errorf("%s is still in the core settings registry", k)
		}
	}
}

// The keys the server hands the start-up environment check (counted as read)
// are exactly the ones CheckRemovedSettings accepts as provided: one source.
// A removed setting no extension declares is in neither, so it is still
// refused at start.
func TestConfigKeysMatchDeclares(t *testing.T) {
	var none *Set
	if none.ConfigKeys() != nil || build(t).ConfigKeys() != nil {
		t.Fatal("Community has no extension config keys")
	}
	s := build(t,
		ext.Extension{Name: "one", ConfigKeys: []string{"ADMIN_AUDIT_SINK"}},
		ext.Extension{Name: "two", ConfigKeys: []string{"TWO_ENDPOINT"}})
	keys := s.ConfigKeys()
	if len(keys) != 2 {
		t.Fatalf("ConfigKeys = %v, want both extensions' keys", keys)
	}
	for _, k := range keys {
		if !s.Declares(k) {
			t.Errorf("ConfigKeys lists %s but Declares says no", k)
		}
	}
	if s.Declares("ADMIN_AUDIT_SINK_SECRET") {
		t.Fatal("an undeclared key is declared")
	}
	if err := s.CheckRemovedSettings(func(k string) string {
		if k == "ADMIN_AUDIT_SINK_SECRET" {
			return "x"
		}
		return ""
	}); err == nil {
		t.Fatal("an undeclared removed setting must still refuse the start")
	}
}
