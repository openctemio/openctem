package main

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/extension"
)

func TestCheckExtensionOnlyEnv(t *testing.T) {
	env := map[string]string{"ADMIN_AUDIT_SINK": "https://siem.example.test/hook"}
	get := func(k string) string { return env[k] }
	err := checkExtensionOnlyEnv(get, extension.Community)
	if err == nil || !strings.Contains(err.Error(), "ADMIN_AUDIT_SINK") || strings.Contains(err.Error(), "siem.example.test") {
		t.Fatalf("Community with a sink set: %v (must refuse and never repeat the value)", err)
	}
	if err := checkExtensionOnlyEnv(get, "extended"); err != nil {
		t.Fatalf("an extension build handles its own settings: %v", err)
	}
	if err := checkExtensionOnlyEnv(func(string) string { return "" }, extension.Community); err != nil {
		t.Fatalf("nothing set: %v", err)
	}
}
