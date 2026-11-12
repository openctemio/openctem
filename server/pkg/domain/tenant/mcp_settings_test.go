package tenant

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMCPSettingsValidate(t *testing.T) {
	s := MCPSettings{ClientHosts: []string{" Assistant.Example ", "assistant.example", "ide.example.org"}, Scopes: []string{"mcp:findings.read"}, RefreshDays: 30}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.ClientHosts, []string{"assistant.example", "ide.example.org"}) {
		t.Fatalf("hosts not normalized: %v", s.ClientHosts)
	}
	for name, bad := range map[string]MCPSettings{
		"scheme":       {ClientHosts: []string{"https://a.example"}},
		"wildcard":     {ClientHosts: []string{"*.example.com"}},
		"path":         {ClientHosts: []string{"a.example/x"}},
		"single label": {ClientHosts: []string{"localhost"}},
		"too many":     {ClientHosts: strings.Split(strings.Repeat("a.example,", MaxMCPClientHosts+1), ",")[:MaxMCPClientHosts+1]},
		"scope shape":  {Scopes: []string{"findings:read"}},
		"refresh>90":   {RefreshDays: 91},
		"refresh<0":    {RefreshDays: -1},
	} {
		if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s accepted", name)
		}
	}
	// The comment-adding write scope can be allowed (its name is not
	// "<area>.read" or "<area>.write").
	if err := (&MCPSettings{Scopes: []string{"mcp:findings.read", "mcp:findings.comment"}}).Validate(); err != nil {
		t.Errorf("comment scope refused: %v", err)
	}
	if (MCPSettings{}).RefreshLimitDays() != 90 || (MCPSettings{RefreshDays: 7}).RefreshLimitDays() != 7 {
		t.Error("refresh limit")
	}
}

func TestMCPSettingsIsASection(t *testing.T) {
	if !IsSettingsSection(SectionMCP) {
		t.Fatal("mcp is not a typed settings section")
	}
}

func TestMCPSettingsMaxTLP(t *testing.T) {
	if got := (MCPSettings{}).AIMaxTLP(); got != "amber" {
		t.Fatalf("default limit = %q, want amber", got)
	}
	for _, v := range []string{"clear", "green", "amber", "amber_strict", "red"} {
		s := MCPSettings{MaxTLP: v}
		if err := s.Validate(); err != nil || s.AIMaxTLP() != v {
			t.Errorf("%s: %v %s", v, err, s.AIMaxTLP())
		}
	}
	for _, bad := range []string{"AMBER", "white", "amber+strict"} {
		s := MCPSettings{MaxTLP: bad}
		if err := s.Validate(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
