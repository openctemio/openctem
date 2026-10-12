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
	if (MCPSettings{}).RefreshLimitDays() != 90 || (MCPSettings{RefreshDays: 7}).RefreshLimitDays() != 7 {
		t.Error("refresh limit")
	}
}

func TestMCPSettingsIsASection(t *testing.T) {
	if !IsSettingsSection(SectionMCP) {
		t.Fatal("mcp is not a typed settings section")
	}
}
