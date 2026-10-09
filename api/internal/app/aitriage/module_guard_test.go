package aitriage

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type aiTriageOff struct{}

func (aiTriageOff) TenantDisabledModules(context.Context, string) map[string]bool {
	return map[string]bool{"ai_triage": true}
}

// With the ai_triage module off, auto-triage never starts: it answers no
// before reading the organization settings (a nil repository here).
func TestShouldAutoTriage_ModuleOff(t *testing.T) {
	s := &AITriageService{platformCfg: config.AITriageConfig{Enabled: true}}
	s.SetModuleGuard(aiTriageOff{})
	ok, err := s.ShouldAutoTriage(context.Background(), shared.NewID(), "critical")
	if err != nil || ok {
		t.Fatalf("ShouldAutoTriage = %v, %v; want false, nil", ok, err)
	}
}
