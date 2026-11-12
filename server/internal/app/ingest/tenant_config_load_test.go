package ingest

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type failingTenantRepo struct{ tenant.Repository }

func (failingTenantRepo) GetByID(context.Context, shared.ID) (*tenant.Tenant, error) {
	return nil, errors.New("connection refused")
}

// When the tenant cannot be loaded, ingest keeps the platform defaults and
// says so; it does not drop the organization's rules silently.
func TestLoadTenantIngestConfig_LogsWhenTenantUnavailable(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New(logger.Config{Level: "debug", Format: "json", Output: &buf})
	s := &Service{tenantRepo: failingTenantRepo{}, logger: log}
	tid := shared.NewID()

	_, cfg, _ := s.loadTenantIngestConfig(context.Background(), tid)
	if cfg != nil {
		t.Fatal("defaults expected when the tenant cannot be loaded")
	}
	out := buf.String()
	if !strings.Contains(out, "tenant settings not loaded") || !strings.Contains(out, tid.String()) {
		t.Fatalf("no warning with the tenant id: %q", out)
	}
}
