package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type recordingDNS struct {
	dangling, email []shared.ID
	err             error
}

func (r *recordingDNS) MonitorTenant(_ context.Context, id shared.ID) (easmdns.RunResult, error) {
	r.dangling = append(r.dangling, id)
	return easmdns.RunResult{}, r.err
}

func (r *recordingDNS) MonitorEmail(_ context.Context, id shared.ID) (easmdns.RunResult, error) {
	r.email = append(r.email, id)
	return easmdns.RunResult{}, r.err
}

// research/22 P0-8: the DNS checks run for a tenant right after its CT
// sweep, both kinds, and a DNS failure never stops the sweep.
func TestCertMonitorController_DNSFollowUp(t *testing.T) {
	dns := &recordingDNS{}
	c := NewCertMonitorController(nil, nil, &CertMonitorControllerConfig{DNSFollowUp: dns})
	tenant := shared.NewID()
	c.followUpDNS(context.Background(), tenant)
	if len(dns.dangling) != 1 || dns.dangling[0] != tenant || len(dns.email) != 1 || dns.email[0] != tenant {
		t.Fatalf("follow-up = %+v", dns)
	}
	dns.err = errors.New("resolver down")
	c.followUpDNS(context.Background(), tenant) // logged, no panic
	if len(dns.email) != 2 {
		t.Fatal("email check skipped after a dangling-check failure")
	}
	NewCertMonitorController(nil, nil, nil).followUpDNS(context.Background(), tenant) // no follow-up wired
}
