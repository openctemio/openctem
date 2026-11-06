package certmonitor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeTenantSettings struct {
	es  map[string]tenant.EASMSettings
	err error
}

func (f fakeTenantSettings) GetEASMSettings(_ context.Context, id string) (*tenant.EASMSettings, error) {
	if f.err != nil {
		return nil, f.err
	}
	es := f.es[id]
	return &es, nil
}

// research/22 P0-11 (E8): a tenant that turned CT off sends nothing to the
// CT source; an unreadable setting skips the tenant too (fail closed);
// another tenant is unaffected.
func TestMonitorTenant_TenantSwitch(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	off, on := shared.NewID(), shared.NewID()
	mk := func(tn shared.ID, ts TenantSettingsReader) *Service {
		svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tn, "listed.com")}}, newFakeExposureRepo(), srv.URL, testLogger())
		svc.setHTTPClient(srv.Client())
		svc.SetTenantSettings(ts)
		return svc
	}
	ts := fakeTenantSettings{es: map[string]tenant.EASMSettings{off.String(): {CTDisabled: true}}}
	if _, err := mk(off, ts).MonitorTenant(context.Background(), off); err != nil || hits.Load() != 0 {
		t.Fatalf("CT ran for a tenant that turned it off: hits=%d err=%v", hits.Load(), err)
	}
	if _, err := mk(off, fakeTenantSettings{err: errors.New("db down")}).MonitorTenant(context.Background(), off); err != nil || hits.Load() != 0 {
		t.Fatalf("CT ran with unreadable settings: hits=%d", hits.Load())
	}
	if _, err := mk(on, ts).MonitorTenant(context.Background(), on); err != nil || hits.Load() == 0 {
		t.Fatalf("CT did not run for a tenant with it on: hits=%d err=%v", hits.Load(), err)
	}
}

func TestRecheckFor(t *testing.T) {
	if RecheckFor(0, 20*time.Hour) != 20*time.Hour || RecheckFor(6, time.Hour) != 5*time.Hour+30*time.Minute {
		t.Fatal("RecheckFor")
	}
}
