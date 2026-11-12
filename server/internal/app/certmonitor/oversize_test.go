package certmonitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An endless answer ends at the cap: the read stops, nothing is raised.
func TestMonitorTenant_EndlessBodyRaisesNothing(t *testing.T) {
	tenant := shared.NewID()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name_value":"a.example.com","not_after":"2030-01-01T00:00:00"}`))
		chunk := []byte(strings.Repeat(",{\"name_value\":\"x.example.com\"}", 64))
		for r.Context().Err() == nil {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	expRepo := newFakeExposureRepo()
	svc := newTestService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}, expRepo, srv.URL)
	svc.setHTTPClient(srv.Client())
	svc.source.(*httpSource).bodyLimit = 64 << 10

	done := make(chan struct{})
	go func() {
		_, _ = svc.MonitorTenant(context.Background(), tenant)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("an endless CT answer was read without bound")
	}
	if len(expRepo.byKey) != 0 {
		t.Fatalf("raised %d exposures from an oversized answer", len(expRepo.byKey))
	}
}
