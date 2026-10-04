package certmonitor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RFC-036 appendix T-4: a CT answer larger than the body cap is refused as a
// whole. Before, it was cut at the cap; a valid payload padded with trailing
// whitespace then parsed and its names were used, and a truncated body was
// handed to the parser.
func TestGet_RefusesOversizedBody(t *testing.T) {
	payload := ctPayload(time.Now().UTC())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload + strings.Repeat(" ", 4096)))
	}))
	defer srv.Close()

	svc := NewService(&fakeAssetRepo{}, newFakeExposureRepo(), srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	svc.maxBody = int64(len(payload) + 1024)

	if _, err := svc.get(context.Background(), srv.URL, "crt.sh"); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
	// Exactly at the cap is accepted.
	svc.maxBody = int64(len(payload) + 4096)
	if body, err := svc.get(context.Background(), srv.URL, "crt.sh"); err != nil || len(body) != len(payload)+4096 {
		t.Fatalf("at the cap: %d bytes, %v", len(body), err)
	}
}

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
	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}, expRepo, srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	svc.maxBody = 64 << 10

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
