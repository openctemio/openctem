package certmonitor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// recordingFetcher answers every CT request with body and records it.
type recordingFetcher struct {
	reqs []CTRequest
	body []byte
	err  error
}

func (f *recordingFetcher) FetchCT(_ context.Context, r CTRequest) ([]byte, error) {
	f.reqs = append(f.reqs, r)
	return f.body, f.err
}

// SECURITY (zero platform egress): without a platform sensor the sweep makes
// no CT request at all, changes no domain's state, and says why.
func TestMonitorTenant_NoPlatformSensorQueriesNothing(t *testing.T) {
	tenant := shared.NewID()
	assetRepo := &fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}
	expRepo := newFakeExposureRepo()
	svc := NewService(assetRepo, expRepo, "", testLogger())
	state := newMemState()
	svc.SetStateStore(state)
	if svc.Available() || svc.UnavailableReason() != ReasonNeedsPlatformSensor {
		t.Fatalf("available %t, reason %q", svc.Available(), svc.UnavailableReason())
	}
	n, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil || n != 0 || len(expRepo.byKey) != 0 {
		t.Fatalf("n %d, err %v, exposures %d", n, err, len(expRepo.byKey))
	}
	if st, err := state.ListStates(context.Background(), tenant); err != nil || len(st) != 0 {
		t.Fatalf("domain state changed: %v %v", st, err)
	}
	if _, err := svc.get(context.Background(), "https://crt.sh/?q=x", SourceCRTSH); !errors.Is(err, ErrNeedsPlatformSensor) {
		t.Fatalf("get without a fetcher: %v", err)
	}
}

// Every CT request goes through the fetcher, bounded, with the Cert Spotter
// key only on Cert Spotter requests; a body over the cap is refused whole.
func TestFetcherCarriesTheRequests(t *testing.T) {
	tenant := shared.NewID()
	assetRepo := &fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}
	svc := NewService(assetRepo, newFakeExposureRepo(), "", testLogger())
	svc.SetCertSpotterKey(" commercial-key ")
	f := &recordingFetcher{body: []byte(`[{"common_name":"a.example.com","name_value":"a.example.com"}]`)}
	svc.SetFetcher(f)
	svc.requestDelay, svc.noSleep = 0, true
	if !svc.Available() || svc.UnavailableReason() != "" {
		t.Fatal("a fetcher makes CT monitoring available")
	}
	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 1 {
		t.Fatalf("requests %+v", f.reqs)
	}
	r := f.reqs[0]
	if r.Source != SourceCRTSH || !strings.HasPrefix(r.URL, DefaultFeedBaseURL+"/?") || r.MaxBytes != maxBodyBytes ||
		r.Header.Get("Authorization") != "" || r.Header.Get("Accept") != "application/json" {
		t.Fatalf("crt.sh request %+v", r)
	}

	svc.SetCertSpotterFallback(DefaultCertSpotterBaseURL)
	f.body = []byte(`[]`)
	if _, err := svc.queryCertSpotter(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	cs := f.reqs[len(f.reqs)-1]
	if cs.Source != SourceCertSpotter || cs.Header.Get("Authorization") != "Bearer commercial-key" {
		t.Fatalf("Cert Spotter request %+v", cs)
	}

	svc.maxBody = 8
	f.body = []byte(`[0123456789]`)
	if _, err := svc.get(context.Background(), "https://crt.sh/?q=x", SourceCRTSH); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized body: %v", err)
	}
	// A fetcher's status error keeps its retry semantics.
	f.err = NewStatusError(SourceCRTSH, 429, "7")
	if _, err := svc.get(context.Background(), "https://crt.sh/?q=x", SourceCRTSH); !errors.Is(err, errRateLimited) {
		t.Fatalf("429: %v", err)
	}
}

// SECURITY (zero platform egress): the package's production code holds no
// HTTP client, dialer or SSRF-guarded client of its own; only tests do.
func TestNoOutboundClientInTheService(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"http.Client", "http.Get(", "http.DefaultClient", "net.Dial", "httpsec.", "tls.Dial"} {
			if strings.Contains(string(src), banned) {
				t.Errorf("%s uses %s: the platform must not reach a CT source itself", f, banned)
			}
		}
	}
}
