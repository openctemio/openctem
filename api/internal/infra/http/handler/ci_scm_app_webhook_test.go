package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	scmappsvc "github.com/openctemio/openctem/api/internal/app/scmapp"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeSCMAppWebhook struct {
	SCMAppService // only the webhook methods are called
	applied       int
}

func (f *fakeSCMAppWebhook) VerifyGitHubWebhook(_ []byte, sig string) error {
	if sig != "good" {
		return scmappsvc.ErrBadSignature
	}
	return nil
}

func (f *fakeSCMAppWebhook) HandleGitHubWebhook(context.Context, string, string, []byte) error {
	f.applied++
	return nil
}

func appDelivery(sig, delivery string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/github-app",
		strings.NewReader(`{"action":"suspend","installation":{"id":7}}`))
	r.Header.Set("X-GitHub-Event", "installation")
	r.Header.Set("X-Hub-Signature-256", sig)
	if delivery != "" {
		r.Header.Set("X-GitHub-Delivery", delivery)
	}
	return r
}

// A captured, validly signed delivery (a suspend, an unsuspend) must not be
// applied twice; the guard runs only after the signature is verified, so an
// unsigned request cannot burn a delivery id.
func TestGitHubAppWebhookRefusesReplays(t *testing.T) {
	svc := &fakeSCMAppWebhook{}
	deliveries := &memoryDeliveries{seen: map[string]bool{}}
	h := NewSCMAppHandler(svc, logger.NewNop())
	h.SetDeliveryGuard(deliveries)

	send := func(r *http.Request) int {
		rec := httptest.NewRecorder()
		h.GitHubWebhook(rec, r)
		return rec.Code
	}
	if c := send(appDelivery("bad", "d-1")); c != http.StatusUnauthorized || len(deliveries.seen) != 0 {
		t.Fatalf("bad signature: %d, recorded %v", c, deliveries.seen)
	}
	if c := send(appDelivery("good", "d-1")); c != http.StatusNoContent || svc.applied != 1 {
		t.Fatalf("first delivery: %d applied %d", c, svc.applied)
	}
	if c := send(appDelivery("good", "d-1")); c != http.StatusNoContent || svc.applied != 1 {
		t.Fatalf("replay applied: %d applied %d", c, svc.applied)
	}
	if !deliveries.seen["ghapp:d-1"] {
		t.Fatalf("delivery key = %v", deliveries.seen)
	}
	if c := send(appDelivery("good", "")); c != http.StatusBadRequest || svc.applied != 1 {
		t.Fatalf("no delivery id: %d", c)
	}
	if c := send(appDelivery("good", "d-2")); c != http.StatusNoContent || svc.applied != 2 {
		t.Fatalf("next delivery: %d applied %d", c, svc.applied)
	}
	deliveries.err = errors.New("redis down")
	if c := send(appDelivery("good", "d-3")); c != http.StatusServiceUnavailable || svc.applied != 2 {
		t.Fatalf("store down must fail closed: %d applied %d", c, svc.applied)
	}
}
