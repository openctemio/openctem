package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type memStore struct {
	mu   sync.Mutex
	m    map[string]string
	fail bool
	ttls []time.Duration
}

func (s *memStore) SetNX(_ context.Context, k, v string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttls = append(s.ttls, ttl)
	if s.fail {
		return false, errors.New("down")
	}
	if _, ok := s.m[k]; ok {
		return false, nil
	}
	s.m[k] = v
	return true, nil
}
func (s *memStore) Get(_ context.Context, k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}
func (s *memStore) Set(_ context.Context, k, v string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}
func (s *memStore) Del(_ context.Context, ks ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range ks {
		delete(s.m, k)
	}
	return nil
}

func idemCall(h *CIRunnerHandler, tenant, run, key, body string, status int, calls *int) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	upload := func(w http.ResponseWriter, _ *http.Request) {
		*calls++
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"n":` + string(rune('0'+*calls)) + `}`))
	}
	if !h.idempotentUpload(w, r, tenant, run, upload) {
		upload(w, r)
	}
	return w
}

func TestIdempotentUploadReplaysTheFirstAnswerWithoutIngestingAgain(t *testing.T) {
	h := NewCIRunnerHandler(nil, logger.NewNop())
	h.SetIdempotencyStore(&memStore{m: map[string]string{}})
	calls := 0
	first := idemCall(h, "t1", "r1", "k1", `{"a":1}`, 201, &calls)
	retry := idemCall(h, "t1", "r1", "k1", `{"a":1}`, 201, &calls)
	if calls != 1 {
		t.Fatalf("ingested %d times, want 1", calls)
	}
	if retry.Code != 201 || retry.Body.String() != first.Body.String() || retry.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("retry = %d %q %v", retry.Code, retry.Body.String(), retry.Header())
	}
}

func TestIdempotentUploadKeyIsScopedToTenantAndRun(t *testing.T) {
	h := NewCIRunnerHandler(nil, logger.NewNop())
	h.SetIdempotencyStore(&memStore{m: map[string]string{}})
	calls := 0
	idemCall(h, "t1", "r1", "k", `{}`, 201, &calls)
	idemCall(h, "t2", "r1", "k", `{}`, 201, &calls) // another tenant
	idemCall(h, "t1", "r2", "k", `{}`, 201, &calls) // another run
	if calls != 3 {
		t.Fatalf("calls = %d, want 3: a key must never replay across tenants or runs", calls)
	}
}

func TestIdempotentUploadSameKeyOtherBodyIsRefused(t *testing.T) {
	h := NewCIRunnerHandler(nil, logger.NewNop())
	h.SetIdempotencyStore(&memStore{m: map[string]string{}})
	calls := 0
	idemCall(h, "t", "r", "k", `{"a":1}`, 201, &calls)
	w := idemCall(h, "t", "r", "k", `{"a":2}`, 201, &calls)
	if w.Code != http.StatusUnprocessableEntity || calls != 1 {
		t.Fatalf("code=%d calls=%d", w.Code, calls)
	}
}

func TestIdempotentUploadFailureReleasesTheKey(t *testing.T) {
	h := NewCIRunnerHandler(nil, logger.NewNop())
	h.SetIdempotencyStore(&memStore{m: map[string]string{}})
	calls := 0
	idemCall(h, "t", "r", "k", `{}`, 500, &calls)
	w := idemCall(h, "t", "r", "k", `{}`, 201, &calls)
	if calls != 2 || w.Code != 201 {
		t.Fatalf("a failed first attempt blocked its retry: calls=%d code=%d", calls, w.Code)
	}
}

func TestIdempotentUploadInFlightIsConflict(t *testing.T) {
	h := NewCIRunnerHandler(nil, logger.NewNop())
	st := &memStore{m: map[string]string{}}
	h.SetIdempotencyStore(st)
	calls := 0
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	r.Header.Set("Idempotency-Key", "k")
	inner := httptest.NewRecorder()
	h.idempotentUpload(inner, r, "t", "r", func(http.ResponseWriter, *http.Request) {
		// While the first request runs, its retry arrives.
		w := idemCall(h, "t", "r", "k", `{}`, 201, &calls)
		if w.Code != http.StatusConflict || w.Header().Get("Retry-After") == "" || calls != 0 {
			t.Errorf("in-flight retry: code=%d calls=%d", w.Code, calls)
		}
	})
}

func TestIdempotentUploadWithoutStoreOrKeyOrOnStoreErrorStillUploads(t *testing.T) {
	calls := 0
	h := NewCIRunnerHandler(nil, logger.NewNop())
	idemCall(h, "t", "r", "k", `{}`, 201, &calls) // no store
	h.SetIdempotencyStore(&memStore{m: map[string]string{}})
	idemCall(h, "t", "r", "", `{}`, 201, &calls) // no key
	h.SetIdempotencyStore(&memStore{m: map[string]string{}, fail: true})
	idemCall(h, "t", "r", "k", `{}`, 201, &calls) // store down
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestIdempotentUploadRejectsBadKey(t *testing.T) {
	h := NewCIRunnerHandler(nil, logger.NewNop())
	h.SetIdempotencyStore(&memStore{m: map[string]string{}})
	calls := 0
	for _, k := range []string{strings.Repeat("a", 129), "has space", "tab\tkey"} {
		if w := idemCall(h, "t", "r", k, `{}`, 201, &calls); w.Code != http.StatusBadRequest {
			t.Fatalf("key %q: code %d", k, w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("bad key reached the upload")
	}
}

func TestIdempotentUploadSameKeyAndBodyUnderAnotherRunTokenDoesNotReplay(t *testing.T) {
	h := NewCIRunnerHandler(nil, logger.NewNop())
	h.SetIdempotencyStore(&memStore{m: map[string]string{}})
	calls := 0
	idemCall(h, "t", "run-of-token-1", "k", `{"a":1}`, 201, &calls)
	w := idemCall(h, "t", "run-of-token-2", "k", `{"a":1}`, 201, &calls)
	if calls != 2 || w.Header().Get("Idempotent-Replayed") != "" {
		t.Fatalf("a key replayed under another run's token: calls=%d", calls)
	}
}

func TestIdempotentPendingMarkerLivesAtLeastTheTokenLife(t *testing.T) {
	h := NewCIRunnerHandler(nil, logger.NewNop())
	st := &memStore{m: map[string]string{}}
	h.SetIdempotencyStore(st)
	calls := 0
	idemCall(h, "t", "r", "k", `{}`, 201, &calls)
	if len(st.ttls) != 1 || st.ttls[0] < cirun.TokenTTL {
		t.Fatalf("pending ttl = %v, want >= %v", st.ttls, cirun.TokenTTL)
	}
	// A later request deadline extends it.
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	r.Header.Set("Idempotency-Key", "k2")
	ctx, cancel := context.WithTimeout(r.Context(), time.Hour)
	defer cancel()
	h.idempotentUpload(httptest.NewRecorder(), r.WithContext(ctx), "t", "r", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	if got := st.ttls[1]; got < 59*time.Minute {
		t.Fatalf("pending ttl with a 1h deadline = %v", got)
	}
}

func TestIdempotentUploadDoesNotTouchAKeyAnotherBodyOwns(t *testing.T) {
	h := NewCIRunnerHandler(nil, logger.NewNop())
	st := &memStore{m: map[string]string{}}
	h.SetIdempotencyStore(st)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"a":1}`))
	r.Header.Set("Idempotency-Key", "k")
	h.idempotentUpload(httptest.NewRecorder(), r, "t", "r", func(w http.ResponseWriter, _ *http.Request) {
		// The marker expired and a request with another body took the key.
		for k := range st.m {
			st.m[k] = `{"state":"pending","body_sha":"someone-else"}`
		}
		w.WriteHeader(201)
	})
	for _, v := range st.m {
		if !strings.Contains(v, "someone-else") {
			t.Fatalf("record of another request was overwritten: %s", v)
		}
	}
	if len(st.m) != 1 {
		t.Fatalf("the other request's record was deleted")
	}
}
