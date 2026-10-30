package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type memoMarker struct{}

// memoAsserter records that the guard asked it for a request memo and sees
// the memo in its own checks.
type memoAsserter struct {
	fakeAsserter
	sawMemo *bool
}

func (m memoAsserter) WithRequestMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, memoMarker{}, true)
}

func (m memoAsserter) AssertFinding(ctx context.Context, t, id shared.ID) error {
	*m.sawMemo = ctx.Value(memoMarker{}) != nil
	return m.fakeAsserter.AssertFinding(ctx, t, id)
}

func TestDataScopeGuard_InstallsRequestMemo(t *testing.T) {
	var guardSaw bool
	hidden := shared.NewID()
	a := memoAsserter{fakeAsserter: fakeAsserter{deny: map[shared.ID]bool{hidden: true}}, sawMemo: &guardSaw}
	var handlerSaw bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerSaw = r.Context().Value(memoMarker{}) != nil
		w.WriteHeader(http.StatusTeapot)
	})
	h := DataScopeGuard(a)(next)

	for _, path := range []string{"/api/v1/findings/" + shared.NewID().String() + "/comments", "/api/v1/findings/stats"} {
		guardSaw, handlerSaw = false, false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, withTenant(httptest.NewRequest(http.MethodGet, path, nil)))
		if rec.Code != http.StatusTeapot || !handlerSaw {
			t.Fatalf("%s: code %d, handler saw memo %v", path, rec.Code, handlerSaw)
		}
	}
	// The guard's own check runs on the memo context too.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+shared.NewID().String(), nil)))
	if !guardSaw {
		t.Fatal("guard check did not run with the request memo")
	}
	// A refusal still refuses.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+hidden.String(), nil)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope finding = %d, want 404", rec.Code)
	}
}
