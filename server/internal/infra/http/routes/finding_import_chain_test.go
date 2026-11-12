package routes

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// The import route's own limit (110 MiB) applies under the global 10 MiB one,
// and only after the permission gate: a caller without the import
// permissions is refused before any of the body is read.
func TestFindingImportChain_BodyLimitOverridesGlobal(t *testing.T) {
	rl := middleware.NewRateLimiter(&config.RateLimitConfig{Enabled: true, RequestsPerSec: 100, Burst: 100, CleanupInterval: time.Minute}, nil)
	var read int
	inner := chainHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := new(bytes.Buffer).ReadFrom(r.Body)
		read = int(n)
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), []Middleware{ // the chain registerFindingImportRoutes declares
		middleware.RequireAll(permission.FindingsWrite, permission.AssetsWrite, permission.AssetsImport),
		rl.TenantMiddleware(),
		middleware.BodyLimit(handler.MaxFindingImportBody),
	})
	h := middleware.BodyLimit(middleware.DefaultMaxBodySize)(inner) // the global limit

	send := func(size int, perms []string) int {
		read = 0
		r := httptest.NewRequest(http.MethodPost, "/api/v1/findings/imports/", bytes.NewReader(make([]byte, size)))
		ctx := context.WithValue(r.Context(), middleware.TenantIDKey, "tenant-1")
		ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, perms)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r.WithContext(ctx))
		return rec.Code
	}
	all := []string{permission.FindingsWrite.String(), permission.AssetsWrite.String(), permission.AssetsImport.String()}

	over10 := middleware.DefaultMaxBodySize + 1<<20
	if code := send(over10, all); code != http.StatusOK || read != over10 {
		t.Fatalf("an 11 MiB import was refused: code=%d read=%d", code, read)
	}
	if code := send(handler.MaxFindingImportBody+1, all); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an import over %d bytes was accepted: code=%d", handler.MaxFindingImportBody, code)
	}
	if code := send(over10, all[:1]); code != http.StatusForbidden || read != 0 {
		t.Fatalf("a caller without assets:import got code=%d after reading %d bytes", code, read)
	}
}
