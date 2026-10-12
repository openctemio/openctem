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

// The SBOM, asset CSV and campaign import routes declare their own body
// limit, which replaces the global 10 MiB one: before, every file between
// 10 MiB and the documented limit was refused. The permission gate still runs
// first, so a caller without it is refused before any byte is read.
func TestImportRoutes_BodyLimitOverridesGlobal(t *testing.T) {
	rl := func() *middleware.RateLimiter {
		return middleware.NewRateLimiter(&config.RateLimitConfig{Enabled: true, RequestsPerSec: 100, Burst: 100, CleanupInterval: time.Minute}, nil)
	}
	cases := []struct {
		name  string
		limit int64
		perms []string
		chain []Middleware // the chain the route registration declares
	}{
		{
			name:  "components/import",
			limit: handler.MaxSBOMImportBody,
			perms: []string{permission.ComponentsWrite.String()},
			chain: []Middleware{middleware.Require(permission.ComponentsWrite), rl().Middleware(), middleware.BodyLimit(handler.MaxSBOMImportBody)},
		},
		{
			name:  "assets/import/csv",
			limit: handler.MaxAssetCSVImportBody,
			perms: []string{permission.AssetsWrite.String(), permission.AssetsImport.String()},
			chain: []Middleware{middleware.RequireAll(permission.AssetsWrite, permission.AssetsImport), rl().Middleware(), middleware.BodyLimit(handler.MaxAssetCSVImportBody)},
		},
		{
			name:  "pentest findings import",
			limit: handler.MaxPentestImportBody,
			perms: []string{permission.PentestFindingsWrite.String()},
			chain: []Middleware{middleware.Require(permission.PentestFindingsWrite), middleware.BodyLimit(handler.MaxPentestImportBody)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var read int64
			inner := chainHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n, err := new(bytes.Buffer).ReadFrom(r.Body)
				read = n
				if err != nil {
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					return
				}
				w.WriteHeader(http.StatusOK)
			}), tc.chain)
			h := middleware.BodyLimit(middleware.DefaultMaxBodySize)(inner) // the global limit

			send := func(size int64, perms []string) int {
				read = 0
				r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, size)))
				ctx := context.WithValue(r.Context(), middleware.TenantIDKey, "tenant-1")
				ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, perms)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r.WithContext(ctx))
				return rec.Code
			}

			over10 := int64(middleware.DefaultMaxBodySize + 1<<20)
			if code := send(over10, tc.perms); code != http.StatusOK || read != over10 {
				t.Fatalf("an 11 MiB upload was refused: code=%d read=%d", code, read)
			}
			if code := send(tc.limit, tc.perms); code != http.StatusOK {
				t.Fatalf("an upload at the limit was refused: code=%d", code)
			}
			if code := send(tc.limit+1, tc.perms); code != http.StatusRequestEntityTooLarge {
				t.Fatalf("an upload over %d bytes was accepted: code=%d", tc.limit, code)
			}
			if code := send(over10, nil); code != http.StatusForbidden || read != 0 {
				t.Fatalf("a caller without the permission got code=%d after reading %d bytes", code, read)
			}
		})
	}
}
