package integration

import (
	"context"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// gatedRoleRepo answers GetUserPermissions from perms. When gate is set, the
// next read takes the current perms, signals read, and returns them only
// after release is closed: a loader that read the database just before a
// revocation and writes the cache just after it.
type gatedRoleRepo struct {
	roledom.Repository
	mu      sync.Mutex
	perms   []string
	gate    bool
	read    chan struct{}
	release chan struct{}
}

func (r *gatedRoleRepo) set(perms ...string) {
	r.mu.Lock()
	r.perms = perms
	r.mu.Unlock()
}

func (r *gatedRoleRepo) GetUserPermissions(context.Context, roledom.ID, roledom.ID) ([]string, error) {
	r.mu.Lock()
	out := slices.Clone(r.perms)
	gated := r.gate
	r.gate = false
	r.mu.Unlock()
	if gated {
		close(r.read)
		<-r.release
	}
	return out, nil
}

func raceRedis(t *testing.T) *redis.Client {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set; skipping permission cache race test")
	}
	port := 6379
	if p := os.Getenv("REDIS_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("REDIS_PORT: %v", err)
		}
		port = n
	}
	rc, err := redis.New(&config.RedisConfig{
		Host: host, Port: port, PoolSize: 4,
		DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
		MaxRetries: 1, MinRetryDelay: 10 * time.Millisecond, MaxRetryDelay: 50 * time.Millisecond,
	}, logger.NewNop())
	if err != nil {
		t.Skipf("redis not available: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}

// A request that loaded the permission set from the database just before a
// revocation must not be able to write that old set back into the cache for
// the requests after the revocation. Before, the cache key had no version:
// the loader's write landed after the revocation's delete and the revoked
// permission kept working for up to the cache TTL (5 minutes).
func TestPermissionCache_LoaderRacingARevocationCannotResurrectIt(t *testing.T) {
	rc := raceRedis(t)
	ctx := context.Background()
	log := logger.NewNop()

	for name, priorVersion := range map[string]int{"first change": 0, "later change": 3} {
		t.Run(name, func(t *testing.T) {
			tenantID, userID := uuid.NewString(), uuid.NewString()
			repo := &gatedRoleRepo{perms: []string{"findings:write"}, gate: true,
				read: make(chan struct{}), release: make(chan struct{})}
			versions := accesscontrol.NewPermissionVersionService(rc, log)
			if priorVersion > 0 {
				if err := versions.Set(ctx, tenantID, userID, priorVersion); err != nil {
					t.Fatal(err)
				}
			}
			cache, err := accesscontrol.NewPermissionCacheService(rc, repo, versions, log)
			if err != nil {
				t.Fatal(err)
			}

			loaded := make(chan []string)
			go func() {
				perms, _ := cache.GetPermissionsWithFallback(ctx, tenantID, userID)
				loaded <- perms
			}()
			<-repo.read // the loader holds the pre-revocation set

			// The revocation, in the order the role and tenant services use.
			repo.set()
			cache.Invalidate(ctx, tenantID, userID)
			versions.Increment(ctx, tenantID, userID)

			close(repo.release) // the loader now writes its old set
			if old := <-loaded; !slices.Contains(old, "findings:write") {
				t.Fatalf("loader returned %v; the test needs it to hold the old set", old)
			}

			after, err := cache.GetPermissionsWithFallback(ctx, tenantID, userID)
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(after, "findings:write") {
				t.Fatalf("revoked permission still served after the revocation: %v", after)
			}
			// The same holds through the non-fallback read.
			if ok, err := cache.HasPermission(ctx, tenantID, userID, "findings:write"); err != nil || ok {
				t.Fatalf("HasPermission after revocation = %v, %v", ok, err)
			}

			// Another tenant's entry for the same user is its own.
			other := uuid.NewString()
			repo.set("assets:read")
			if p, _ := cache.GetPermissionsWithFallback(ctx, other, userID); !slices.Equal(p, []string{"assets:read"}) {
				t.Fatalf("other tenant = %v", p)
			}
		})
	}
}
