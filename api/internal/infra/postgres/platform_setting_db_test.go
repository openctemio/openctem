package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The console settings store: create only when absent, and a write only
// against the version that was read (a stale save is refused, not merged).
func TestPlatformSettingRepository_CreateAndCompareAndSwap(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	key := "test." + shared.NewID().String()
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_settings WHERE key = $1`, key) })
	repo := NewPlatformSettingRepository(&DB{DB: db})

	if _, err := repo.Get(ctx, key); !errors.Is(err, platformsetting.ErrNotFound) {
		t.Fatalf("get absent = %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	created, err := repo.CreateIfAbsent(ctx, key, platformsetting.State{Value: json.RawMessage(`{"a":1}`), Source: platformsetting.SourceEnvironment, UpdatedAt: now})
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	if created, _ := repo.CreateIfAbsent(ctx, key, platformsetting.State{Value: json.RawMessage(`{"a":2}`), UpdatedAt: now}); created {
		t.Fatal("a second create must not overwrite")
	}
	by := shared.NewID()
	st, err := repo.Update(ctx, key, json.RawMessage(`{"a":3}`), 1, by, now)
	if err != nil || st.Version != 2 || st.Source != platformsetting.SourceConsole {
		t.Fatalf("update: %+v %v", st, err)
	}
	if _, err := repo.Update(ctx, key, json.RawMessage(`{"a":4}`), 1, by, now); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("stale update = %v, want ErrVersionConflict", err)
	}
	got, err := repo.Get(ctx, key)
	if err != nil || got.Version != 2 || string(got.Value) != `{"a": 3}` && string(got.Value) != `{"a":3}` || got.UpdatedBy == nil || *got.UpdatedBy != by {
		t.Fatalf("get: %+v %v (value %s)", got, err, got.Value)
	}
}
