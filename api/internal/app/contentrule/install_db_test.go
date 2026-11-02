package contentrule

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/app/contentrule/builtin"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/internal/testdb"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/contentrule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The built-in rule packs through the real platform store (lint, canonical
// form, platform signature, channels): installed once with stable pointing
// at them, never moved on a second start, and read back into an engine
// that holds both kinds. Names get a unique suffix: platform packs are
// global. Requires DATABASE_URL.
func TestInstallBuiltinRulePacks_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	// Blobs are content addressed and global: a database that ran this test
	// before holds the blob rows, so the files live in one fixed directory.
	blobDir := filepath.Join(os.TempDir(), "openctem-test-rule-packs")
	signer, _ := dom.NewSigner(bytes.Repeat([]byte{9}, 32))
	svc := contentpack.NewPlatformService(postgres.NewPlatformContentPackRepository(&postgres.DB{DB: db}),
		storage.NewLocalStorage(blobDir), signer, logger.NewNop())
	packs, err := builtin.Packs()
	if err != nil {
		t.Fatal(err)
	}
	suffix := "-t" + strings.ReplaceAll(shared.NewID().String()[24:], "-", "")
	for i := range packs {
		packs[i].Name += suffix
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	set, err := installPacks(ctx, svc, packs, quiet)
	if err != nil || len(set) != 2 {
		t.Fatalf("install: %v %v", set, err)
	}
	again, err := installPacks(ctx, svc, packs, quiet)
	if err != nil || len(again) != 0 {
		t.Fatalf("second start moved channels: %v %v", again, err)
	}

	// The service reads the stable packs back (only ours: other tests may
	// have their own platform packs, of other kinds or names).
	rules := NewService(onlyNames{svc, suffix}, nil, nil, nil, nil, quiet)
	e, err := rules.Engine(ctx, shared.NewID())
	if err != nil || e == nil {
		t.Fatalf("engine: %v %v", e, err)
	}
	if !e.HasKind(contentrule.KindFingerprint) || !e.HasKind(contentrule.KindSecret) {
		t.Fatalf("engine kinds missing: %+v", Pins(e))
	}
	for _, p := range Pins(e) {
		if p.Scope != contentrule.ScopePlatform || !strings.HasPrefix(p.Digest, "sha256:") || p.Version != builtin.Release || p.Rules == 0 {
			t.Errorf("pin %+v", p)
		}
	}
}

// onlyNames narrows the channels to the packs of this test.
type onlyNames struct {
	*contentpack.PlatformService
	suffix string
}

func (o onlyNames) Channels(ctx context.Context) ([]dom.ChannelPointer, error) {
	all, err := o.PlatformService.Channels(ctx)
	var out []dom.ChannelPointer
	for _, c := range all {
		if strings.HasSuffix(c.Name, o.suffix) {
			out = append(out, c)
		}
	}
	return out, err
}
