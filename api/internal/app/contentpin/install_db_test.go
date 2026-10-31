package contentpin

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/app/contentpin/builtin"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/internal/testdb"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The seed through the real platform store (Postgres migration 001568, file
// storage, platform signature): the embedded packs are ingested with their
// recorded digests, stable points at them, the delivery resolves them for
// sensors, and a second start, or a second replica, changes nothing.
// The packs get a unique name suffix: platform packs are global, and other
// tests of the same database must not see these names. Requires DATABASE_URL.
func TestInstallBuiltin_DB(t *testing.T) {
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

	signer, _ := dom.NewSigner(bytes.Repeat([]byte{7}, 32))
	svc := contentpack.NewPlatformService(postgres.NewPlatformContentPackRepository(&postgres.DB{DB: db}),
		storage.NewLocalStorage(t.TempDir()), signer, logger.NewNop())

	packs, err := builtin.Packs()
	if err != nil {
		t.Fatal(err)
	}
	suffix := "-t" + strings.ReplaceAll(shared.NewID().String()[24:], "-", "")
	for i := range packs {
		packs[i].Name += suffix
	}
	set, err := installPacks(ctx, svc, packs, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 {
		t.Fatalf("set %v", set)
	}
	// A second replica that read the channels before the first set them
	// ingests again, meets the unique (name, version), and points stable at
	// the same pack.
	again, err := installPacks(ctx, &staleChannels{svc}, packs, quiet())
	if err != nil || len(again) != 2 {
		t.Fatalf("second replica: %v %v", again, err)
	}
	chans, err := svc.Channels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	delivery := contentpack.NewDelivery(nil, svc)
	for _, p := range packs {
		var stable *dom.ChannelPointer
		for i, c := range chans {
			if c.Name == p.Name && c.Channel == dom.ChannelStable {
				stable = &chans[i]
			}
		}
		if stable == nil || stable.Digest != p.PackDigest || stable.Version != p.Release {
			t.Fatalf("%s: stable %+v, want digest %s version %s", p.Name, stable, p.PackDigest, p.Release)
		}
		got, err := svc.Get(ctx, stable.PackID.String())
		if err != nil {
			t.Fatal(err)
		}
		if got.SourceRef != "builtin:"+p.Asset || got.Kind != kindWordlist || len(got.Signature) == 0 {
			t.Fatalf("%s recorded as %+v", p.Name, got.Pack)
		}
		pin, err := delivery.PlatformStable(ctx, p.Name)
		if err != nil || pin.Digest != p.PackDigest {
			t.Fatalf("%s: delivery %+v %v", p.Name, pin, err)
		}
	}
	// Restart: stable exists, nothing is ingested or moved.
	if set, err := installPacks(ctx, svc, packs, quiet()); err != nil || len(set) != 0 {
		t.Fatalf("restart: %v %v", set, err)
	}
}

// staleChannels answers no channels, as a replica that read them before
// another set them.
type staleChannels struct{ *contentpack.PlatformService }

func (*staleChannels) Channels(context.Context) ([]dom.ChannelPointer, error) { return nil, nil }
