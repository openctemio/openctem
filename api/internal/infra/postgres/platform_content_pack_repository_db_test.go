package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Platform content packs against a real schema (migration 001568):
// channels name a pack of their own name, revocation rolls a channel back
// to the previous good pack, a revoked pack cannot be put on a channel.
// Requires DATABASE_URL.

func TestPlatformContentPackRepository_ChannelsAndRollback(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewPlatformContentPackRepository(&DB{DB: sqlDB})
	name := "nt-" + strings.ReplaceAll(shared.NewID().String()[24:], "-", "")
	base := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(n, version string, i int) *contentpack.PlatformPack {
		digest := fmt.Sprintf("sha256:%064x", time.Now().UnixNano()+int64(i))
		if _, err := repo.CreateBlob(ctx, &contentpack.Blob{Digest: digest, SizeBytes: 10, FileCount: 1, StorageKey: "k", CreatedAt: base}); err != nil {
			t.Fatal(err)
		}
		p := &contentpack.PlatformPack{Pack: contentpack.Pack{
			ID: shared.NewID(), Name: n, Version: version, Kind: contentpack.KindNucleiTemplates, Digest: digest,
			Tier: contentpack.TierT1, Status: contentpack.StatusActive, Source: contentpack.SourceUpload,
			Signature: []byte(`{}`), CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}}
		if err := repo.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	v1, v2, v3 := mk(name, "1", 1), mk(name, "2", 2), mk(name, "3", 3)
	other := mk(name+"-x", "1", 4)

	if _, err := repo.SetChannel(ctx, v3.ID, contentpack.ChannelCanary, base); err != nil {
		t.Fatal(err)
	}
	c, err := repo.SetChannel(ctx, v2.ID, contentpack.ChannelStable, base)
	if err != nil || c.Name != name || c.Version != "2" || c.Digest != v2.Digest {
		t.Fatalf("stable: %+v %v", c, err)
	}
	// SECURITY: a channel cannot point at a pack of another name.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE platform_content_channels SET pack_id = $1 WHERE name = $2`, other.ID.String(), name); err == nil {
		t.Fatal("a channel named a pack of another name")
	}
	if err := repo.Create(ctx, &contentpack.PlatformPack{Pack: *func() *contentpack.Pack { p := v1.Pack; p.ID = shared.NewID(); return &p }()}); !errors.Is(err, contentpack.ErrExists) {
		t.Fatalf("duplicate version: %v", err)
	}

	// Revoking the stable pack moves stable back to v1; canary stays.
	cs, err := repo.Revoke(ctx, v2.ID, "bad release", base)
	if err != nil {
		t.Fatal(err)
	}
	got := map[contentpack.Channel]string{}
	for _, c := range cs {
		got[c.Channel] = c.Version
	}
	if got[contentpack.ChannelStable] != "1" || got[contentpack.ChannelCanary] != "3" {
		t.Fatalf("after revoking v2: %v", got)
	}
	if _, err := repo.Revoke(ctx, v2.ID, "again", base); !errors.Is(err, contentpack.ErrNotActive) {
		t.Fatalf("revoke twice: %v", err)
	}
	if _, err := repo.SetChannel(ctx, v2.ID, contentpack.ChannelStable, base); !errors.Is(err, contentpack.ErrNotActive) {
		t.Fatalf("revoked pack on a channel: %v", err)
	}
	if _, err := repo.SetChannel(ctx, shared.NewID(), contentpack.ChannelStable, base); !errors.Is(err, contentpack.ErrNotFound) {
		t.Fatalf("unknown pack: %v", err)
	}
	// Revoking the oldest pack with nothing older removes its channel.
	if cs, err = repo.Revoke(ctx, v1.ID, "also bad", base); err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Channel == contentpack.ChannelStable {
			t.Fatalf("stable kept a revoked pack: %+v", c)
		}
	}
	if p, _ := repo.GetByID(ctx, v1.ID); p.Status != contentpack.StatusRevoked || p.RevokeReason != "also bad" {
		t.Fatalf("revoked: %+v", p)
	}
	if list, total, err := repo.List(ctx, contentpack.Filter{Name: name, Status: contentpack.StatusActive}, 10, 0); err != nil || total != 1 || list[0].Version != "3" {
		t.Fatalf("active list: %d %v", total, err)
	}
}
