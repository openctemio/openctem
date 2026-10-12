package webevidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image"
	"image/png"
	"io"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/webevidence"
)

type fakeRepo struct {
	recs    []webevidence.Record
	expired []webevidence.BlobRef
	orphans []webevidence.BlobRef
	failIns bool
}

func (f *fakeRepo) Insert(_ context.Context, r webevidence.Record) error {
	if f.failIns {
		return errors.New("db down")
	}
	r.ID = shared.NewID().String()
	f.recs = append(f.recs, r)
	return nil
}
func (f *fakeRepo) List(context.Context, shared.ID, shared.ID) ([]webevidence.Record, error) {
	return f.recs, nil
}
func (f *fakeRepo) Get(_ context.Context, _, _ shared.ID, id string) (*webevidence.Record, error) {
	for _, r := range f.recs {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, shared.ErrNotFound
}
func (f *fakeRepo) ExpireScreenshots(context.Context, time.Time, int) ([]webevidence.BlobRef, error) {
	return f.expired, nil
}
func (f *fakeRepo) TakeOrphans(context.Context, int) ([]webevidence.BlobRef, error) {
	return f.orphans, nil
}
func (f *fakeRepo) DeleteOlderThan(context.Context, time.Time) (int64, error) { return 0, nil }

type fakeBlobs struct {
	stored  map[string][]byte
	deleted []string
	fail    bool
}

func (f *fakeBlobs) StoreBlob(_ context.Context, tenantID, name, _ string, data []byte) (string, string, error) {
	if f.fail {
		return "", "", errors.New("s3 down")
	}
	key := tenantID + "/" + name
	f.stored[key] = data
	return key, "local", nil
}
func (f *fakeBlobs) OpenBlob(_ context.Context, _, _, key string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f.stored[key])), nil
}
func (f *fakeBlobs) DeleteBlob(_ context.Context, _, _, key string) error {
	f.deleted = append(f.deleted, key)
	delete(f.stored, key)
	return nil
}

type fakeSettings struct {
	on  bool
	err error
}

func (f fakeSettings) GetEASMSettings(context.Context, string) (*tenant.EASMSettings, error) {
	return &tenant.EASMSettings{WebScreenshotsEnabled: f.on}, f.err
}

func capture(t *testing.T) any {
	t.Helper()
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 8, 6)))
	return []any{map[string]any{
		"url": "https://app.example.com/", "status_code": float64(200), "title": "App",
		"screenshot": map[string]any{"data": base64.StdEncoding.EncodeToString(buf.Bytes())},
	}}
}

func TestRecordReport(t *testing.T) {
	ctx := context.Background()
	tid, aid := shared.NewID(), shared.NewID()

	t.Run("screenshots kept only when the organization turned them on", func(t *testing.T) {
		for _, on := range []bool{false, true} {
			repo, blobs := &fakeRepo{}, &fakeBlobs{stored: map[string][]byte{}}
			svc := NewService(repo, blobs, fakeSettings{on: on}, nil)
			stored, skipped := svc.RecordReport(ctx, tid, "screenshot", []webevidence.Item{{AssetID: aid, Raw: capture(t)}})
			if stored != 1 || skipped != 0 {
				t.Fatalf("on=%v stored=%d skipped=%d", on, stored, skipped)
			}
			if got := repo.recs[0].HasScreenshot(); got != on || (len(blobs.stored) == 1) != on {
				t.Fatalf("on=%v screenshot kept=%v blobs=%d", on, got, len(blobs.stored))
			}
			if on && (repo.recs[0].ScreenshotExpiresAt == nil || repo.recs[0].TenantID != tid.String()) {
				t.Fatalf("record: %+v", repo.recs[0])
			}
		}
	})

	t.Run("unreadable settings keep no screenshot", func(t *testing.T) {
		repo, blobs := &fakeRepo{}, &fakeBlobs{stored: map[string][]byte{}}
		svc := NewService(repo, blobs, fakeSettings{on: true, err: errors.New("boom")}, nil)
		svc.RecordReport(ctx, tid, "", []webevidence.Item{{AssetID: aid, Raw: capture(t)}})
		if len(repo.recs) != 1 || repo.recs[0].HasScreenshot() || len(blobs.stored) != 0 {
			t.Fatal("screenshot kept without readable settings")
		}
	})

	t.Run("storage failure keeps the text", func(t *testing.T) {
		repo := &fakeRepo{}
		svc := NewService(repo, &fakeBlobs{stored: map[string][]byte{}, fail: true}, fakeSettings{on: true}, nil)
		if stored, _ := svc.RecordReport(ctx, tid, "", []webevidence.Item{{AssetID: aid, Raw: capture(t)}}); stored != 1 || repo.recs[0].HasScreenshot() {
			t.Fatal("text not stored on storage failure")
		}
	})

	t.Run("a failed insert deletes the stored file", func(t *testing.T) {
		blobs := &fakeBlobs{stored: map[string][]byte{}}
		svc := NewService(&fakeRepo{failIns: true}, blobs, fakeSettings{on: true}, nil)
		if stored, skipped := svc.RecordReport(ctx, tid, "", []webevidence.Item{{AssetID: aid, Raw: capture(t)}}); stored != 0 || skipped != 1 {
			t.Fatalf("stored=%d skipped=%d", stored, skipped)
		}
		if len(blobs.stored) != 0 || len(blobs.deleted) != 1 {
			t.Fatal("orphan file left behind")
		}
	})
}

func TestScreenshotAndSweep(t *testing.T) {
	ctx := context.Background()
	tid, aid := shared.NewID(), shared.NewID()
	repo, blobs := &fakeRepo{}, &fakeBlobs{stored: map[string][]byte{}}
	svc := NewService(repo, blobs, fakeSettings{on: true}, nil)
	svc.RecordReport(ctx, tid, "", []webevidence.Item{{AssetID: aid, Raw: capture(t)}})
	rc, rec, err := svc.Screenshot(ctx, tid, aid, repo.recs[0].ID)
	if err != nil || rec.ScreenshotSize == 0 {
		t.Fatalf("screenshot: %v", err)
	}
	_ = rc.Close()
	// A stored file that no longer matches the recorded size is refused.
	blobs.stored[repo.recs[0].ScreenshotKey] = []byte("tampered")
	if _, _, err := svc.Screenshot(ctx, tid, aid, repo.recs[0].ID); err == nil {
		t.Fatal("tampered file served")
	}
	if _, _, err := svc.Screenshot(ctx, tid, aid, shared.NewID().String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing capture: %v", err)
	}
	repo.expired = []webevidence.BlobRef{{TenantID: tid.String(), Provider: "local", Key: "a"}}
	repo.orphans = []webevidence.BlobRef{{TenantID: tid.String(), Provider: "local", Key: "b"}}
	n, err := svc.Sweep(ctx)
	if err != nil || n != 2 {
		t.Fatalf("sweep: %v %d", err, n)
	}
}
