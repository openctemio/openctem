package fetchers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
)

// A template-source download is read into memory: it must stop at the size
// cap instead of reading whatever the server sends (settings audit SC-M1).
func TestHTTPFetch_StopsAtSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 8192)))
	}))
	defer srv.Close()
	f := &HTTPFetcher{config: HTTPConfig{URL: srv.URL + "/t.yaml"}, httpClient: srv.Client()}

	_, err := f.Fetch(context.Background(), FetchOptions{MaxTotalSize: 1024})
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized response: err = %v, want a size-limit error", err)
	}
	if _, err := f.Fetch(context.Background(), FetchOptions{MaxTotalSize: 1 << 20}); err != nil {
		t.Fatalf("response under the limit: %v", err)
	}
}

// A clone that grows past the cap is cancelled (settings audit SC-M2: the
// clone lands on the API server's disk).
func TestCloneWithSizeCap_AbortsOversizedClone(t *testing.T) {
	oldMax, oldPoll := maxCloneBytes, cloneSizePoll
	maxCloneBytes, cloneSizePoll = 1024, 10*time.Millisecond
	t.Cleanup(func() { maxCloneBytes, cloneSizePoll = oldMax, oldPoll })

	dir := t.TempDir()
	growing := func(ctx context.Context) (*git.Repository, error) {
		for i := 0; ; i++ {
			if err := os.WriteFile(filepath.Join(dir, "pack-"+string(rune('a'+i%26))+".bin"), make([]byte, 600), 0o600); err != nil {
				return nil, err
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
			if i > 200 {
				return nil, errors.New("clone was never cancelled")
			}
		}
	}
	if _, err := cloneWithSizeCap(context.Background(), dir, growing); !errors.Is(err, ErrRepositoryTooLarge) {
		t.Fatalf("oversized clone: err = %v, want ErrRepositoryTooLarge", err)
	}

	small := t.TempDir()
	ok := func(context.Context) (*git.Repository, error) {
		return nil, os.WriteFile(filepath.Join(small, "a"), []byte("x"), 0o600)
	}
	if _, err := cloneWithSizeCap(context.Background(), small, ok); err != nil {
		t.Fatalf("small clone: %v", err)
	}
}
