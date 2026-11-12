package threat

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/feedstatus"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
)

// The raw failure text is stored and shown on the platform admin route: a
// fetch error must not carry the query string of the URL it quotes.
func TestMarkFailedRedactsURLCredentials(t *testing.T) {
	st := threatintel.NewSyncStatus("kev", 1)
	ue := &url.Error{Op: "Get", URL: "https://mirror.example/kev.json?X-Amz-Signature=deadbeef&token=s3cr3t",
		Err: errors.New("connection reset by peer")}
	markFailed(st, fmt.Errorf("failed to fetch KEV data: %w", ue))
	got := st.LastSyncError()
	if strings.Contains(got, "deadbeef") || strings.Contains(got, "s3cr3t") {
		t.Fatalf("stored error leaks the query: %s", got)
	}
	if !strings.Contains(got, "https://mirror.example/kev.json?[REDACTED]") || !strings.Contains(got, "connection reset by peer") {
		t.Fatalf("stored error lost the endpoint or cause: %s", got)
	}
	if c := st.Metadata()[threatintel.MetaErrorCode]; c != feedstatus.CodeUnreachable {
		t.Fatalf("classification must still see the *url.Error, got %v", c)
	}
}
