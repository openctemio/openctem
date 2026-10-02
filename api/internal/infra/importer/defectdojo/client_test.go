package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// mockDD serves a paginated /api/v2/findings/ and records auth + pagination.
func mockDD(t *testing.T, total int, pageLimit int) (*httptest.Server, *int) {
	t.Helper()
	authSeen := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Token secret-tok" {
			authSeen++
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v2/product_types/":
			_ = json.NewEncoder(w).Encode(map[string]any{"count": 3})
			return
		case "/api/v2/findings/":
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
			if limit == 0 {
				limit = pageLimit
			}
			results := []Finding{}
			for i := offset; i < offset+limit && i < total; i++ {
				results = append(results, Finding{ID: i + 1, Title: fmt.Sprintf("f-%d", i+1), Severity: "High", HashCode: fmt.Sprintf("h%d", i+1)})
			}
			next := ""
			if offset+limit < total {
				next = "next-page"
			}
			_ = json.NewEncoder(w).Encode(findingsResponse{Count: total, Next: next, Results: results})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &authSeen
}

func TestClient_FetchFindings_Paginates(t *testing.T) {
	srv, auth := mockDD(t, 250, 100) // 3 pages: 100 + 100 + 50
	c := NewClient(srv.URL, "secret-tok", srv.Client())

	findings, err := c.FetchFindings(context.Background(), FindingFilter{ActiveOnly: true})
	if err != nil {
		t.Fatalf("FetchFindings: %v", err)
	}
	if len(findings) != 250 {
		t.Fatalf("got %d findings, want 250 (across pages)", len(findings))
	}
	if findings[0].ID != 1 || findings[249].ID != 250 {
		t.Errorf("pagination order wrong: first=%d last=%d", findings[0].ID, findings[249].ID)
	}
	if *auth < 3 {
		t.Errorf("expected ≥3 authenticated page requests, got %d", *auth)
	}
}

func TestClient_FetchFindings_RespectsMaxTotal(t *testing.T) {
	srv, _ := mockDD(t, 1000, 100)
	c := NewClient(srv.URL, "secret-tok", srv.Client())

	findings, err := c.FetchFindings(context.Background(), FindingFilter{MaxTotal: 150})
	if err != nil {
		t.Fatalf("FetchFindings: %v", err)
	}
	if len(findings) != 150 {
		t.Fatalf("got %d, want capped at 150", len(findings))
	}
}

func TestClient_Unauthorized(t *testing.T) {
	srv, _ := mockDD(t, 10, 100)
	c := NewClient(srv.URL, "wrong-token", srv.Client())
	if _, err := c.FetchFindings(context.Background(), FindingFilter{}); err == nil {
		t.Fatal("expected auth error with a bad token")
	}
}

func TestClient_TestConnection(t *testing.T) {
	srv, _ := mockDD(t, 0, 100)
	if err := NewClient(srv.URL, "secret-tok", srv.Client()).TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if err := NewClient(srv.URL, "", srv.Client()).TestConnection(context.Background()); err == nil {
		t.Fatal("expected error with empty token")
	}
}

// End-to-end: pull → convert → CTIS, proving the client + Phase-1 converter
// compose (with the dedup/coverage invariants intact).
func TestClient_FetchThenConvert(t *testing.T) {
	srv, _ := mockDD(t, 3, 100)
	c := NewClient(srv.URL, "secret-tok", srv.Client())
	findings, err := c.FetchFindings(context.Background(), FindingFilter{})
	if err != nil {
		t.Fatalf("FetchFindings: %v", err)
	}
	report := Convert(findings, ConvertOptions{SourceRef: "sync-1", ProductName: "acme/app"})
	if report.Metadata.CoverageType != "partial" {
		t.Errorf("coverage must stay partial through the pipeline")
	}
	if len(report.Findings) != 3 {
		t.Fatalf("converted %d findings, want 3", len(report.Findings))
	}
	if report.Findings[0].Fingerprint == "" {
		t.Error("converted finding missing dedup fingerprint")
	}
}
