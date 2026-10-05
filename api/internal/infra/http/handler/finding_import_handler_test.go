package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type importIngester struct{ calls []ingest.Input }

func (f *importIngester) Ingest(_ context.Context, _ *sensor.Sensor, in ingest.Input) (*ingest.Output, error) {
	f.calls = append(f.calls, in)
	return &ingest.Output{FindingsCreated: len(in.Report.Findings), AssetsCreated: len(in.Report.Assets)}, nil
}

type importVEXRepo struct{ applies int }

func (f *importVEXRepo) MatchVEXDocument(context.Context, shared.ID, vulnerability.VEXDocumentQuery, int) ([]vulnerability.VEXCandidate, error) {
	return nil, nil
}

func (f *importVEXRepo) ApplyVEXDocument(context.Context, shared.ID, []shared.ID, vulnerability.InteropVEX, bool, string) ([]shared.ID, []shared.ID, error) {
	f.applies++
	return nil, nil, nil
}

type importScope struct{}

func (importScope) AssetsInScope(context.Context, []shared.ID) ([]shared.ID, error) { return nil, nil }

func newImportTestHandler(restricted bool) (*FindingImportHandler, *importIngester) {
	ing := &importIngester{}
	svc := findingimport.NewService(ing, &importVEXRepo{}, ingest.SourceResolveDryRun, logger.NewNop())
	h := &FindingImportHandler{svc: svc, logger: logger.NewNop()}
	h.actorOf = func(context.Context, shared.ID) (ingest.ActorScope, error) {
		if restricted {
			return importScope{}, nil
		}
		return nil, nil
	}
	return h, ing
}

const importNessus = `<?xml version="1.0"?>
<NessusClientData_v2><Report name="r"><ReportHost name="192.0.2.5"><HostProperties><tag name="host-ip">192.0.2.5</tag></HostProperties>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="3" pluginID="1001" pluginName="OpenSSH issue" pluginFamily="General"><cve>CVE-2024-0001</cve></ReportItem>
</ReportHost></Report></NessusClientData_v2>`

type part struct {
	field, name string
	data        []byte
}

func multipartBody(t *testing.T, parts ...part) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		w, err := mw.CreateFormFile(p.field, p.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(p.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

func doImport(t *testing.T, h *FindingImportHandler, query string, body io.Reader, ctype string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/import"+query, body)
	req.Header.Set("Content-Type", ctype)
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String()))
	rec := httptest.NewRecorder()
	h.Import(rec, req)
	return rec
}

func zipOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decodeImport(t *testing.T, rec *httptest.ResponseRecorder) FindingImportResponse {
	t.Helper()
	var resp FindingImportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	return resp
}

func TestFindingImport_PreviewHasNoSideEffects(t *testing.T) {
	h, ing := newImportTestHandler(false)
	body, ct := multipartBody(t, part{"file", "scan.txt", []byte(importNessus)})
	// The client type and name lie; the content decides.
	rec := doImport(t, h, "?dry_run=true", body, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	resp := decodeImport(t, rec)
	if !resp.DryRun || len(resp.Files) != 1 || resp.Files[0].Format != "nessus" || resp.Files[0].Stats.Findings != 1 {
		t.Fatalf("response = %+v", resp)
	}
	if len(ing.calls) != 0 {
		t.Fatal("a preview ingested")
	}
}

func TestFindingImport_CommitRunsWithTheUploadersScope(t *testing.T) {
	h, ing := newImportTestHandler(true)
	body, ct := multipartBody(t, part{"file", "scan.nessus", []byte(importNessus)})
	rec := doImport(t, h, "", body, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if len(ing.calls) != 1 || ing.calls[0].Options.Actor == nil || ing.calls[0].CoverageType != ingest.CoverageTypePartial {
		t.Fatalf("ingest = %+v", ing.calls)
	}
	resp := decodeImport(t, rec)
	if resp.Files[0].Ingest == nil || resp.Files[0].Ingest.FindingsCreated != 1 {
		t.Fatalf("response = %+v", resp.Files[0])
	}
}

func TestFindingImport_Refusals(t *testing.T) {
	bomb := zipOf(t, map[string][]byte{"big.nessus": append([]byte(`<?xml version="1.0"?><NessusClientData_v2>`), bytes.Repeat([]byte(" "), 80<<20)...)})
	cases := []struct {
		name   string
		query  string
		parts  []part
		status int
		kind   string
	}{
		{"unknown format", "", []part{{"file", "a.bin", []byte("hello world")}}, 400, "unknown_format"},
		{"xxe", "", []part{{"file", "a.nessus", []byte(`<?xml version="1.0"?><!DOCTYPE NessusClientData_v2 [<!ENTITY x SYSTEM "file:///etc/passwd">]><NessusClientData_v2>&x;</NessusClientData_v2>`)}}, 400, "unsafe"},
		{"zip traversal", "", []part{{"file", "a.zip", zipOf(t, map[string][]byte{"../../etc/x.nessus": []byte(importNessus)})}}, 400, "unsafe"},
		{"nested zip", "", []part{{"file", "a.zip", zipOf(t, map[string][]byte{"inner.zip": []byte("PK")})}}, 400, "unsafe"},
		{"knowledge base alone", "", []part{{"file", "kb.xml", []byte(`<?xml version="1.0"?><KNOWLEDGE_BASE_VULN_LIST_OUTPUT/>`)}}, 400, "unknown_format"},
		{"bad format", "?format=pdf", []part{{"file", "a", []byte(importNessus)}}, 400, ""},
		{"bad severity", "?min_severity=urgent", []part{{"file", "a", []byte(importNessus)}}, 400, ""},
		{"no file", "", []part{{"other", "a", []byte("x")}}, 400, ""},
		{"too many files", "", []part{{"file", "1", []byte(importNessus)}, {"file", "2", []byte(importNessus)}, {"file", "3", []byte(importNessus)}, {"file", "4", []byte(importNessus)}, {"file", "5", []byte(importNessus)}, {"file", "6", []byte(importNessus)}, {"file", "7", []byte(importNessus)}, {"file", "8", []byte(importNessus)}, {"file", "9", []byte(importNessus)}, {"file", "10", []byte(importNessus)}, {"file", "11", []byte(importNessus)}}, 400, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, ing := newImportTestHandler(false)
			body, ct := multipartBody(t, c.parts...)
			rec := doImport(t, h, c.query, body, ct)
			if rec.Code != c.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.status, rec.Body.String())
			}
			if c.kind != "" && !strings.Contains(rec.Body.String(), `"kind":"`+c.kind+`"`) {
				t.Fatalf("body has no kind %s: %s", c.kind, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "root:") {
				t.Fatal("file content leaked")
			}
			if c.name != "too many files" && len(ing.calls) != 0 {
				t.Fatal("a refused upload was ingested")
			}
		})
	}
	t.Run("decompression bomb", func(t *testing.T) {
		h, ing := newImportTestHandler(false)
		body, ct := multipartBody(t, part{"file", "a.zip", bomb})
		rec := doImport(t, h, "", body, ct)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		resp := decodeImport(t, rec)
		if resp.Files[0].Error == nil || resp.Files[0].Error.Kind != "too_large" || len(ing.calls) != 0 {
			t.Fatalf("bomb not refused: %+v", resp.Files[0])
		}
	})
	t.Run("not multipart", func(t *testing.T) {
		h, _ := newImportTestHandler(false)
		rec := doImport(t, h, "", strings.NewReader(importNessus), "application/xml")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("body over the limit", func(t *testing.T) {
		h, ing := newImportTestHandler(false)
		h.maxBody = 4096
		body, ct := multipartBody(t, part{"file", "a.nessus", []byte(importNessus + strings.Repeat(" ", 10_000))})
		rec := doImport(t, h, "", body, ct)
		if rec.Code != http.StatusRequestEntityTooLarge || len(ing.calls) != 0 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("archive over the limit", func(t *testing.T) {
		h, _ := newImportTestHandler(false)
		h.maxBody = 4096
		z := zipOf(t, map[string][]byte{"a.nessus": bytes.Repeat([]byte("x"), 1<<20)})
		body, ct := multipartBody(t, part{"file", "a.zip", append(z, bytes.Repeat([]byte{0}, 8192)...)})
		rec := doImport(t, h, "", body, ct)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestFindingImport_ArchiveImportsEachFile(t *testing.T) {
	h, ing := newImportTestHandler(false)
	z := zipOf(t, map[string][]byte{"a/one.nessus": []byte(importNessus), "two.nessus": []byte(importNessus), "notes.txt": []byte("hello")})
	body, ct := multipartBody(t, part{"file", "batch.zip", z})
	rec := doImport(t, h, "", body, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	resp := decodeImport(t, rec)
	if len(resp.Files) != 3 || len(ing.calls) != 2 {
		t.Fatalf("files %d, ingests %d: %+v", len(resp.Files), len(ing.calls), resp.Files)
	}
	var unknown int
	for _, f := range resp.Files {
		if !strings.HasPrefix(f.Name, "batch.zip/") {
			t.Errorf("name %q", f.Name)
		}
		if f.Error != nil && f.Error.Kind == "unknown_format" {
			unknown++
		}
	}
	if unknown != 1 {
		t.Fatalf("the text file was not reported as unknown: %+v", resp.Files)
	}
}

func TestFindingImport_NotConfiguredFailsClosed(t *testing.T) {
	h := &FindingImportHandler{logger: logger.NewNop()}
	body, ct := multipartBody(t, part{"file", "a", []byte(importNessus)})
	rec := doImport(t, h, "", body, ct)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestSafeFileName(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd":          "passwd",
		"C:\\Users\\x\\scan.nessus": "scan.nessus",
		"a\x1b[31mb":                "a[31mb",
		"":                          "upload",
		"..":                        "..",
		strings.Repeat("é", 300):    strings.Repeat("é", 200),
	}
	for in, want := range cases {
		if got := safeFileName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
	}
}
