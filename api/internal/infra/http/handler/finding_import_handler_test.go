package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/ingestqueue"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
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

type importVEXRepo struct{ applies, uploads int }

func (f *importVEXRepo) CreateUpload(context.Context, *ingestreceipt.Upload) error {
	f.uploads++
	return nil
}

func (f *importVEXRepo) FinishUpload(context.Context, shared.ID, shared.ID, *ingestreceipt.UploadResult) error {
	return nil
}

func (f *importVEXRepo) StampAssetsImport(context.Context, shared.ID, shared.ID, []shared.ID) (int64, error) {
	return 0, nil
}

func (f *importVEXRepo) MatchVEXDocument(context.Context, shared.ID, vulnerability.VEXDocumentQuery, int) ([]vulnerability.VEXCandidate, error) {
	return nil, nil
}

func (f *importVEXRepo) ApplyVEXDocument(context.Context, shared.ID, []shared.ID, vulnerability.InteropVEX, bool, string) ([]shared.ID, []shared.ID, error) {
	f.applies++
	return nil, nil, nil
}

type importScope struct{}

func (importScope) AssetsInScope(context.Context, []shared.ID) ([]shared.ID, error) { return nil, nil }

// memQueue is an in-memory ingest queue: the handler test runs the worker's
// side itself (process).
type memQueue struct {
	parts    map[shared.ID][]ingestqueue.OpenedPart
	jobs     []*ingestjob.Job
	admitErr error
}

func (q *memQueue) StagePart(_ context.Context, _, jobID shared.ID, part int, name string, body []byte) error {
	if q.parts == nil {
		q.parts = map[shared.ID][]ingestqueue.OpenedPart{}
	}
	q.parts[jobID] = append(q.parts[jobID], ingestqueue.OpenedPart{Part: part, Name: name, Body: append([]byte(nil), body...)})
	return nil
}
func (q *memQueue) Commit(_ context.Context, job *ingestjob.Job, _ func() error) (*ingestjob.Job, bool, error) {
	q.jobs = append(q.jobs, job)
	return job, true, nil
}
func (q *memQueue) Discard(_ context.Context, _, jobID shared.ID) { delete(q.parts, jobID) }
func (q *memQueue) Recent(context.Context, shared.ID, ingestjob.Kind, string, []byte, time.Duration) (*ingestjob.Job, error) {
	return nil, nil
}
func (q *memQueue) Admit(context.Context, shared.ID) error { return q.admitErr }
func (q *memQueue) Get(context.Context, shared.ID, shared.ID, ingestjob.Kind) (*ingestjob.Job, error) {
	return nil, shared.ErrNotFound
}
func (q *memQueue) Wait(context.Context, shared.ID, shared.ID, ingestjob.Kind, time.Duration) (*ingestjob.Job, error) {
	return nil, shared.ErrNotFound
}
func (q *memQueue) BySource(context.Context, shared.ID, ingestjob.Kind, string) (*ingestjob.Job, error) {
	return nil, shared.ErrNotFound
}
func (q *memQueue) Parts(_ context.Context, job *ingestjob.Job) ([]ingestqueue.OpenedPart, error) {
	return q.parts[job.ID()], nil
}
func (q *memQueue) Done(_ context.Context, job *ingestjob.Job) error {
	delete(q.parts, job.ID())
	return nil
}

type importTestRig struct {
	svc   *findingimport.Service
	queue *memQueue
}

// process runs the queued uploads as the ingest worker does and returns
// their per-file results.
func (r *importTestRig) process(t *testing.T) []FindingImportResponse {
	t.Helper()
	var out []FindingImportResponse
	for _, job := range r.queue.jobs {
		raw, err := r.svc.ProcessImportJob(context.Background(), job)
		if err != nil {
			t.Fatalf("process: %v", err)
		}
		// The worker's Complete deletes the stored parts.
		if err := r.queue.Done(context.Background(), job); err != nil {
			t.Fatal(err)
		}
		var res findingimport.QueuedResult
		if err := json.Unmarshal(raw, &res); err != nil {
			t.Fatal(err)
		}
		resp := FindingImportResponse{}
		for i := range res.Files {
			resp.Files = append(resp.Files, toImportFileResponse(&res.Files[i]))
		}
		out = append(out, resp)
	}
	r.queue.jobs = nil
	return out
}

func newImportTestHandler(restricted bool) (*FindingImportHandler, *importIngester) {
	h, ing, _ := newImportTestRig(restricted)
	return h, ing
}

func newImportTestRig(restricted bool) (*FindingImportHandler, *importIngester, *importTestRig) {
	ing := &importIngester{}
	repo := &importVEXRepo{}
	svc := findingimport.NewService(ing, repo, repo, ingest.SourceResolveDryRun, logger.NewNop())
	q := &memQueue{}
	svc.SetQueue(q, func(context.Context, shared.ID, findingimport.Caller) (ingest.ActorScope, ingest.ActorScope, error) {
		if restricted {
			return importScope{}, importScope{}, nil
		}
		return nil, nil, nil
	}, nil)
	h := &FindingImportHandler{svc: svc, logger: logger.NewNop()}
	h.actorOf = func(context.Context, shared.ID) (ingest.ActorScope, error) {
		if restricted {
			return importScope{}, nil
		}
		return nil, nil
	}
	return h, ing, &importTestRig{svc: svc, queue: q}
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/imports"+query, body)
	req.Header.Set("Content-Type", ctype)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String())
	ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
	req = req.WithContext(ctx)
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

// A committed upload is stored and answered 202 with its receipt before
// anything is ingested; the worker then imports it with the uploader's
// scope, resolved when it runs.
func TestFindingImport_CommitRunsWithTheUploadersScope(t *testing.T) {
	h, ing, rig := newImportTestRig(true)
	body, ct := multipartBody(t, part{"file", "scan.nessus", []byte(importNessus)})
	rec := doImport(t, h, "", body, ct)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	accepted := decodeImport(t, rec)
	if accepted.Status != "queued" || accepted.ReceiptID == "" || rec.Header().Get("Location") != "/api/v1/findings/imports/"+accepted.ReceiptID {
		t.Fatalf("accept = %+v (Location %q)", accepted, rec.Header().Get("Location"))
	}
	if len(ing.calls) != 0 {
		t.Fatal("ingested in the request")
	}
	resp := rig.process(t)
	if len(ing.calls) != 1 || ing.calls[0].Options.Actor == nil || ing.calls[0].CoverageType != ingest.CoverageTypePartial {
		t.Fatalf("ingest = %+v", ing.calls)
	}
	if len(resp) != 1 || resp[0].Files[0].Ingest == nil || resp[0].Files[0].Ingest.FindingsCreated != 1 {
		t.Fatalf("result = %+v", resp)
	}
	if len(rig.queue.parts) != 0 {
		t.Fatal("stored parts left after the import")
	}
}

// An upload recorded without an uploader is never imported (the worker
// would otherwise resolve no scope at all).
func TestFindingImport_WorkerRefusesAnUploadWithoutAnUploader(t *testing.T) {
	_, ing, rig := newImportTestRig(false)
	env, _ := json.Marshal(findingimport.Envelope{SessionID: "s", Parts: []findingimport.EnvelopePart{{Part: 0, Name: "a"}}})
	job := ingestjob.NewUploadJob(shared.NewID(), shared.NewID(), ingestjob.KindFindingImport, shared.NewID().String(), "user:x", "import:x", env, make([]byte, 32))
	_ = rig.queue.StagePart(context.Background(), job.TenantID(), job.ID(), 0, "a", []byte(importNessus))
	_, err := rig.svc.ProcessImportJob(context.Background(), job)
	var perm *ingestjob.PermanentError
	if !errors.As(err, &perm) || perm.Code != findingimport.ImportErrorUploaderGone || len(ing.calls) != 0 {
		t.Fatalf("err = %v, ingests %d", err, len(ing.calls))
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
			// The parsers' refusals are the same in a preview and in the
			// worker; a preview answers them in the request.
			q := c.query
			if c.kind != "" {
				q = "?dry_run=true"
			}
			rec := doImport(t, h, q, body, ct)
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
		h, ing, rig := newImportTestRig(false)
		body, ct := multipartBody(t, part{"file", "a.zip", bomb})
		rec := doImport(t, h, "", body, ct)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		resp := rig.process(t)
		if resp[0].Files[0].Error == nil || resp[0].Files[0].Error.Kind != "too_large" || len(ing.calls) != 0 {
			t.Fatalf("bomb not refused: %+v", resp[0].Files[0])
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
	h, ing, rig := newImportTestRig(false)
	z := zipOf(t, map[string][]byte{"a/one.nessus": []byte(importNessus), "two.nessus": []byte(importNessus), "notes.txt": []byte("hello")})
	body, ct := multipartBody(t, part{"file", "batch.zip", z})
	rec := doImport(t, h, "", body, ct)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	resp := rig.process(t)[0]
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
		if got := findingimport.SafeName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A tenant at its queue limit gets 429 with Retry-After, and the refused
// upload leaves no receipt and no stored part.
func TestFindingImport_QueueFullIs429WithoutAReceipt(t *testing.T) {
	ing := &importIngester{}
	repo := &importVEXRepo{}
	svc := findingimport.NewService(ing, repo, repo, ingest.SourceResolveDryRun, logger.NewNop())
	q := &memQueue{admitErr: &ingestqueue.ErrQueueFull{RetryAfter: 30 * time.Second}}
	svc.SetQueue(q, func(context.Context, shared.ID, findingimport.Caller) (ingest.ActorScope, ingest.ActorScope, error) {
		return nil, nil, nil
	}, nil)
	h := &FindingImportHandler{svc: svc, logger: logger.NewNop()}
	h.actorOf = func(context.Context, shared.ID) (ingest.ActorScope, error) { return nil, nil }
	body, ct := multipartBody(t, part{"file", "scan.nessus", []byte(importNessus)})
	rec := doImport(t, h, "", body, ct)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "30" {
		t.Fatalf("status %d Retry-After %q: %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
	if repo.uploads != 0 || len(q.jobs) != 0 || len(q.parts) != 0 {
		t.Fatalf("receipts %d, jobs %d, parts %d after a refusal", repo.uploads, len(q.jobs), len(q.parts))
	}
}
