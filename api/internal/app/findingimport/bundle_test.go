package findingimport

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const osintSentinel = "NEVER-OPENED-SENTINEL@example.com"

func reconZip(t *testing.T, target string, extra map[string]string) []byte {
	t.Helper()
	files := map[string]string{
		"report/report.json":         `{"domain":"` + target + `","mode":"recon","generated_at":"2026-10-04T10:00:00Z"}`,
		".log/run.txt":               "reconFTW version: v4.0\n",
		"subdomains/subdomains.txt":  target + "\nwww." + target + "\nevil.net\n",
		"hosts/ips.txt":              "192.0.2.10\n",
		"webs/webs.txt":              "https://www." + target + "\nhttps://evil.net\n",
		"webs/url_extract.txt":       "https://www." + target + "/search?q=1\nhttps://evil.net/a?b=1\n",
		"osint/emails.txt":           osintSentinel + "\n",
		"osint/passwords.txt":        "hunter2-" + osintSentinel + "\n",
		"unknown/new_tool_output.md": "x\n",
	}
	for k, v := range extra {
		files[k] = v
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// coverNames covers the given names and anything under them, like a scope
// entry for a domain.
type coverNames struct {
	roots []string
	err   error
	asked [][]string
}

func (c *coverNames) CoverOf(_ context.Context, _ shared.ID, targets []string) (map[string]scopeauth.Via, error) {
	c.asked = append(c.asked, targets)
	if c.err != nil {
		return nil, c.err
	}
	out := map[string]scopeauth.Via{}
	for _, t := range targets {
		for _, r := range c.roots {
			if t == r || strings.HasSuffix(t, "."+r) {
				out[t] = scopeauth.Via{Kind: scopeauth.KindScopeTarget}
			}
		}
	}
	return out, nil
}

func importBundle(t *testing.T, svc *Service, req Request, body []byte) []FileResult {
	t.Helper()
	res, archive, refused := svc.ImportUpload(context.Background(), req, Upload{Name: "recon.zip", Body: bytes.NewReader(body), TempDir: t.TempDir()})
	if refused != nil {
		t.Fatalf("refused: %+v", refused)
	}
	if !archive {
		t.Fatal("not an archive")
	}
	return res
}

func scopeOf(t *testing.T, in ingest.Input) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, a := range in.Report.Assets {
		if v, ok := a.Properties[ingest.PropImportScope].(string); ok {
			out[a.Value] = v
		}
	}
	return out
}

func TestBundle_OneParseScopeFromOrganization(t *testing.T) {
	svc, ing, _ := newSvc(ingest.SourceResolveDryRun)
	svc.SetScopeCover(&coverNames{roots: []string{"example.com"}})
	req := Request{TenantID: shared.NewID(), ReceiptID: shared.NewID(), SessionID: "s"}
	res := importBundle(t, svc, req, reconZip(t, "example.com", nil))
	if len(res) != 1 || res[0].Error != nil {
		t.Fatalf("results %+v", res)
	}
	fr := res[0]
	if fr.Format != importer.FormatReconFTW || fr.Layout != "v4" {
		t.Fatalf("format %q layout %q", fr.Format, fr.Layout)
	}
	if len(ing.calls) != 1 {
		t.Fatalf("ingest calls %d, want one for the whole bundle", len(ing.calls))
	}
	in := ing.calls[0]
	if in.Options.SourceName != "import:reconftw" {
		t.Fatalf("source %q", in.Options.SourceName)
	}
	if in.CoverageType != ingest.CoverageTypePartial {
		t.Fatalf("coverage %q", in.CoverageType)
	}
	sc := scopeOf(t, in)
	if sc["www.example.com"] != "in_target" || sc["evil.net"] != "outside_target" || sc["192.0.2.10"] != "unknown" {
		t.Fatalf("scope verdicts %v", sc)
	}
	if fr.Candidates == 0 {
		t.Fatal("no candidates counted")
	}
	// Policy skips and unmapped files are reported, not read.
	var skipped []string
	for _, sp := range fr.SkippedByPolicy {
		skipped = append(skipped, sp.Path)
	}
	if !strings.Contains(strings.Join(skipped, ","), "osint/emails.txt") {
		t.Fatalf("osint not listed as skipped: %v", skipped)
	}
	if !strings.Contains(strings.Join(fr.Unmapped, ","), "unknown/new_tool_output.md") {
		t.Fatalf("unmapped %v", fr.Unmapped)
	}
}

// The file's own claim of its target never puts a host in scope.
func TestBundle_FileClaimedTargetGrantsNothing(t *testing.T) {
	svc, ing, _ := newSvc(ingest.SourceResolveDryRun)
	svc.SetScopeCover(&coverNames{roots: []string{"example.com"}})
	req := Request{TenantID: shared.NewID(), ReceiptID: shared.NewID(), SessionID: "s"}
	importBundle(t, svc, req, reconZip(t, "victim.org", nil))
	for host, v := range scopeOf(t, ing.calls[0]) {
		if v == "in_target" {
			t.Fatalf("%s is in_target without a scope entry", host)
		}
	}
}

// Unreadable or missing scope: every host is a candidate (fail closed).
func TestBundle_ScopeUnavailableHoldsEverything(t *testing.T) {
	for name, cover := range map[string]ScopeCover{"nil": nil, "error": &coverNames{err: errors.New("db down")}} {
		t.Run(name, func(t *testing.T) {
			svc, ing, _ := newSvc(ingest.SourceResolveDryRun)
			if cover != nil {
				svc.SetScopeCover(cover)
			}
			req := Request{TenantID: shared.NewID(), ReceiptID: shared.NewID(), SessionID: "s"}
			importBundle(t, svc, req, reconZip(t, "example.com", nil))
			for host, v := range scopeOf(t, ing.calls[0]) {
				if v == "in_target" {
					t.Fatalf("%s in_target", host)
				}
			}
		})
	}
}

// Scope is asked for the uploader's tenant only.
func TestBundle_ScopeAskedForTheTenant(t *testing.T) {
	svc, _, _ := newSvc(ingest.SourceResolveDryRun)
	var got shared.ID
	svc.SetScopeCover(coverFunc(func(_ context.Context, tid shared.ID, _ []string) (map[string]scopeauth.Via, error) {
		got = tid
		return nil, nil
	}))
	req := Request{TenantID: shared.NewID(), ReceiptID: shared.NewID(), SessionID: "s"}
	importBundle(t, svc, req, reconZip(t, "example.com", nil))
	if got != req.TenantID {
		t.Fatalf("scope read for %v, want %v", got, req.TenantID)
	}
}

type coverFunc func(context.Context, shared.ID, []string) (map[string]scopeauth.Via, error)

func (f coverFunc) CoverOf(ctx context.Context, tid shared.ID, t []string) (map[string]scopeauth.Via, error) {
	return f(ctx, tid, t)
}

// People and credential files are never opened: nothing from them reaches
// the report, the results or the receipt.
func TestBundle_OsintNeverRead(t *testing.T) {
	svc, ing, repo := newSvc(ingest.SourceResolveDryRun)
	req := Request{TenantID: shared.NewID(), ReceiptID: shared.NewID(), SessionID: "s"}
	res := importBundle(t, svc, req, reconZip(t, "example.com", nil))
	for name, v := range map[string]any{"report": ing.calls[0].Report, "result": res, "finished": repo.finished} {
		b, _ := json.Marshal(v)
		if bytes.Contains(b, []byte("SENTINEL")) {
			t.Fatalf("osint content reached the %s", name)
		}
	}
}

// A bundle is partial coverage: full coverage is refused, and a finished
// upload closes nothing even when a caller reaches FinishUpload with it.
func TestBundle_PartialNeverCloses(t *testing.T) {
	svc, ing, _ := newSvc(ingest.SourceResolveDryRun)
	req := Request{TenantID: shared.NewID(), ReceiptID: shared.NewID(), SessionID: "s",
		Coverage: Coverage{Full: true, AssetIDs: []shared.ID{shared.NewID()}}}
	_, _, refused := svc.ImportUpload(context.Background(), req, Upload{Name: "r.zip", Body: bytes.NewReader(reconZip(t, "example.com", nil)), TempDir: t.TempDir()})
	if refused == nil || len(ing.calls) != 0 {
		t.Fatalf("full coverage was not refused (calls %d)", len(ing.calls))
	}

	repo := &coverageFake{assets: 1, open: 2, stale: []shared.ID{shared.NewID()}}
	s2 := NewService(&fakeIngester{}, repo, repo, ingest.SourceResolveDryRun, logger.NewNop())
	s2.FinishUpload(context.Background(), coverageReq(), []FileResult{{Format: importer.FormatReconFTW, Tool: "reconftw", Ingest: &ingest.Output{}}}, true)
	if len(repo.resolved) != 0 || len(repo.finished) != 1 || repo.finished[0].Coverage == ingestreceipt.CoverageFull {
		t.Fatalf("a bundle closed findings or claimed full coverage: %+v", repo.finished)
	}
}

// The receipt counts the files skipped by policy with the skipped records.
func TestBundle_ReceiptCountsSkipped(t *testing.T) {
	svc, _, repo := newSvc(ingest.SourceResolveDryRun)
	req := Request{TenantID: shared.NewID(), ReceiptID: shared.NewID(), SessionID: "s"}
	res := importBundle(t, svc, req, reconZip(t, "example.com", nil))
	svc.FinishUpload(context.Background(), req, res, true)
	if len(repo.finished) != 1 || repo.finished[0].Skipped < res[0].SkippedByPolicyTotal || res[0].SkippedByPolicyTotal == 0 {
		t.Fatalf("receipt skipped %+v, policy skips %d", repo.finished, res[0].SkippedByPolicyTotal)
	}
}

// A preview parses and judges scope but writes nothing.
func TestBundle_PreviewWritesNothing(t *testing.T) {
	svc, ing, repo := newSvc(ingest.SourceResolveDryRun)
	res := importBundle(t, svc, Request{TenantID: shared.NewID(), DryRun: true, SessionID: "s"}, reconZip(t, "example.com", nil))
	if len(ing.calls) != 0 || len(repo.created) != 0 {
		t.Fatal("a preview wrote")
	}
	if res[0].Layout != "v4" || res[0].Stats.Endpoints == 0 || len(res[0].SkippedByPolicy) == 0 {
		t.Fatalf("preview %+v", res[0])
	}
}

// A zip that is not a recon directory still takes the per-file path.
func TestBundle_PlainZipUnchanged(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("a.nessus")
	_, _ = w.Write([]byte(nessusDoc))
	_ = zw.Close()
	svc, ing, _ := newSvc(ingest.SourceResolveDryRun)
	res := importBundle(t, svc, Request{TenantID: shared.NewID(), ReceiptID: shared.NewID(), SessionID: "s"}, buf.Bytes())
	if len(res) != 1 || res[0].Layout != "" || len(ing.calls) != 1 {
		t.Fatalf("%+v", res)
	}
}

// Findings on hosts outside the scope stay visible and carry the label.
func TestBundle_FindingsOnCandidatesAreLabelled(t *testing.T) {
	nuclei := func(host string) string {
		return `{"template-id":"t1","info":{"name":"N","severity":"high"},"host":"https://` + host + `","matched-at":"https://` + host + `/","type":"http"}` + "\n"
	}
	svc, ing, _ := newSvc(ingest.SourceResolveDryRun)
	svc.SetScopeCover(&coverNames{roots: []string{"example.com"}})
	req := Request{TenantID: shared.NewID(), ReceiptID: shared.NewID(), SessionID: "s"}
	importBundle(t, svc, req, reconZip(t, "example.com", map[string]string{
		"nuclei_output/high_json.txt": nuclei("www.example.com") + nuclei("evil.net"),
	}))
	if len(ing.calls[0].Report.Findings) != 2 {
		t.Fatalf("findings %d", len(ing.calls[0].Report.Findings))
	}
	var in, out int
	for _, f := range ing.calls[0].Report.Findings {
		isTagged := slices.Contains(f.Tags, TagCandidate)
		for _, a := range ing.calls[0].Report.Assets {
			if a.ID == f.AssetRef {
				if strings.Contains(a.Value, "evil.net") && isTagged {
					out++
				}
				if strings.Contains(a.Value, "www.example.com") && !isTagged {
					in++
				}
			}
		}
	}
	if in != 1 || out != 1 {
		t.Fatalf("labels wrong: in-scope untagged %d, outside tagged %d", in, out)
	}
}
