package findingimport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeIngester struct {
	calls   []ingest.Input
	sensors []*sensor.Sensor
	err     error
}

func (f *fakeIngester) Ingest(_ context.Context, agt *sensor.Sensor, in ingest.Input) (*ingest.Output, error) {
	f.calls = append(f.calls, in)
	f.sensors = append(f.sensors, agt)
	if f.err != nil {
		return nil, f.err
	}
	m := map[string]shared.ID{}
	for _, a := range in.Report.Assets {
		m[a.ID] = shared.NewID()
	}
	return &ingest.Output{FindingsCreated: len(in.Report.Findings), AssetsCreated: len(in.Report.Assets), AssetMap: m}, nil
}

type applyCall struct {
	ids     []shared.ID
	vex     vulnerability.InteropVEX
	closeIt bool
}

type fakeRepo struct {
	created  []vulnerability.FindingImport
	finished []vulnerability.FindingImport
	stamped  []shared.ID
	cands    []vulnerability.VEXCandidate
	// assetName names the candidates' assets, for AssetNames queries.
	assetName map[shared.ID]string
	queries   []vulnerability.VEXDocumentQuery
	applies   []applyCall
}

func (f *fakeRepo) CreateFindingImport(_ context.Context, rec *vulnerability.FindingImport) error {
	f.created = append(f.created, *rec)
	return nil
}

func (f *fakeRepo) FinishFindingImport(_ context.Context, rec *vulnerability.FindingImport) error {
	f.finished = append(f.finished, *rec)
	return nil
}

func (f *fakeRepo) StampAssetsImport(_ context.Context, _, _ shared.ID, ids []shared.ID) (int64, error) {
	f.stamped = append(f.stamped, ids...)
	return int64(len(ids)), nil
}

func (f *fakeRepo) MatchVEXDocument(_ context.Context, _ shared.ID, q vulnerability.VEXDocumentQuery, _ int) ([]vulnerability.VEXCandidate, error) {
	f.queries = append(f.queries, q)
	if len(q.AssetNames) == 0 {
		return append([]vulnerability.VEXCandidate(nil), f.cands...), nil
	}
	var out []vulnerability.VEXCandidate
	for _, c := range f.cands {
		for _, n := range q.AssetNames {
			if f.assetName[c.AssetID] == n {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func (f *fakeRepo) ApplyVEXDocument(_ context.Context, _ shared.ID, ids []shared.ID, v vulnerability.InteropVEX, closeIt bool, _ string) ([]shared.ID, []shared.ID, error) {
	f.applies = append(f.applies, applyCall{ids: ids, vex: v, closeIt: closeIt})
	var closed []shared.ID
	if closeIt {
		for _, c := range f.cands {
			for _, id := range ids {
				if c.ID == id && openStatuses[c.Status] && !protectedSources[c.Source] {
					closed = append(closed, id)
				}
			}
		}
	}
	return ids, closed, nil
}

// onlyAssets is an actor whose scope is a fixed asset set.
type onlyAssets map[shared.ID]bool

func (o onlyAssets) AssetsInScope(_ context.Context, ids []shared.ID) ([]shared.ID, error) {
	var out []shared.ID
	for _, id := range ids {
		if o[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// ctisFixture returns a fixture of the pinned ctis module (its importer
// golden inputs), from the module cache.
func ctisFixture(t *testing.T, rel string) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/openctemio/ctis").Output()
	if err != nil {
		t.Skipf("ctis module not resolvable: %v", err)
	}
	p := filepath.Join(strings.TrimSpace(string(out)), "testdata", "importers", rel)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("ctis fixture not available: %v", err)
	}
	return p
}

const nessusDoc = `<?xml version="1.0"?>
<NessusClientData_v2><Report name="r"><ReportHost name="192.0.2.5"><HostProperties><tag name="host-ip">192.0.2.5</tag></HostProperties>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="3" pluginID="1001" pluginName="OpenSSH issue" pluginFamily="General"><cve>CVE-2024-0001</cve></ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Scan info" pluginFamily="Settings"/>
</ReportHost></Report></NessusClientData_v2>`

func newSvc(mode ingest.VEXMode) (*Service, *fakeIngester, *fakeRepo) {
	ing := &fakeIngester{}
	repo := &fakeRepo{}
	return NewService(ing, repo, mode, logger.NewNop()), ing, repo
}

func TestImportFile_PreviewWritesNothing(t *testing.T) {
	svc, ing, repo := newSvc(ingest.SourceResolveEnforce)
	fr := svc.ImportFile(context.Background(), Request{TenantID: shared.NewID(), DryRun: true, SessionID: "s"}, 0, "a.nessus", strings.NewReader(nessusDoc), nil)
	if fr.Error != nil {
		t.Fatal(fr.Error.Message)
	}
	if fr.Format != importer.FormatNessus || fr.Stats.Findings != 2 || fr.Stats.Assets != 1 {
		t.Fatalf("stats = %+v format %s", fr.Stats, fr.Format)
	}
	if len(ing.calls) != 0 || len(repo.applies) != 0 || fr.Ingest != nil {
		t.Fatal("a preview wrote")
	}
}

func TestImportFile_CommitIsPartialWithTheUploadersScope(t *testing.T) {
	svc, ing, _ := newSvc(ingest.SourceResolveDryRun)
	tid := shared.NewID()
	actor := onlyAssets{}
	fr := svc.ImportFile(context.Background(), Request{TenantID: tid, Actor: actor, SessionID: "sess", MinSeverity: ctis.SeverityLow}, 3, "a.nessus", strings.NewReader(nessusDoc), nil)
	if fr.Error != nil {
		t.Fatal(fr.Error.Message)
	}
	if len(ing.calls) != 1 {
		t.Fatalf("ingest calls = %d", len(ing.calls))
	}
	in := ing.calls[0]
	if in.CoverageType != ingest.CoverageTypePartial || in.Report.Metadata.CoverageType != "partial" || in.Report.Metadata.Branch != nil {
		t.Fatal("an upload must never be full coverage (no auto-resolve)")
	}
	if in.Options.Actor == nil {
		t.Fatal("the uploader's scope was not passed to ingest")
	}
	if *ing.sensors[0].TenantID != tid {
		t.Fatal("ingest ran for another tenant")
	}
	if in.Report.Metadata.ID != fr.ImportID || fr.ImportID == "" {
		t.Fatalf("report id = %q", in.Report.Metadata.ID)
	}
	if len(in.Report.Findings) != 1 || fr.Stats.Skipped != 1 {
		t.Fatalf("min severity not applied: %d findings, %d skipped", len(in.Report.Findings), fr.Stats.Skipped)
	}
}

// TestImportFile_RealFixtures imports every input fixture of the pinned
// ctis importers (all formats it ships), with its Qualys KnowledgeBase
// companion when there is one.
func TestImportFile_RealFixtures(t *testing.T) {
	root := ctisFixture(t, "")
	inputs, err := filepath.Glob(filepath.Join(root, "*", "*"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range inputs {
		base := filepath.Base(p)
		if strings.HasSuffix(base, ".golden.json") || strings.HasSuffix(base, ".result.json") || strings.HasSuffix(base, ".kb.xml") {
			continue
		}
		n++
		t.Run(filepath.Base(filepath.Dir(p))+"/"+base, func(t *testing.T) {
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			var kb io.Reader
			if b, err := os.ReadFile(strings.TrimSuffix(p, filepath.Ext(p)) + ".kb.xml"); err == nil {
				kb = bytes.NewReader(b)
			}
			svc, ing, _ := newSvc(ingest.SourceResolveDryRun)
			fr := svc.ImportFile(context.Background(), Request{TenantID: shared.NewID(), SessionID: "s"}, 0, base, f, kb)
			if fr.Error != nil {
				t.Fatalf("%+v", fr.Error)
			}
			if fr.Stats.Findings+fr.Stats.Components+fr.Stats.Statements == 0 {
				t.Fatal("fixture imported nothing")
			}
			for _, in := range ing.calls {
				if err := in.Report.Validate(); err != nil {
					t.Fatalf("invalid report: %v", err)
				}
			}
		})
	}
	if n == 0 {
		t.Fatal("no fixture")
	}
}

func TestImportFile_Errors(t *testing.T) {
	svc, ing, _ := newSvc(ingest.SourceResolveDryRun)
	cases := map[string]struct {
		in   string
		kind string
	}{
		"unknown":  {"hello world", "unknown_format"},
		"xxe":      {`<?xml version="1.0"?><!DOCTYPE NessusClientData_v2 [<!ENTITY x SYSTEM "file:///etc/passwd">]><NessusClientData_v2/>`, "unsafe"},
		"deep":     {`<?xml version="1.0"?><NessusClientData_v2>` + strings.Repeat("<a>", 5000) + `</NessusClientData_v2>`, "too_large"},
		"truncate": {"<?xml version=\"1.0\"?>\n<NessusClientData_v2>\n<Report>\n<ReportHost name=\"a\"", "malformed"},
	}
	for name, c := range cases {
		fr := svc.ImportFile(context.Background(), Request{TenantID: shared.NewID(), SessionID: "s"}, 0, name, strings.NewReader(c.in), nil)
		if fr.Error == nil || fr.Error.Kind != c.kind {
			t.Errorf("%s: error = %+v, want kind %s", name, fr.Error, c.kind)
		}
	}
	fr := svc.ImportFile(context.Background(), Request{TenantID: shared.NewID(), SessionID: "s"}, 0, "t", strings.NewReader("<?xml version=\"1.0\"?>\n<NessusClientData_v2>\n<Report>\n<ReportHost name=\"a\"\n"), nil)
	if fr.Error == nil || fr.Error.Line == 0 {
		t.Errorf("malformed file has no line: %+v", fr.Error)
	}
	if len(ing.calls) != 0 {
		t.Fatal("a refused file was ingested")
	}
	ing.err = errors.New("db down")
	fr = svc.ImportFile(context.Background(), Request{TenantID: shared.NewID(), SessionID: "s"}, 0, "a", strings.NewReader(nessusDoc), nil)
	if fr.Error == nil || strings.Contains(fr.Error.Message, "db down") {
		t.Errorf("internal error leaked or missing: %+v", fr.Error)
	}
}

func notAffected(purl string) importer.VEXStatement {
	return importer.VEXStatement{
		VulnerabilityIDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-0001"}, {Type: ctis.VulnerabilityIDGHSA, ID: "GHSA-aaaa-bbbb-cccc"}},
		Products:         []importer.Product{{PURL: purl}},
		VEX:              ctis.VEX{Status: ctis.VEXStatusNotAffected, Justification: ctis.VEXJustificationVulnerableCodeNotInExecutePath, Source: "doc-1"},
	}
}

func TestApplyVEX_Modes(t *testing.T) {
	assetA, assetB := shared.NewID(), shared.NewID()
	open1, open2, pentest, resolved := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	cands := []vulnerability.VEXCandidate{
		{ID: open1, AssetID: assetA, Status: "open", Source: "sca"},
		{ID: open2, AssetID: assetB, Status: "new", Source: "sca"},
		{ID: pentest, AssetID: assetA, Status: "open", Source: "pentest"},
		{ID: resolved, AssetID: assetA, Status: "resolved", Source: "sca"},
	}
	stmts := []importer.VEXStatement{notAffected("pkg:npm/lodash@4.17.20")}
	cases := []struct {
		name               string
		mode               ingest.VEXMode
		canApprove, dryRun bool
		actor              ingest.ActorScope
		wantApplies        int
		wantClose          bool
		wantClosed, wantWC int
		wantMatched        int
	}{
		{"enforce with approve closes open non-human", ingest.SourceResolveEnforce, true, false, nil, 1, true, 2, 0, 4},
		{"enforce without approve never closes", ingest.SourceResolveEnforce, false, false, nil, 1, false, 0, 2, 4},
		{"dry_run mode counts", ingest.SourceResolveDryRun, true, false, nil, 1, false, 0, 2, 4},
		{"off stores only", ingest.SourceResolveOff, true, false, nil, 1, false, 0, 0, 4},
		{"preview writes nothing", ingest.SourceResolveEnforce, true, true, nil, 0, false, 0, 2, 4},
		{"restricted uploader only its assets", ingest.SourceResolveEnforce, true, false, onlyAssets{assetB: true}, 1, true, 1, 0, 1},
		{"scopeless uploader touches nothing", ingest.SourceResolveEnforce, true, false, onlyAssets{}, 0, false, 0, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, _, repo := newSvc(c.mode)
			repo.cands = cands
			sum, err := svc.applyVEX(context.Background(), Request{TenantID: shared.NewID(), CanApprove: c.canApprove, DryRun: c.dryRun, Actor: c.actor}, stmts)
			if err != nil {
				t.Fatal(err)
			}
			if len(repo.applies) != c.wantApplies {
				t.Fatalf("applies = %d, want %d", len(repo.applies), c.wantApplies)
			}
			if c.wantApplies > 0 && repo.applies[0].closeIt != c.wantClose {
				t.Fatalf("close = %v, want %v", repo.applies[0].closeIt, c.wantClose)
			}
			if c.actor != nil && c.wantApplies > 0 {
				for _, id := range repo.applies[0].ids {
					if id != open2 {
						t.Fatalf("applied to an out-of-scope finding %s", id)
					}
				}
			}
			if sum.Matched != c.wantMatched || sum.Closed != c.wantClosed || sum.WouldClose != c.wantWC {
				t.Fatalf("summary = %+v", sum)
			}
		})
	}
	// The query carries the ids and the version-less product.
	svc, _, repo := newSvc(ingest.SourceResolveEnforce)
	repo.cands = cands
	if _, err := svc.applyVEX(context.Background(), Request{TenantID: shared.NewID()}, stmts); err != nil {
		t.Fatal(err)
	}
	q := repo.queries[0]
	if strings.Join(q.IDs, ",") != "CVE-2024-0001,GHSA-AAAA-BBBB-CCCC" || q.Products[0] != (vulnerability.VEXProduct{Base: "pkg:npm/lodash", Version: "4.17.20"}) {
		t.Fatalf("query = %+v", q)
	}
}

func TestApplyVEX_Unmatchable(t *testing.T) {
	svc, _, repo := newSvc(ingest.SourceResolveEnforce)
	st := notAffected("")
	st.Products = []importer.Product{{CPE: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}}
	noID := notAffected("pkg:npm/x@1")
	noID.VulnerabilityIDs = nil
	sum, err := svc.applyVEX(context.Background(), Request{TenantID: shared.NewID()}, []importer.VEXStatement{st, noID})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Unmatchable != 2 || len(repo.queries) != 0 {
		t.Fatalf("summary = %+v, queries %d", sum, len(repo.queries))
	}
}

// A statement about a component inside product X never touches the same
// package's finding on asset Y.
func TestApplyVEX_SubcomponentsOnlyInsideTheProduct(t *testing.T) {
	imageX, imageY := shared.NewID(), shared.NewID()
	onX, onY := shared.NewID(), shared.NewID()
	svc, _, repo := newSvc(ingest.SourceResolveEnforce)
	repo.cands = []vulnerability.VEXCandidate{
		{ID: onX, AssetID: imageX, Status: "open", Source: "sca"},
		{ID: onY, AssetID: imageY, Status: "open", Source: "sca"},
	}
	repo.assetName = map[shared.ID]string{imageX: "registry.example.com/shop:1.2", imageY: "registry.example.com/other:3"}
	st := notAffected("")
	st.Products = []importer.Product{{Name: "registry.example.com/shop", Version: "1.2",
		Subcomponents: []importer.Product{{PURL: "pkg:npm/lodash@4.17.20"}}}}
	sum, err := svc.applyVEX(context.Background(), Request{TenantID: shared.NewID(), CanApprove: true}, []importer.VEXStatement{st})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Matched != 1 || sum.Closed != 1 || len(repo.applies) != 1 || len(repo.applies[0].ids) != 1 || repo.applies[0].ids[0] != onX {
		t.Fatalf("summary %+v, applies %+v", sum, repo.applies)
	}
	if len(repo.queries) != 1 || len(repo.queries[0].AssetNames) == 0 {
		t.Fatalf("the subcomponent query is not restricted to the product: %+v", repo.queries)
	}

	// A product with subcomponents but no name or PURL matches nothing,
	// rather than everything.
	svc, _, repo = newSvc(ingest.SourceResolveEnforce)
	repo.cands = []vulnerability.VEXCandidate{{ID: onY, AssetID: imageY, Status: "open", Source: "sca"}}
	st.Products = []importer.Product{{CPE: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", Subcomponents: []importer.Product{{PURL: "pkg:npm/lodash@4.17.20"}}}}
	sum, err = svc.applyVEX(context.Background(), Request{TenantID: shared.NewID(), CanApprove: true}, []importer.VEXStatement{st})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Unmatchable != 1 || len(repo.queries) != 0 || len(repo.applies) != 0 {
		t.Fatalf("summary %+v, queries %d", sum, len(repo.queries))
	}
}

func TestProductAssetNames(t *testing.T) {
	got := productAssetNames(importer.Product{Name: "Shop", Version: "1.2", PURL: "pkg:oci/shop@sha256%3Aabc?repository_url=r"})
	want := "shop,shop:1.2,pkg:oci/shop@sha256%3aabc?repository_url=r,pkg:oci/shop,pkg:oci/shop@sha256%3aabc,r"
	if strings.Join(got, ",") != want {
		t.Fatalf("names = %v", got)
	}
}

// A committed file gets an import record before anything is written: the
// uploader, the format, a hash of the name (never the name), the counts;
// the report id (the findings' scan_id) is the import id and the written
// assets are stamped. A preview records nothing.
func TestImportFile_RecordsTheProducer(t *testing.T) {
	svc, ing, repo := newSvc(ingest.SourceResolveDryRun)
	uid := shared.NewID()
	tid := shared.NewID()
	fr := svc.ImportFile(context.Background(), Request{TenantID: tid, ActorUserID: &uid, DryRun: true, SessionID: "s"}, 0, "secret-name.nessus", strings.NewReader(nessusDoc), nil)
	if fr.ImportID != "" || len(repo.created) != 0 || len(repo.stamped) != 0 {
		t.Fatal("a preview recorded an import")
	}
	fr = svc.ImportFile(context.Background(), Request{TenantID: tid, ActorUserID: &uid, SessionID: "s"}, 0, "secret-name.nessus", strings.NewReader(nessusDoc), nil)
	if fr.Error != nil || fr.ImportID == "" || len(repo.created) != 1 {
		t.Fatalf("import = %+v, records %d", fr.Error, len(repo.created))
	}
	rec := repo.created[0]
	if rec.ID.String() != fr.ImportID || rec.TenantID != tid || rec.ActorUserID == nil || *rec.ActorUserID != uid || rec.Format != "nessus" {
		t.Fatalf("record = %+v", rec)
	}
	if len(rec.FilenameSHA256) != 64 || strings.Contains(rec.FilenameSHA256, "secret") {
		t.Fatalf("file name not hashed: %q", rec.FilenameSHA256)
	}
	if ing.calls[0].Report.Metadata.ID != fr.ImportID {
		t.Fatalf("report id %q is not the import id", ing.calls[0].Report.Metadata.ID)
	}
	if len(repo.stamped) != 1 || len(repo.finished) != 1 || repo.finished[0].FindingsCreated != 2 || repo.finished[0].AssetsCreated != 1 {
		t.Fatalf("stamped %v finished %+v", repo.stamped, repo.finished)
	}

	// A restricted uploader stamps only the assets in their scope.
	svc, _, repo = newSvc(ingest.SourceResolveDryRun)
	_ = svc.ImportFile(context.Background(), Request{TenantID: tid, Actor: onlyAssets{}, SessionID: "s"}, 0, "a", strings.NewReader(nessusDoc), nil)
	if len(repo.stamped) != 0 {
		t.Fatalf("stamped out-of-scope assets: %v", repo.stamped)
	}
}
