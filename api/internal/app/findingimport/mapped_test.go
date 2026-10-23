package findingimport

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	appimportmapping "github.com/openctemio/openctem/api/internal/app/importmapping"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	dom "github.com/openctemio/openctem/api/pkg/domain/importmapping"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func resolvedCSV(t *testing.T) *appimportmapping.Resolved {
	t.Helper()
	doc := `{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "identity": ["title", "asset_value"],
	  "records": [{"kind": "finding", "set": {"title": "/title", "severity": {"path": "/severity", "lower": true}, "asset_value": "/host", "asset_type": {"const": "host"}}}]}`
	m, problems := dom.Compile([]byte(doc))
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	return &appimportmapping.Resolved{
		Mapping:  &dom.Mapping{ID: shared.NewID(), Name: "legacy-vm", Source: "csv", LatestVersion: 2},
		Version:  &dom.Version{Version: 2},
		Compiled: m,
	}
}

// An upload through a mapping is converted by the mapping, recorded as
// "mapped:<name>", and ingested as partial coverage whatever it says.
func TestImportFile_Mapping(t *testing.T) {
	svc, ing, _ := newSvc(ingest.SourceResolveDryRun)
	mp := resolvedCSV(t)
	req := Request{TenantID: shared.NewID(), SessionID: "s", Mapping: mp, Format: "mapping:legacy-vm@2", MinSeverity: ctis.SeverityMedium}
	in := "title,severity,host\nOpenSSL,High,web-01.example.com\nBanner,info,web-01.example.com\n,high,x\n"
	fr := svc.ImportFile(context.Background(), req, 0, "export.csv", strings.NewReader(in), nil)
	if fr.Error != nil {
		t.Fatalf("%+v", fr.Error)
	}
	if fr.Format != "mapping:legacy-vm@2" || fr.Stats.Findings != 1 || fr.Stats.Skipped < 1 {
		t.Fatalf("result %+v", fr)
	}
	if len(ing.calls) != 1 {
		t.Fatalf("ingest calls %d", len(ing.calls))
	}
	call := ing.calls[0]
	if call.CoverageType != ingest.CoverageTypePartial || call.Report.Metadata.CoverageType != string(ingest.CoverageTypePartial) {
		t.Fatalf("coverage %q / %q", call.CoverageType, call.Report.Metadata.CoverageType)
	}
	if call.Options.SourceName != "mapped:legacy-vm" || call.Report.Tool == nil || call.Report.Tool.Name != "mapped:legacy-vm" {
		t.Fatalf("source %q tool %+v", call.Options.SourceName, call.Report.Tool)
	}
	if f := call.Report.Findings[0]; f.Title != "OpenSSL" || f.AssetValue != "web-01.example.com" {
		t.Fatalf("finding %+v", f)
	}
}

// A mapping applies to one file: an archive is refused, and a hostile
// file is refused with its error class.
func TestImportFile_MappingRefusals(t *testing.T) {
	svc, _, _ := newSvc(ingest.SourceResolveDryRun)
	mp := resolvedCSV(t)
	zip := "PK\x03\x04" + strings.Repeat("\x00", 64)
	fr := svc.ImportFile(context.Background(), Request{TenantID: shared.NewID(), SessionID: "s", Mapping: mp, Format: "mapping:legacy-vm@2"}, 0, "a.zip", strings.NewReader(zip), nil)
	if fr.Error == nil || fr.Error.Kind != KindMalformed {
		t.Fatalf("archive: %+v", fr.Error)
	}
	fr = svc.ImportFile(context.Background(), Request{TenantID: shared.NewID(), SessionID: "s", Mapping: mp, Format: "mapping:legacy-vm@2"}, 0, "a.csv", strings.NewReader("\xff\xfet\x00"), nil)
	if fr.Error == nil {
		t.Fatal("UTF-16 accepted")
	}
}

// A CI run's repository is the asset of a mapped record that names none.
func TestConvert_MappingRepositoryDefault(t *testing.T) {
	mp := resolvedCSV(t)
	var got *Converted
	_, refused := Convert(context.Background(), Upload{Name: "r", Body: strings.NewReader("title,severity\nX,high\n"), Mapping: mp,
		ReportIDPrefix: "run", Repository: "github.com/example/app"}, func(c Converted) { got = &c })
	if refused != nil || got == nil || got.Error != nil {
		t.Fatalf("refused %+v got %+v", refused, got)
	}
	f := got.Result.Report.Findings[0]
	if f.AssetValue != "github.com/example/app" || f.AssetType != ctis.AssetTypeRepository {
		t.Fatalf("finding %+v", f)
	}
}
