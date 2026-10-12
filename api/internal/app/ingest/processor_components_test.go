package ingest

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
)

type fakePackageWriter struct {
	snaps   []software.PackageSnapshot
	tenants []shared.ID
	err     error
}

func (f *fakePackageWriter) WritePackages(_ context.Context, tenantID shared.ID, snap software.PackageSnapshot) (software.PackageWriteResult, error) {
	f.tenants = append(f.tenants, tenantID)
	f.snaps = append(f.snaps, snap)
	if f.err != nil {
		return software.PackageWriteResult{}, f.err
	}
	return software.PackageWriteResult{Links: len(snap.Packages), Versions: 1}, nil
}

func (f *fakePackageWriter) EnsurePackageVersion(context.Context, shared.ID, software.PURL) (shared.ID, error) {
	return shared.NewID(), nil
}

func TestDependencyNodes(t *testing.T) {
	deps := []ctis.Dependency{
		{ID: "app", Name: "app", Relationship: "root", DependsOn: []string{"express-id"}},
		{ID: "express-id", Name: "express", Version: "4.18.0", PURL: "pkg:npm/express@4.18.0",
			Licenses: []string{"MIT"}, DependsOn: []string{"pkg:npm/debug@2.6.9"}, Path: "package-lock.json"},
		{ID: "debug-id", Name: "debug", Version: "2.6.9", PURL: "pkg:npm/debug@2.6.9", Relationship: "indirect",
			Properties: ctis.Properties{"dev": true}},
		{Name: "requests", Version: "2.31.0", Ecosystem: "pip", Relationship: "direct"},
		{Name: "", Version: "1"},
		{Name: "bad", PURL: "pkg:/nope", Ecosystem: ""},
	}
	nodes, ok := DependencyNodes(deps)
	if ok[0] {
		t.Fatal("the root entry (the project itself) must not become a package")
	}
	if !ok[1] || nodes[1].Relationship != software.RelationshipDirect || nodes[1].Location != "package-lock.json" {
		t.Fatalf("express: %+v", nodes[1])
	}
	if nodes[1].PURL.String() != "pkg:npm/express@4.18.0" || len(nodes[1].Licenses) != 1 {
		t.Fatalf("express identity: %+v", nodes[1])
	}
	if nodes[2].Relationship != software.RelationshipTransitive || nodes[2].Scope != software.ScopeDevelopment {
		t.Fatalf("debug: %+v", nodes[2])
	}
	if !ok[3] || !nodes[3].Synthetic || nodes[3].PURL.String() != "pkg:pypi/requests@2.31.0" {
		t.Fatalf("requests without a purl: %+v", nodes[3])
	}
	if ok[4] {
		t.Fatal("an entry without a name must be skipped")
	}
	if !ok[5] || nodes[5].PURL.Type != "generic" {
		t.Fatalf("an invalid purl falls back to the name: %+v", nodes[5])
	}
}

func TestComponentProcessor_ProcessBatch_PerAsset(t *testing.T) {
	w := &fakePackageWriter{}
	p := NewComponentProcessor(w, slog.Default())
	tenant := shared.NewID()
	a1, a2 := shared.NewID(), shared.NewID()
	report := &ctis.Report{
		Assets: []ctis.Asset{{ID: "r1", Value: "svc-one"}, {ID: "r2", Value: "svc-two"}},
		Dependencies: []ctis.Dependency{
			{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", Path: "svc-one/package-lock.json"},
			{Name: "flask", Version: "3.0.0", PURL: "pkg:pypi/flask@3.0.0", Path: "svc-two/requirements.txt"},
			{Name: "chalk", Version: "5.0.0", PURL: "pkg:npm/chalk@5.0.0", Path: "svc-one/package-lock.json"},
		},
	}
	out := &Output{}
	if err := p.ProcessBatch(context.Background(), tenant, report, map[string]shared.ID{"r1": a1, "r2": a2}, software.ChannelSensor, out); err != nil {
		t.Fatal(err)
	}
	if len(w.snaps) != 2 {
		t.Fatalf("want one snapshot per asset, got %d", len(w.snaps))
	}
	got := map[shared.ID]int{}
	for i, s := range w.snaps {
		if w.tenants[i] != tenant {
			t.Fatal("snapshot written for another tenant")
		}
		if !s.Replace || s.Channel != software.ChannelSensor {
			t.Fatalf("snapshot %+v", s)
		}
		got[s.AssetID] = len(s.Packages)
	}
	if got[a1] != 2 || got[a2] != 1 {
		t.Fatalf("attribution %v", got)
	}
	if out.DependenciesLinked != 3 {
		t.Fatalf("output %+v", out)
	}
}

func TestComponentProcessor_ProcessBatch_WriteErrorIsReported(t *testing.T) {
	w := &fakePackageWriter{err: errors.New("boom")}
	p := NewComponentProcessor(w, slog.Default())
	out := &Output{}
	report := &ctis.Report{Dependencies: []ctis.Dependency{{Name: "x", Version: "1", PURL: "pkg:npm/x@1"}}}
	if err := p.ProcessBatch(context.Background(), shared.NewID(), report, map[string]shared.ID{"a": shared.NewID()}, software.ChannelCI, out); err != nil {
		t.Fatal(err)
	}
	if len(out.Errors) != 1 {
		t.Fatalf("errors %v", out.Errors)
	}
}

func TestComponentProcessor_NoAssetsNoWrite(t *testing.T) {
	w := &fakePackageWriter{}
	p := NewComponentProcessor(w, slog.Default())
	report := &ctis.Report{Dependencies: []ctis.Dependency{{Name: "x", Version: "1", PURL: "pkg:npm/x@1"}}}
	if err := p.ProcessBatch(context.Background(), shared.NewID(), report, nil, software.ChannelCI, &Output{}); err != nil {
		t.Fatal(err)
	}
	if len(w.snaps) != 0 {
		t.Fatal("packages written without an owning asset")
	}
}

func TestPackageChannel(t *testing.T) {
	cases := []struct {
		sensor bool
		source string
		want   string
	}{
		{true, "", software.ChannelSensor},
		{false, "integration", software.ChannelIntegration},
		{false, "manual", software.ChannelFindingImport},
		{false, "", software.ChannelCI},
	}
	for _, c := range cases {
		if got := PackageChannel(c.sensor, c.source); got != c.want {
			t.Errorf("PackageChannel(%v, %q) = %q, want %q", c.sensor, c.source, got, c.want)
		}
	}
}
