package ingest

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func storedNames(repo *memAssetRepo, tenant shared.ID) []string {
	var out []string
	for n := range repo.rows[tenant] {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// Passive-source junk never becomes an asset: a name that is not a host
// name after normalisation, and the remnant of a percent-encoded delimiter
// next to the name it was cut from. A percent-encoded name is decoded, and
// a real name that merely starts like a remnant is kept.
func TestDropJunkHostnames(t *testing.T) {
	repo := newMemAssetRepo()
	p, _ := newDiscoveryProcessor(repo)
	tenant := shared.NewID()
	out := &Output{}
	report := reconReport(
		"www.example.com",
		"2fwww.example.com",    // remnant of "%2Fwww.example.com", the name is in the report
		"%2Fapi.example.com",   // decoded to api.example.com
		"3ds.example.com",      // looks like a remnant, nothing behind it: real
		"exa mple.example.com", // not a host name
		"-bad-.example.com",    // trimmed to "bad-.example.com": a label ends with "-"
		"nodot",                // one label
	)
	if _, err := p.ProcessBatch(context.Background(), tenant, report, out, nil); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	want := []string{"3ds.example.com", "api.example.com", "www.example.com"}
	if got := storedNames(repo, tenant); !slices.Equal(got, want) {
		t.Fatalf("stored %v, want %v", got, want)
	}
	// Each dropped name is reported by its report id (a1, a4, a5, a6).
	joined := strings.Join(out.Errors, "\n")
	for _, ref := range []string{"asset a1: the name is the remnant", "asset a4: the name is not a host name", "asset a5:", "asset a6:"} {
		if !strings.Contains(joined, ref) {
			t.Errorf("no error recorded as %q: %v", ref, out.Errors)
		}
	}
	if len(out.Errors) != 4 {
		t.Errorf("errors %v, want 4", out.Errors)
	}
}

// The name behind a remnant may already be in the tenant's inventory, and
// only there: another tenant's asset of that name decides nothing.
func TestDropJunkHostnames_InventoryIsTenantScoped(t *testing.T) {
	repo := newMemAssetRepo()
	p, _ := newDiscoveryProcessor(repo)
	mine, other := shared.NewID(), shared.NewID()
	for _, tn := range []shared.ID{mine, other} {
		if _, err := p.ProcessBatch(context.Background(), tn, reconReport("seed.example.org"), &Output{}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.ProcessBatch(context.Background(), mine, reconReport("www.example.com"), &Output{}, nil); err != nil {
		t.Fatal(err)
	}
	// In mine, www.example.com is known: the remnant is dropped.
	if _, err := p.ProcessBatch(context.Background(), mine, reconReport("2fwww.example.com"), &Output{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := repo.rows[mine]["2fwww.example.com"]; ok {
		t.Fatal("remnant of a name in the inventory was added")
	}
	// In other, nobody knows www.example.com: kept (it might be real).
	if _, err := p.ProcessBatch(context.Background(), other, reconReport("2fwww.example.com"), &Output{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := repo.rows[other]["2fwww.example.com"]; !ok {
		t.Fatal("another tenant's inventory decided about this tenant's name")
	}
}
