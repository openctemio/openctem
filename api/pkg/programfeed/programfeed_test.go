package programfeed_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/programfeed"
	"github.com/openctemio/openctem/api/pkg/programfeed/programfeedtest"
)

// Bundles written and signed by the collector (openctemio/programfeed):
// seq2 (snapshot, delta from 1) and seq3 (snapshot, delta from 2).
const collector = "testdata/collector"

func fixture(t *testing.T) (root string, at time.Time) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(collector, "root-keyid.txt"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(filepath.Join(collector, "created-at.txt"))
	if err != nil {
		t.Fatal(err)
	}
	at, err = time.Parse(time.RFC3339, strings.TrimSpace(string(c)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b)), at.Add(time.Minute)
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func byID(ps []bp.PublicProgram) map[string]bp.PublicProgram {
	out := map[string]bp.PublicProgram{}
	for _, p := range ps {
		out[p.FeedID] = p
	}
	return out
}

func TestCollectorBundles(t *testing.T) {
	root, now := fixture(t)
	// First import: the snapshot.
	v, err := programfeed.VerifyDir(filepath.Join(collector, "seq2"), programfeed.Options{PinnedRoot: root, Now: now})
	if err != nil {
		t.Fatalf("verify seq2: %v", err)
	}
	if v.IsDelta() || v.Latest.Sequence != 2 {
		t.Fatalf("seq2 uses %s %d", v.Use.Kind, v.Latest.Sequence)
	}
	progs, _, err := v.Read(programfeed.V1{})
	if err != nil {
		t.Fatalf("read seq2: %v", err)
	}
	ps := byID(progs)
	acme, agency := ps["disclose:acme"], ps["disclose:agency"]
	if len(ps) != 2 || !acme.Open() || !acme.ScopePublished || agency.ScopePublished || agency.Handle != "agency" {
		t.Fatalf("programs = %+v", ps)
	}
	var inferred, published int
	for _, it := range agency.Items {
		if it.Confidence == bp.ConfidenceInferred {
			inferred++
		}
	}
	for _, it := range acme.Items {
		if it.Confidence == bp.ConfidencePublished && it.InScope {
			published++
		}
	}
	if inferred != 1 || published != 3 || len(acme.Rules.RequiredHeaders) != 1 || !strings.Contains(acme.TermsText, "No denial of service") {
		t.Fatalf("items/rules: inferred %d published %d headers %+v text %q", inferred, published, acme.Rules.RequiredHeaders, acme.TermsText)
	}
	// An inferred target is a suggestion until confirmed.
	for _, it := range agency.ItemsFor(nil) {
		if it.InScope && it.Scannable() {
			t.Fatalf("unconfirmed suggestion is scannable: %+v", it)
		}
	}
	if !agency.ItemsFor([]string{"agency-fixture.org"})[0].Scannable() {
		t.Fatal("confirmed suggestion not scannable")
	}

	// Next import: the delta from 2.
	v, err = programfeed.VerifyDir(filepath.Join(collector, "seq3"), programfeed.Options{PinnedRoot: root, AppliedSequence: 2, MinKeySetVersion: 1, Now: now})
	if err != nil {
		t.Fatalf("verify seq3: %v", err)
	}
	if !v.IsDelta() {
		t.Fatal("seq3 after 2 must use the delta")
	}
	progs, changes, err := v.Read(programfeed.V1{})
	if err != nil {
		t.Fatalf("read seq3 delta: %v", err)
	}
	ps = byID(progs)
	if ps["disclose:acme"].Status != bp.FeedStatusClosed || ps["disclose:beta"].Status != bp.FeedStatusOpen || len(changes) != 2 {
		t.Fatalf("delta programs %+v changes %+v", ps, changes)
	}
	// A base that is not the applied sequence: the snapshot is used.
	v, err = programfeed.VerifyDir(filepath.Join(collector, "seq3"), programfeed.Options{PinnedRoot: root, AppliedSequence: 1, Now: now})
	if err != nil || v.IsDelta() {
		t.Fatalf("seq3 after 1: delta %v err %v", v != nil && v.IsDelta(), err)
	}
}

func TestVerifyRefusals(t *testing.T) {
	root, now := fixture(t)
	seq2 := filepath.Join(collector, "seq2")
	opt := programfeed.Options{PinnedRoot: root, Now: now}
	cases := map[string]func() (string, programfeed.Options){
		"wrong pinned root": func() (string, programfeed.Options) {
			o := opt
			o.PinnedRoot = programfeedtest.New(t, now).RootKeyID()
			return seq2, o
		},
		"key set rolled back": func() (string, programfeed.Options) {
			o := opt
			o.MinKeySetVersion = 2
			return seq2, o
		},
		"not newer": func() (string, programfeed.Options) {
			o := opt
			o.AppliedSequence = 2
			return seq2, o
		},
		"expired": func() (string, programfeed.Options) {
			o := opt
			o.Now = now.Add(8 * 24 * time.Hour)
			return seq2, o
		},
		"tampered records": func() (string, programfeed.Options) {
			d := copyDir(t, seq2)
			p := filepath.Join(d, "snapshot-programs.jsonl.gz")
			raw, _ := os.ReadFile(p)
			raw[len(raw)-1] ^= 0xff
			_ = os.WriteFile(p, raw, 0o600)
			return d, opt
		},
		"pointer from another key": func() (string, programfeed.Options) {
			d := copyDir(t, seq2)
			other := programfeedtest.New(t, now).Write(t, 9, nil)
			raw, _ := os.ReadFile(filepath.Join(other, programfeed.LatestFile))
			_ = os.WriteFile(filepath.Join(d, programfeed.LatestFile), raw, 0o600)
			return d, opt
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			dir, o := mk()
			_, err := programfeed.VerifyDir(dir, o)
			if err == nil {
				t.Fatal("accepted")
			}
			if name == "not newer" && !errors.Is(err, programfeed.ErrNotNewer) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestReadRefusesBadRecords(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	b := programfeedtest.New(t, now)
	good := func() []map[string]any {
		return []map[string]any{
			programfeedtest.Record("disclose", "acme", []string{"*.acme.io", "api.acme.io"}, []string{"admin.acme.io"}, now),
			programfeedtest.Record("disclose", "beta", []string{"beta.io"}, nil, now),
		}
	}
	bad := map[string]func(r map[string]any){
		"bad id":            func(r map[string]any) { r["id"] = "../../etc" },
		"source mismatch":   func(r map[string]any) { r["source"] = "other" },
		"javascript url":    func(r map[string]any) { r["url"] = "javascript:alert(1)" },
		"bad status":        func(r map[string]any) { r["status"] = "maybe" },
		"closed without at": func(r map[string]any) { r["status"] = "closed" },
		"bad confidence": func(r map[string]any) {
			r["in_scope"] = []map[string]string{{"type": "domain", "value": "x.io", "confidence": "sure"}}
		},
		"bad target type": func(r map[string]any) {
			r["in_scope"] = []map[string]string{{"type": "shell", "value": "x.io", "confidence": "published"}}
		},
		"missing last_seen": func(r map[string]any) { delete(r, "last_seen") },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			recs := good()
			mutate(recs[1])
			v, err := programfeed.VerifyDir(b.Write(t, 9, recs), programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if _, _, err := v.Read(programfeed.V1{}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// A credential header in the feed rules is never enforced as a header.
	recs := good()
	recs[0]["rules"] = map[string]any{"testing_restrictions": []string{}, "required_headers": []string{"Cookie: x", "X-HackerHandle: me"},
		"safe_harbour": "unknown", "languages": []string{}} //nolint:misspell // the collector wire name
	v, err := programfeed.VerifyDir(b.Write(t, 10, recs), programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	progs, _, err := v.Read(programfeed.V1{})
	if err != nil {
		t.Fatal(err)
	}
	if h := byID(progs)["disclose:acme"].Rules.RequiredHeaders; len(h) != 1 || h[0].Name != "X-HackerHandle" {
		t.Fatalf("headers = %+v", h)
	}
	// A duplicate id is refused.
	dup := append(good(), good()[0])
	v, err = programfeed.VerifyDir(b.Write(t, 11, dup), programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Read(programfeed.V1{}); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestLocalOnlyRefusedAndDatasetRecords(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	b := programfeedtest.New(t, now)
	rec := programfeedtest.Record("bounty-targets", "acme", nil, nil, now)
	rec["platform"] = "hackerone"
	rec["scope_published"] = true
	rec["in_scope"] = []map[string]string{{"type": "domain", "value": "api.acme.io", "confidence": "published_by_platform"}}
	rec["provenance"] = map[string]any{"source": "bounty-targets", "source_url": "https://github.com/arkadiyt/bounty-targets-data",
		"fetched_at": now.Format(time.RFC3339), "dataset": "arkadiyt/bounty-targets-data",
		"dataset_commit": strings.Repeat("a", 40), "original_platform": "hackerone", "original_url": "https://hackerone.com/acme"}
	// A local-only bundle is never accepted from the signed feed.
	b.LocalOnly = true
	if _, err := programfeed.VerifyDir(b.Write(t, 5, []map[string]any{rec}), programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now}); err == nil {
		t.Fatal("local-only bundle accepted on the signed path")
	}
	b.LocalOnly = false
	v, err := programfeed.VerifyDir(b.Write(t, 6, []map[string]any{rec}), programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	progs, _, err := v.Read(programfeed.V1{})
	if err != nil {
		t.Fatal(err)
	}
	p := progs[0]
	if p.Provenance.Dataset != "arkadiyt/bounty-targets-data" || p.Provenance.OriginalURL != "https://hackerone.com/acme" {
		t.Fatalf("provenance = %+v", p.Provenance)
	}
	// Scope a platform published through a dataset is a suggestion.
	for _, it := range p.ItemsFor(nil) {
		if it.InScope && it.Scannable() {
			t.Fatalf("published_by_platform target scannable without confirmation: %+v", it)
		}
	}
	// A bad provenance is refused.
	rec["provenance"].(map[string]any)["dataset_commit"] = "main"
	v, err = programfeed.VerifyDir(b.Write(t, 7, []map[string]any{rec}), programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Read(programfeed.V1{}); err == nil {
		t.Fatal("bad provenance accepted")
	}
}

// Unsigned local-only bundles written by `programfeed build --local-only`.
const local = "testdata/local"

func TestLocalBundles(t *testing.T) {
	c, err := os.ReadFile(filepath.Join(local, "created-at.txt"))
	if err != nil {
		t.Fatal(err)
	}
	at, _ := time.Parse(time.RFC3339, strings.TrimSpace(string(c)))
	now := at.Add(time.Minute)
	v, err := programfeed.VerifyLocalDir(filepath.Join(local, "seq1"), programfeed.Options{Now: now})
	if err != nil || v.IsDelta() || v.Latest.Sequence != 1 || !v.Use.Collector.LocalOnly {
		t.Fatalf("seq1: %+v %v", v, err)
	}
	progs, _, err := v.Read(programfeed.V1{})
	if err != nil || len(progs) != 2 {
		t.Fatalf("read seq1: %d %v", len(progs), err)
	}
	if progs[0].Provenance.Dataset != "arkadiyt/bounty-targets-data" || progs[0].Provenance.OriginalPlatform != "hackerone" {
		t.Fatalf("provenance = %+v", progs[0].Provenance)
	}
	// A local record never makes an entry without confirmation.
	p := progs[0]
	p.LocalOnly = true
	for _, it := range p.ItemsFor(nil) {
		if it.InScope && it.Scannable() {
			t.Fatalf("local target scannable without confirmation: %+v", it)
		}
	}
	// The delta on top of 1; a lower or equal sequence is refused.
	if v, err = programfeed.VerifyLocalDir(filepath.Join(local, "seq2"), programfeed.Options{AppliedSequence: 1, Now: now}); err != nil || !v.IsDelta() {
		t.Fatalf("seq2 after 1: %v", err)
	}
	if _, err := programfeed.VerifyLocalDir(filepath.Join(local, "seq1"), programfeed.Options{AppliedSequence: 1, Now: now}); !errors.Is(err, programfeed.ErrNotNewer) {
		t.Fatalf("not newer: %v", err)
	}
	// Expired, tampered and the signed path refuse.
	if _, err := programfeed.VerifyLocalDir(filepath.Join(local, "seq1"), programfeed.Options{Now: now.Add(8 * 24 * time.Hour)}); err == nil {
		t.Fatal("expired local bundle accepted")
	}
	d := copyDir(t, filepath.Join(local, "seq1"))
	raw, _ := os.ReadFile(filepath.Join(d, "snapshot-programs.jsonl.gz"))
	raw[len(raw)-1] ^= 0xff
	_ = os.WriteFile(filepath.Join(d, "snapshot-programs.jsonl.gz"), raw, 0o600)
	if _, err := programfeed.VerifyLocalDir(d, programfeed.Options{Now: now}); err == nil {
		t.Fatal("tampered local bundle accepted")
	}
	if _, err := programfeed.VerifyDir(filepath.Join(local, "seq1"), programfeed.Options{PinnedRoot: "SHA256:x", Now: now}); err == nil {
		t.Fatal("unsigned bundle accepted on the signed path")
	}
	// Oversized manifest refused.
	d = copyDir(t, filepath.Join(local, "seq1"))
	_ = os.WriteFile(filepath.Join(d, "latest.json"), make([]byte, programfeed.MaxManifestBytes+1), 0o600)
	if _, err := programfeed.VerifyLocalDir(d, programfeed.Options{Now: now}); err == nil {
		t.Fatal("oversized pointer accepted")
	}
}

// Fields the collector adds within v1 are ignored, not refused.
func TestRecordToleratesAddedFields(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	b := programfeedtest.New(t, now)
	rec := programfeedtest.Record("disclose", "acme", []string{"api.acme.io"}, nil, now)
	rec["environment"] = "production"
	rec["in_scope"] = []map[string]any{{"type": "domain", "value": "api.acme.io", "confidence": "published", "port": 8443, "protocol": "tcp"}}
	v, err := programfeed.VerifyDir(b.Write(t, 3, []map[string]any{rec}), programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if progs, _, err := v.Read(programfeed.V1{}); err != nil || len(progs) != 1 {
		t.Fatalf("added fields: %d %v", len(progs), err)
	}
}
