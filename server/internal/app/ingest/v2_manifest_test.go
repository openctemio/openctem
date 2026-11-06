package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// twoSegments is what the server stored for a report of two segments, and the
// manifest an honest sensor sends for it.
func twoSegments() (map[int]ingestjob.V2SegmentContent, protov2.CommitRequest, []byte) {
	a, b := sha256.Sum256([]byte("segment-0")), sha256.Sum256([]byte("segment-one"))
	stored := map[int]ingestjob.V2SegmentContent{0: {SHA256: a[:], Bytes: 9}, 1: {SHA256: b[:], Bytes: 11}}
	root := protov2.ReportRoot([][]byte{a[:], b[:]})
	req := protov2.CommitRequest{
		SegmentCount: 2,
		Segments: []protov2.SegmentManifest{
			{Seq: 1, SHA256: hex.EncodeToString(b[:]), Bytes: 11, Assets: 1, Findings: 4},
			{Seq: 0, SHA256: hex.EncodeToString(a[:]), Bytes: 9, Assets: 2, Findings: 3},
		},
		Totals:       &protov2.Counts{Assets: 3, Findings: 7},
		ReportSHA256: hex.EncodeToString(root),
	}
	return stored, req, root
}

func TestVerifyManifest(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*protov2.CommitRequest)
		// assets, findings: what the server counted at receipt.
		assets, findings int
		code             string // "" = matches
	}{
		{name: "honest manifest, any order", mutate: func(*protov2.CommitRequest) {}, assets: 3, findings: 7},
		{name: "a segment's content differs", mutate: func(r *protov2.CommitRequest) {
			r.Segments[0].SHA256 = hex.EncodeToString(make([]byte, 32))
		}, assets: 3, findings: 7, code: manifestCodeHash},
		{name: "a segment's size differs", mutate: func(r *protov2.CommitRequest) { r.Segments[1].Bytes++ },
			assets: 3, findings: 7, code: manifestCodeBytes},
		{name: "inflated totals", mutate: func(r *protov2.CommitRequest) {
			r.Totals.Findings, r.Segments[0].Findings = 70, 67
		}, assets: 3, findings: 7, code: manifestCodeCounts},
		{name: "segment counts do not add up", mutate: func(r *protov2.CommitRequest) { r.Segments[0].Assets = 5 },
			assets: 3, findings: 7, code: manifestCodeCounts},
		{name: "server counted fewer findings than claimed", mutate: func(*protov2.CommitRequest) {},
			assets: 3, findings: 6, code: manifestCodeCounts},
		{name: "report hash differs", mutate: func(r *protov2.CommitRequest) {
			r.ReportSHA256 = hex.EncodeToString(make([]byte, 32))
		}, assets: 3, findings: 7, code: manifestCodeRootHash},
		{name: "duplicate segment number", mutate: func(r *protov2.CommitRequest) { r.Segments[1].Seq = 1 },
			assets: 3, findings: 7, code: manifestCodeShape},
		{name: "segment missing from the manifest", mutate: func(r *protov2.CommitRequest) { r.Segments = r.Segments[:1] },
			assets: 3, findings: 7, code: manifestCodeShape},
		{name: "no totals", mutate: func(r *protov2.CommitRequest) { r.Totals = nil },
			assets: 3, findings: 7, code: manifestCodeShape},
		{name: "upper-case hex", mutate: func(r *protov2.CommitRequest) {
			r.Segments[0].SHA256 = "AB" + r.Segments[0].SHA256[2:]
		}, assets: 3, findings: 7, code: manifestCodeShape},
		{name: "negative counts", mutate: func(r *protov2.CommitRequest) {
			r.Segments[0].Findings, r.Segments[1].Findings = -1, 8
		}, assets: 3, findings: 7, code: manifestCodeShape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stored, req, root := twoSegments()
			tc.mutate(&req)
			errs := verifyManifest(req, stored, tc.assets, tc.findings, root)
			if tc.code == "" {
				if len(errs) != 0 {
					t.Fatalf("want a match, got %+v", errs)
				}
				return
			}
			for _, e := range errs {
				if e.Code == tc.code {
					return
				}
			}
			t.Fatalf("want code %s, got %+v", tc.code, errs)
		})
	}
}

func TestReportRootIsOrderedHashList(t *testing.T) {
	a, b := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	ab := protov2.ReportRoot([][]byte{a[:], b[:]})
	want := sha256.Sum256(append(append([]byte{}, a[:]...), b[:]...))
	if hex.EncodeToString(ab) != hex.EncodeToString(want[:]) {
		t.Fatal("root is not SHA-256 over the concatenated segment hashes")
	}
	if hex.EncodeToString(ab) == hex.EncodeToString(protov2.ReportRoot([][]byte{b[:], a[:]})) {
		t.Fatal("root must depend on segment order")
	}
}

// A segmented report committed without a verified manifest never proves
// absence; one segment, or a verified manifest, may.
func TestCoverageRefusesUnverifiedIntegrity(t *testing.T) {
	for integrity, want := range map[string]bool{
		protov2.IntegritySingle:     true,
		protov2.IntegrityManifest:   true,
		protov2.IntegrityDigestOnly: false,
		"":                          false,
	} {
		c := completedRun(t, shared.NewID(), shared.NewID())
		c.Reports[0].Integrity = integrity
		d := decideCoverage(c)
		if d.eligible() != want {
			t.Fatalf("integrity %q: eligible = %v (%s), want %v", integrity, d.eligible(), d.reason, want)
		}
		if !want && d.reason != coverageIntegrity {
			t.Fatalf("integrity %q: reason %s, want %s", integrity, d.reason, coverageIntegrity)
		}
	}
}
