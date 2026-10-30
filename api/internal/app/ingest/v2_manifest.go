package ingest

// Commit manifest verification (docs/rfcs/RFC-026-sensor-results-ingest.md
// §3.5a). A segment's Content-Digest proves the bytes as sent arrived intact
// and is checked before decoding. The manifest adds what the digests cannot:
// the hash of each segment's decoded content (independent of the coding), its
// size, the report's asset and finding totals, and one hash for the whole
// report. Every value is compared with what the server itself stored and
// counted when it received the segments, so a sensor that drops, adds or
// inflates anything is refused before any report-level step runs.
//
// Threat model: a buggy or hostile sensor claims counts or content it did not
// send (to pass as a complete, clean run and close findings by absence). The
// server never trusts a claimed value: it compares it with its own. Error
// details are fixed templates; pointers are built from indices only.

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Manifest item error codes.
const (
	manifestCodeShape    = "manifest_invalid"
	manifestCodeHash     = "hash_mismatch"
	manifestCodeBytes    = "size_mismatch"
	manifestCodeCounts   = "count_mismatch"
	manifestCodeRootHash = "report_hash_mismatch"
)

// commitFacts decides what a commit records: the report hash over the stored
// segments and the integrity level, verifying the manifest when one is sent.
func (v *V2Receiver) commitFacts(rep *ingestreport.Report, req protov2.CommitRequest, stored map[int]ingestjob.V2SegmentContent) (ingestreport.CommitFacts, error) {
	n := req.SegmentCount
	hashes := make([][]byte, n)
	for seq := range n {
		c, ok := stored[seq]
		if !ok {
			return ingestreport.CommitFacts{}, problem(protov2.ProblemSegmentSetMismatch)
		}
		hashes[seq] = c.SHA256
	}
	facts := ingestreport.CommitFacts{SegmentCount: n, ContentSHA256: protov2.ReportRoot(hashes)}
	switch {
	case req.HasManifest():
		if errs := verifyManifest(req, stored, rep.AssetsReceived, rep.FindingsReceived, facts.ContentSHA256); len(errs) > 0 {
			metrics.IngestV2CommitIntegrityTotal.WithLabelValues(errs[0].Code).Inc()
			return ingestreport.CommitFacts{}, &V2ReportError{Problem: protov2.ProblemSegmentSetMismatch, Errors: errs}
		}
		facts.Integrity = protov2.IntegrityManifest
	case n == 1:
		facts.Integrity = protov2.IntegritySingle
	default:
		facts.Integrity = protov2.IntegrityDigestOnly
	}
	metrics.IngestV2CommitIntegrityTotal.WithLabelValues(facts.Integrity).Inc()
	return facts, nil
}

// verifyManifest compares a commit manifest with what the server stored for
// the report: every segment's decoded hash and size, the per-segment counts
// summing to the totals, the totals equal to what the server counted at
// receipt, and the report hash equal to root. It returns at most
// protov2.MaxItemErrors errors; none means the manifest matches.
func verifyManifest(req protov2.CommitRequest, stored map[int]ingestjob.V2SegmentContent, assets, findings int, root []byte) []protov2.ItemError {
	var errs []protov2.ItemError
	add := func(pointer, code, detail string) {
		if len(errs) < protov2.MaxItemErrors {
			errs = append(errs, protov2.ItemError{Pointer: pointer, Code: code, Detail: detail})
		}
	}
	if len(req.Segments) != req.SegmentCount || req.Totals == nil || req.ReportSHA256 == "" {
		add("", manifestCodeShape, "the manifest must list every segment, the totals and the report hash")
		return errs
	}
	seen := make([]bool, req.SegmentCount)
	sumAssets, sumFindings := 0, 0
	for i, s := range req.Segments {
		at := fmt.Sprintf("/segments/%d", i)
		if s.Seq < 0 || s.Seq >= req.SegmentCount || seen[s.Seq] {
			add(at+"/seq", manifestCodeShape, "segment numbers must be 0 to segment_count-1, each once")
			continue
		}
		seen[s.Seq] = true
		if s.Assets < 0 || s.Findings < 0 {
			add(at, manifestCodeShape, "counts cannot be negative")
			continue
		}
		sumAssets += s.Assets
		sumFindings += s.Findings
		got := stored[s.Seq]
		want, ok := decodeSHA256Hex(s.SHA256)
		if !ok {
			add(at+"/sha256", manifestCodeShape, "sha256 must be 64 lower-case hex digits")
		} else if !bytes.Equal(want, got.SHA256) {
			add(at+"/sha256", manifestCodeHash, "the segment's content hash differs from the segment received")
		}
		if s.Bytes != got.Bytes {
			add(at+"/bytes", manifestCodeBytes, "the segment's decoded size differs from the segment received")
		}
	}
	if sumAssets != req.Totals.Assets || sumFindings != req.Totals.Findings {
		add("/totals", manifestCodeCounts, "the segment counts do not add up to the totals")
	}
	if req.Totals.Assets != assets || req.Totals.Findings != findings {
		add("/totals", manifestCodeCounts, "the totals differ from the assets and findings received")
	}
	if want, ok := decodeSHA256Hex(req.ReportSHA256); !ok {
		add("/report_sha256", manifestCodeShape, "report_sha256 must be 64 lower-case hex digits")
	} else if !bytes.Equal(want, root) {
		add("/report_sha256", manifestCodeRootHash, "the report hash differs from the hash of the segments received")
	}
	return errs
}

// decodeSHA256Hex parses 64 lower-case hex digits.
func decodeSHA256Hex(s string) ([]byte, bool) {
	if len(s) != 64 {
		return nil, false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, false
		}
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}
