package ingest

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func TestVerifyManifest_RejectsOversizedSegmentCount(t *testing.T) {
	stored := map[int]ingestjob.V2SegmentContent{0: {SHA256: make([]byte, 32)}}
	for _, n := range []int{-1, 0, 2, maxManifestSegments + 1, 1 << 40} {
		req := protov2.CommitRequest{SegmentCount: n}
		errs := verifyManifest(req, stored, 0, 0, nil)
		if len(errs) != 1 || errs[0].Code != manifestCodeShape {
			t.Fatalf("n=%d: want one shape error, got %v", n, errs)
		}
	}
}
