package ingest

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestpayload"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func segSealer(t *testing.T, current byte, previous ...byte) *ingestpayload.Sealer {
	t.Helper()
	prev := make([][]byte, 0, len(previous))
	for _, b := range previous {
		prev = append(prev, bytes.Repeat([]byte{b}, 32))
	}
	s, err := ingestpayload.NewSealer(bytes.Repeat([]byte{current}, 32), prev...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func segJob(tenant, report shared.ID, seq int, payload []byte) *ingestjob.Job {
	return ingestjob.NewV2Job(tenant, nil, "r", ingestjob.V2Segment{ReportRef: report, Seq: &seq}, payload)
}

// rebind returns a copy of a stored job as the repository would read it
// back, with another tenant, report or segment (a row moved or rewritten).
func rebind(j *ingestjob.Job, tenant, report shared.ID, seq int) *ingestjob.Job {
	c := ingestjob.FromRow(j.ID(), tenant, nil, j.ReportID(), "", j.Payload(), j.PayloadSHA(),
		ingestjob.StatusPending, 0, 5, 0, nil, "", "", nil, j.AvailableAt(), j.CreatedAt(), j.UpdatedAt())
	c.SetSealedPayload(j.PayloadKeyID(), j.Payload(), j.PayloadBytes())
	c.SetV2(&ingestjob.V2Segment{ReportRef: report, Seq: &seq})
	return c
}

func TestSealedSegmentRoundTripAndBinding(t *testing.T) {
	s := segSealer(t, 1)
	tenant, report := shared.NewID(), shared.NewID()
	plain := []byte(`{"findings":[{"type":"secret","title":"aws key AKIAEXAMPLESECRET"}]}`)
	job := segJob(tenant, report, 2, plain)
	sum := append([]byte(nil), job.PayloadSHA()...)

	if err := sealSegment(s, job); err != nil {
		t.Fatal(err)
	}
	if !job.PayloadSealed() || bytes.Contains(job.Payload(), []byte("AKIAEXAMPLESECRET")) {
		t.Fatal("segment stored in plaintext")
	}
	if job.PayloadBytes() != int64(len(plain)) || !bytes.Equal(job.PayloadSHA(), sum) {
		t.Fatalf("size %d / hash changed after sealing", job.PayloadBytes())
	}
	got, err := openSegment(s, job)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %v", err)
	}

	// Cross-tenant, another report, another segment number: none opens.
	for name, moved := range map[string]*ingestjob.Job{
		"other tenant":  rebind(job, shared.NewID(), report, 2),
		"other report":  rebind(job, tenant, shared.NewID(), 2),
		"other segment": rebind(job, tenant, report, 3),
	} {
		if _, err := openSegment(s, moved); !errors.Is(err, ingestpayload.ErrOpen) {
			t.Errorf("%s: %v, want ErrOpen", name, err)
		}
	}
	// A changed content hash does not open either.
	forged := rebind(job, tenant, report, 2)
	forged = ingestjob.FromRow(forged.ID(), tenant, nil, "r", "", job.Payload(), make([]byte, 32),
		ingestjob.StatusPending, 0, 5, 0, nil, "", "", nil, job.AvailableAt(), job.CreatedAt(), job.UpdatedAt())
	forged.SetSealedPayload(job.PayloadKeyID(), job.Payload(), job.PayloadBytes())
	seq := 2
	forged.SetV2(&ingestjob.V2Segment{ReportRef: report, Seq: &seq})
	if _, err := openSegment(s, forged); !errors.Is(err, ingestpayload.ErrOpen) {
		t.Errorf("forged hash: %v, want ErrOpen", err)
	}
	// Another master key does not open it.
	if _, err := openSegment(segSealer(t, 9), job); !errors.Is(err, ingestpayload.ErrOpen) {
		t.Errorf("other key: %v, want ErrOpen", err)
	}
}

// Key rotation: a segment sealed under the previous key still opens while
// that key is listed in APP_ENCRYPTION_KEY_PREVIOUS.
func TestSealedSegmentOpensAfterKeyRotation(t *testing.T) {
	job := segJob(shared.NewID(), shared.NewID(), 0, []byte(`{"findings":[]}`))
	if err := sealSegment(segSealer(t, 1), job); err != nil {
		t.Fatal(err)
	}
	if _, err := openSegment(segSealer(t, 2, 1), job); err != nil {
		t.Fatalf("rotated sealer: %v", err)
	}
	if _, err := openSegment(segSealer(t, 2), job); !errors.Is(err, ingestpayload.ErrOpen) {
		t.Fatalf("previous key removed: %v, want ErrOpen", err)
	}
}

// Without a sealer nothing is sealed (the receiver refuses the segment) and
// a sealed segment waits; a plaintext segment from before is read as is.
func TestSegmentSealerMissing(t *testing.T) {
	plain := []byte(`{"findings":[]}`)
	job := segJob(shared.NewID(), shared.NewID(), 0, plain)
	if err := sealSegment(nil, job); !errors.Is(err, errNoSegmentSealer) {
		t.Fatalf("seal without sealer: %v", err)
	}
	if got, err := openSegment(nil, job); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("legacy plaintext: %v", err)
	}
	if err := sealSegment(segSealer(t, 1), job); err != nil {
		t.Fatal(err)
	}
	if _, err := openSegment(nil, job); !errors.Is(err, errNoSegmentSealer) {
		t.Fatalf("open without sealer: %v", err)
	}
	// Sealing twice is a no-op.
	before := append([]byte(nil), job.Payload()...)
	if err := sealSegment(segSealer(t, 1), job); err != nil || !bytes.Equal(before, job.Payload()) {
		t.Fatalf("second seal changed the payload: %v", err)
	}
}

// A protocol v1 job (no report, no segment) seals under its own binding: it
// opens for its tenant, job and content hash only, and is never mistaken for
// a segment.
func TestSealedV1JobRoundTripAndBinding(t *testing.T) {
	s := segSealer(t, 1)
	tenant := shared.NewID()
	plain := []byte(`{"version":"1.0","findings":[{"title":"token ghp_EXAMPLESECRET"}]}`)
	job := ingestjob.NewJob(tenant, nil, "v1-report", "scanner", plain)
	if err := sealSegment(s, job); err != nil {
		t.Fatal(err)
	}
	if !job.PayloadSealed() || bytes.Contains(job.Payload(), []byte("ghp_EXAMPLESECRET")) {
		t.Fatal("v1 job stored in plaintext")
	}
	got, err := openSegment(s, job)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %v", err)
	}
	moved := ingestjob.FromRow(job.ID(), shared.NewID(), nil, "v1-report", "", job.Payload(), job.PayloadSHA(),
		ingestjob.StatusPending, 0, 5, 0, nil, "", "", nil, job.AvailableAt(), job.CreatedAt(), job.UpdatedAt())
	moved.SetSealedPayload(job.PayloadKeyID(), job.Payload(), job.PayloadBytes())
	if _, err := openSegment(s, moved); !errors.Is(err, ingestpayload.ErrOpen) {
		t.Fatalf("other tenant: %v, want ErrOpen", err)
	}
	// A v1 payload does not open as a v2 segment.
	seg := ingestjob.FromRow(job.ID(), tenant, nil, "v1-report", "", job.Payload(), job.PayloadSHA(),
		ingestjob.StatusPending, 0, 5, 0, nil, "", "", nil, job.AvailableAt(), job.CreatedAt(), job.UpdatedAt())
	seg.SetSealedPayload(job.PayloadKeyID(), job.Payload(), job.PayloadBytes())
	n := 0
	seg.SetV2(&ingestjob.V2Segment{ReportRef: shared.NewID(), Seq: &n})
	if _, err := openSegment(s, seg); !errors.Is(err, ingestpayload.ErrOpen) {
		t.Fatalf("as a segment: %v, want ErrOpen", err)
	}
	// An upload job is not a sensor payload.
	up := ingestjob.NewUploadJob(shared.NewID(), tenant, ingestjob.KindCIResults, "r", "u", "rep", []byte("{}"), make([]byte, 32))
	if err := sealSegment(s, up); err == nil {
		t.Fatal("an upload job must not be sealed as a sensor payload")
	}
}

// BenchmarkSealOpenSegment measures what sealing adds to accept (seal) and
// to the import (open) for a typical and a large segment.
func BenchmarkSealOpenSegment(b *testing.B) {
	s, _ := ingestpayload.NewSealer(bytes.Repeat([]byte{1}, 32))
	for _, size := range []int{256 << 10, 4 << 20, 64 << 20} {
		var buf bytes.Buffer
		for i := 0; buf.Len() < size; i++ {
			fmt.Fprintf(&buf, `{"type":"vulnerability","title":"finding %d","severity":"high","rule_id":"r%d","asset_ref":"a%d","location":{"path":"src/f%d.go","start_line":%d}},`, i, i%97, i%613, i, i%400)
		}
		plain := buf.Bytes()[:size]
		b.Run(fmt.Sprintf("seal_%dKiB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				j := segJob(shared.NewID(), shared.NewID(), 0, plain)
				if err := sealSegment(s, j); err != nil {
					b.Fatal(err)
				}
			}
		})
		j := segJob(shared.NewID(), shared.NewID(), 0, plain)
		_ = sealSegment(s, j)
		b.Logf("%d KiB decoded -> %d KiB sealed", size>>10, len(j.Payload())>>10)
		b.Run(fmt.Sprintf("open_%dKiB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				if _, err := openSegment(s, j); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
