package ingest

// Queued protocol v2 segments at rest (docs/rfcs/RFC-026-sensor-results-ingest.md,
// "Queued segments at rest").
//
// Threat model: a segment waits in ingest_jobs.payload until the worker
// applies it, before secrets in it are masked (secret-scanner findings,
// HTTP evidence with tokens). A database dump, a backup or a read-only SQL
// foothold must not expose it. Each segment is sealed with the tenant's
// ingest payload key (the CI upload sealer: AES-256-GCM under a key derived
// per tenant from APP_ENCRYPTION_KEY) and bound, through the additional
// data, to its tenant, job, report, segment number and decoded content hash:
// a sealed row copied to another tenant, report, segment or job does not
// open, and neither does one whose recorded hash was changed. Only the
// ingest worker opens a segment; the receiver never reads one back (a replay
// compares digests). Payloads are never logged.

import (
	"crypto/subtle"
	"errors"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestpayload"
)

// errNoSegmentSealer: the server has no ingest payload sealer; segments are
// refused rather than stored in plaintext, and sealed ones wait (retried).
var errNoSegmentSealer = errors.New("ingest v2: no segment sealer configured")

// sealSegment replaces a not-yet-stored segment job's decoded payload with
// its sealed form.
func sealSegment(s *ingestpayload.Sealer, job *ingestjob.Job) error {
	seg := job.V2()
	if seg == nil || seg.Seq == nil {
		return errors.New("ingest v2: seal: not a segment job")
	}
	if job.PayloadSealed() {
		return nil
	}
	if s == nil {
		return errNoSegmentSealer
	}
	p, err := s.SealBound(job.TenantID(), job.ID(), 0, "",
		ingestpayload.SensorSegmentBinding(seg.ReportRef, *seg.Seq, job.PayloadSHA()), job.Payload())
	if err != nil {
		return err
	}
	// The binding names the job's hash: it must be the hash of what was
	// sealed, or the segment would never open.
	if subtle.ConstantTimeCompare(p.Digest, job.PayloadSHA()) != 1 {
		return errors.New("ingest v2: seal: payload hash mismatch")
	}
	job.SetSealedPayload(p.KeyID, p.Sealed, p.SizeBytes)
	return nil
}

// openSegment returns the decoded payload of a segment job. A payload stored
// before segments were sealed is returned as stored (the worker also seals
// those in place, SealPlaintextV2Payloads).
func openSegment(s *ingestpayload.Sealer, job *ingestjob.Job) ([]byte, error) {
	if !job.PayloadSealed() {
		return job.Payload(), nil
	}
	if s == nil {
		return nil, errNoSegmentSealer
	}
	seg := job.V2()
	if seg == nil || seg.Seq == nil {
		return nil, ingestpayload.ErrOpen
	}
	return s.Open(&ingestpayload.Part{
		JobID: job.ID(), Part: 0, TenantID: job.TenantID(), KeyID: job.PayloadKeyID(),
		SizeBytes: job.PayloadBytes(), Digest: job.PayloadSHA(), Sealed: job.Payload(),
		Binding: ingestpayload.SensorSegmentBinding(seg.ReportRef, *seg.Seq, job.PayloadSHA()),
	})
}
