package ingest

// Queued sensor payloads at rest (docs/rfcs/RFC-026-sensor-results-ingest.md,
// "Queued segments at rest"): protocol v2 segments and legacy protocol v1 jobs.
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

// queuedBinding is the binding a queued sensor payload is sealed under: a
// protocol v2 segment binds its report, segment number and content hash, a
// protocol v1 job its content hash.
func queuedBinding(job *ingestjob.Job) (string, error) {
	if seg := job.V2(); seg != nil {
		if seg.Seq == nil {
			return "", errors.New("ingest: seal: a commit job has no payload")
		}
		return ingestpayload.SensorSegmentBinding(seg.ReportRef, *seg.Seq, job.PayloadSHA()), nil
	}
	if job.Kind() != ingestjob.KindSensor {
		return "", errors.New("ingest: seal: not a sensor job")
	}
	return ingestpayload.SensorJobBinding(job.PayloadSHA()), nil
}

// sealSegment replaces a not-yet-stored sensor job's decoded payload (a v2
// segment, or a legacy v1 report) with its sealed form.
func sealSegment(s *ingestpayload.Sealer, job *ingestjob.Job) error {
	binding, err := queuedBinding(job)
	if err != nil {
		return err
	}
	if job.PayloadSealed() {
		return nil
	}
	if s == nil {
		return errNoSegmentSealer
	}
	p, err := s.SealBound(job.TenantID(), job.ID(), 0, "", binding, job.Payload())
	if err != nil {
		return err
	}
	// The binding names the job's hash: it must be the hash of what was
	// sealed, or the payload would never open.
	if subtle.ConstantTimeCompare(p.Digest, job.PayloadSHA()) != 1 {
		return errors.New("ingest: seal: payload hash mismatch")
	}
	job.SetSealedPayload(p.KeyID, p.Sealed, p.SizeBytes)
	return nil
}

// openSegment returns the decoded payload of a sensor job. A payload stored
// before payloads were sealed is returned as stored (the worker also seals
// those in place, SealPlaintextSensorPayloads).
func openSegment(s *ingestpayload.Sealer, job *ingestjob.Job) ([]byte, error) {
	if !job.PayloadSealed() {
		return job.Payload(), nil
	}
	if s == nil {
		return nil, errNoSegmentSealer
	}
	binding, err := queuedBinding(job)
	if err != nil {
		return nil, ingestpayload.ErrOpen
	}
	return s.Open(&ingestpayload.Part{
		JobID: job.ID(), Part: 0, TenantID: job.TenantID(), KeyID: job.PayloadKeyID(),
		SizeBytes: job.PayloadBytes(), Digest: job.PayloadSHA(), Sealed: job.Payload(),
		Binding: binding,
	})
}
