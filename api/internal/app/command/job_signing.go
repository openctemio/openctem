package command

// Signed jobs at claim time: every command a claim hands a sensor carries
// an envelope from the separate signer, or is not handed out at all.
// Design: docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md §5.6;
// wire format: docs/architecture/job-signing.md.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// JobSigner asks the signer to sign a job statement and returns the DSSE
// envelope (JSON). An error means the command must not leave unsigned.
type JobSigner interface {
	SignJob(ctx context.Context, st jobsign.Statement) (json.RawMessage, error)
}

// ErrJobRefused is returned by a JobSigner whose signer refused the
// statement (as opposed to being unreachable).
var ErrJobRefused = errors.New("job signer refused the statement")

// ErrJobNotSigned: a signer is configured and did not sign the command, so
// it was not handed to the sensor (fail closed).
var ErrJobNotSigned = errors.New("command not signed")

// WithJobSigner makes every claim (claim-N and the claim by id) carry a
// signed job, and hand out nothing the signer did not sign. Without it
// claims are as before.
func WithJobSigner(j JobSigner) Option {
	return func(s *Service) { s.jobs = j }
}

// Unclaimer is the repository side of taking back a claim the signer did
// not sign (CommandRepository).
type Unclaimer interface {
	// UnclaimForSensor returns an acknowledged command held by sensorID to
	// pending; keepPin keeps it addressed to sensorID (it was pinned to that
	// sensor before the claim), otherwise it is unpinned. False when the
	// command is no longer acknowledged by sensorID.
	UnclaimForSensor(ctx context.Context, tenantID, commandID shared.ID, sensorID string, keepPin bool) (bool, error)
}

// SignsJobs reports whether claims carry signed jobs.
func (s *Service) SignsJobs() bool { return s.jobs != nil }

// DeliveryPayload is the payload exactly as a v2 response carries it: the
// compact JSON encoding/json writes for a json.RawMessage, "null" when
// empty. payload_sha256 is computed over these bytes, and the command
// handed out carries them, so the digest matches what the sensor reads.
func DeliveryPayload(payload json.RawMessage) json.RawMessage {
	if len(payload) == 0 {
		return json.RawMessage("null")
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// signJob returns a copy of c with its delivery payload and the signer's
// envelope for sensorID, or ErrJobNotSigned.
func (s *Service) signJob(ctx context.Context, sensorID string, c *commanddom.Command) (*commanddom.Command, error) {
	payload := DeliveryPayload(c.Payload)
	now := s.now().UTC()
	expires := now.Add(jobsign.MaxTTL)
	if c.ExpiresAt != nil && c.ExpiresAt.After(now) && c.ExpiresAt.Before(expires) {
		expires = c.ExpiresAt.UTC()
	}
	targets := commanddom.PayloadTargets(payload)
	if targets == nil {
		targets = []string{}
	}
	st := jobsign.Statement{
		Kind:          jobsign.Kind,
		TenantID:      c.TenantID.String(),
		SensorID:      sensorID,
		CommandID:     c.ID.String(),
		CommandType:   string(c.Type),
		Tool:          commanddom.PayloadTool(payload),
		PayloadSHA256: jobsign.PayloadDigest(payload),
		Targets:       targets,
		LeaseEpoch:    c.LeaseEpoch,
		IssuedAt:      now,
		ExpiresAt:     expires,
	}
	env, err := s.jobs.SignJob(ctx, st)
	if err != nil {
		outcome := "unavailable"
		if errors.Is(err, ErrJobRefused) {
			outcome = "refused"
			reason := "other"
			var rf *jobsign.RefusalError
			if errors.As(err, &rf) {
				reason = rf.Reason
			}
			metrics.SignerRefusalsTotal.WithLabelValues(reason).Inc()
		}
		metrics.JobSigningTotal.WithLabelValues(outcome).Inc()
		s.logger.Warn("command not signed; not handed to the sensor",
			"command_id", c.ID.String(), "sensor_id", sensorID, "outcome", outcome, "error", err)
		return nil, fmt.Errorf("%w: %w", ErrJobNotSigned, err)
	}
	metrics.JobSigningTotal.WithLabelValues("signed").Inc()
	cp := *c
	cp.Payload = payload
	cp.SignedJob = env
	return &cp, nil
}

// signClaimed signs each claimed command for sensorID. A command the signer
// does not sign is taken back (pending again, pinned only if it was pinned
// to the sensor before the claim) and left out: the sensor gets no unsigned
// work. pinned says which commands were pinned before the claim.
func (s *Service) signClaimed(ctx context.Context, tenantID shared.ID, sensorID string,
	cmds []*commanddom.Command, pinned map[shared.ID]bool,
) []*commanddom.Command {
	if s.jobs == nil {
		return cmds
	}
	out := cmds[:0:0]
	down := false
	for _, c := range cmds {
		if down {
			// The signer did not answer for an earlier command: the rest
			// are taken back without waiting on it again.
			metrics.JobSigningTotal.WithLabelValues("unavailable").Inc()
			s.unclaim(ctx, tenantID, c.ID, sensorID, pinned[c.ID])
			continue
		}
		signed, err := s.signJob(ctx, sensorID, c)
		if err != nil {
			down = !errors.Is(err, ErrJobRefused)
			s.unclaim(ctx, tenantID, c.ID, sensorID, pinned[c.ID])
			if rf := permanentRefusal(err); rf != nil {
				// The signer's ledger does not authorize this job: it would
				// refuse it on every claim. Fail it with the reason.
				s.failAtClaim(ctx, c, signerRefusedMessage(rf), FailureSignerRefused)
			}
			continue
		}
		out = append(out, signed)
	}
	return out
}

// FailureSignerRefused: the job signer refused the job for good (outside
// its scope ledger); the command is failed with the reason.
const FailureSignerRefused = scanrundom.FailureSignerRefused

// permanentRefusal is the signer's refusal in err when the signer will
// refuse the job again as its ledger stands (RFC-040 §5.6 point 4).
func permanentRefusal(err error) *jobsign.RefusalError {
	var rf *jobsign.RefusalError
	if errors.As(err, &rf) && rf.Permanent() {
		return rf
	}
	return nil
}

// signerRefusedMessage is the error recorded on a command the signer
// refused for good.
func signerRefusedMessage(rf *jobsign.RefusalError) string {
	msg := FailureSignerRefused + ": the job signer refused to sign this job (" + rf.Reason + "): " + rf.Detail +
		". The organization's approved scope in the signer's ledger does not allow it."
	return truncateUTF8(msg, MaxFailErrorMessageBytes)
}

// unclaim takes back a claim that was not signed. A failure is logged: the
// command then waits for its lease to expire, still never unsigned.
func (s *Service) unclaim(ctx context.Context, tenantID, commandID shared.ID, sensorID string, keepPin bool) {
	u, ok := s.repo.(Unclaimer)
	if !ok {
		return
	}
	// Not the request's context: a sensor that hangs up must not leave the
	// command claimed until its lease runs out.
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := u.UnclaimForSensor(uctx, tenantID, commandID, sensorID, keepPin); err != nil {
		s.logger.Error("unsigned claim not taken back; it waits for its lease to expire",
			"command_id", commandID.String(), "sensor_id", sensorID, "error", err)
	}
}
