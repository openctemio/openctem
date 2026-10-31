package command

// Content a job pins (docs/architecture/content-packs.md, RFC-061 §3.7).
// The "content" and "inputs" members of a scan or retest command name the
// packs the job reads by digest and the lists the platform generated for it.
// Like the proxy pool (egress.go) they are set on the copy of the command a
// sensor receives, never on the stored command, and the job signature covers
// them; a member a command's creator put there is removed. The signed
// statement lists each pack's digest, and before it is signed every digest
// is checked to be one the job's organization may hold: a platform pack, or
// one of the organization's own for a sensor of its own, never another
// organization's and never a tenant pack for a shared sensor.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// ErrContentRefused: the platform will not pin content for this job (no pack
// for the slot, a class the job's depth does not allow, a digest the
// organization may not use). Permanent: the command is failed with the
// reason, not retried.
var ErrContentRefused = errors.New("job content refused")

// ContentRefusedError carries the reason of ErrContentRefused.
type ContentRefusedError struct{ Reason string }

func (e *ContentRefusedError) Error() string { return "job content refused: " + e.Reason }

// Is makes errors.Is(err, ErrContentRefused) hold.
func (e *ContentRefusedError) Is(target error) bool { return target == ErrContentRefused }

// PinRequest is what a content source needs to plan one job's content.
type PinRequest struct {
	TenantID shared.ID
	// Shared: the job goes to a shared (instance) sensor, which mounts
	// platform packs only.
	Shared bool
	// Payload is the stored payload without any content or inputs member.
	Payload json.RawMessage
}

// ContentSource plans the content of one job: the packs it pins and the
// lists generated for it (nil, nil: none). A *ContentRefusedError is a
// permanent refusal; any other error is transient.
type ContentSource interface {
	PinJobContent(ctx context.Context, req PinRequest) ([]protov2.JobContent, []protov2.JobInput, error)
}

// ContentChecker says whether a digest may be pinned by a job of an
// organization: scope is the organization's id, or the instance scope for a
// shared sensor.
type ContentChecker interface {
	Deliverable(ctx context.Context, tenantID shared.ID, sharedSensor bool, digest string) (bool, error)
}

// ContentPinRecorder stores what a job pinned on its command, once the job
// is signed (scanrun.ContentPins). Scoped to tenantID.
type ContentPinRecorder interface {
	RecordContentPins(ctx context.Context, tenantID, commandID shared.ID, pins *scanrundom.ContentPins) error
}

// WithContentRecorder records each signed job's pinned content on its
// command, for the run page and later audits.
func WithContentRecorder(r ContentPinRecorder) Option {
	return func(s *Service) { s.contentRecorder = r }
}

// pinsOf is the record of a job's content and inputs (nil: none).
func pinsOf(content []protov2.JobContent, inputs []protov2.JobInput) *scanrundom.ContentPins {
	if len(content) == 0 && len(inputs) == 0 {
		return nil
	}
	p := &scanrundom.ContentPins{}
	for _, c := range content {
		p.Packs = append(p.Packs, scanrundom.PinnedPack{Slot: c.Slot, Scope: c.Scope, Pack: c.Pack, Version: c.Version, Digest: c.Digest})
	}
	for _, in := range inputs {
		pi := scanrundom.PinnedInput{Slot: in.Slot, Purpose: in.Purpose, Source: in.Source, SHA256: in.SHA256, Lines: in.Lines}
		for _, l := range in.Lists {
			pi.Lists = append(pi.Lists, scanrundom.PinnedList{ID: l.ID, Name: l.Name, Version: l.Version, SHA256: l.SHA256})
		}
		p.Inputs = append(p.Inputs, pi)
	}
	return p
}

// recordPins stores a signed job's pinned content. A failure is logged: the
// job runs either way, and the record is written again on a retry.
func (s *Service) recordPins(ctx context.Context, c *commanddom.Command, pins *scanrundom.ContentPins) {
	if s.contentRecorder == nil || pins == nil {
		return
	}
	if err := s.contentRecorder.RecordContentPins(ctx, c.TenantID, c.ID, pins); err != nil {
		s.logger.Warn("job content record not stored", "command_id", c.ID.String(), "error", err)
	}
}

// WithContent makes every scan and retest job carry the content its source
// plans, with each pinned digest checked by checker before the signer is
// asked. Without it such a job carries no content.
func WithContent(src ContentSource, checker ContentChecker) Option {
	return func(s *Service) { s.content, s.contentCheck = src, checker }
}

// pinContent returns c with its content and inputs members set by the
// platform (any a creator wrote is removed first), and the record of what
// it pinned (nil: nothing). A command that is not a scan or retest is
// returned as is.
func (s *Service) pinContent(ctx context.Context, c *commanddom.Command) (*commanddom.Command, *scanrundom.ContentPins, error) {
	if !egressCommand(c.Type) {
		return c, nil, nil
	}
	fields, ok := payloadObject(c.Payload)
	if !ok {
		// Not an object: nothing the platform can pin; whatever else is
		// wrong with the payload is not this step's to judge.
		return c, nil, nil
	}
	_, hadContent := fields[protov2.PayloadKeyContent]
	_, hadInputs := fields[protov2.PayloadKeyInputs]
	delete(fields, protov2.PayloadKeyContent)
	delete(fields, protov2.PayloadKeyInputs)

	var (
		content []protov2.JobContent
		inputs  []protov2.JobInput
	)
	if s.content != nil {
		// The source sees the payload without any content or inputs member;
		// the stored payload is passed as is when it has none (no re-encoding
		// of a large payload on every claim).
		stripped := c.Payload
		if hadContent || hadInputs {
			var err error
			if stripped, err = json.Marshal(fields); err != nil {
				return nil, nil, err
			}
		}
		var err error
		if content, inputs, err = s.content.PinJobContent(ctx, PinRequest{TenantID: c.TenantID, Shared: c.IsPlatformJob, Payload: stripped}); err != nil {
			return nil, nil, err
		}
	}
	pins := pinsOf(content, inputs)
	if len(content) == 0 && len(inputs) == 0 && !hadContent && !hadInputs {
		return c, nil, nil
	}
	if len(content) > 0 {
		b, err := json.Marshal(content)
		if err != nil {
			return nil, nil, err
		}
		fields[protov2.PayloadKeyContent] = b
	}
	if len(inputs) > 0 {
		b, err := json.Marshal(inputs)
		if err != nil {
			return nil, nil, err
		}
		fields[protov2.PayloadKeyInputs] = b
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return nil, nil, err
	}
	cp := *c
	cp.Payload = payload
	return &cp, pins, nil
}

// checkPinnedContent refuses a payload that pins a digest the job's
// organization may not use, whatever put it there.
func (s *Service) checkPinnedContent(ctx context.Context, c *commanddom.Command, payload json.RawMessage) error {
	refs := jobsign.PayloadContentRefs(payload)
	if len(refs) == 0 {
		return nil
	}
	if s.contentCheck == nil {
		return &ContentRefusedError{Reason: "this platform cannot check which packs the organization may use"}
	}
	for _, r := range refs {
		ok, err := s.contentCheck.Deliverable(ctx, c.TenantID, c.IsPlatformJob, r.Digest)
		if err != nil {
			return fmt.Errorf("check pinned content: %w", err)
		}
		if !ok {
			return &ContentRefusedError{Reason: fmt.Sprintf("pack %.19s... is not one this organization's job may use (another organization's, revoked, or unknown)", r.Digest)}
		}
	}
	return nil
}

// payloadObject decodes a command payload as a JSON object (an empty or null
// payload is an empty object); false when it is anything else.
func payloadObject(payload json.RawMessage) (map[string]json.RawMessage, bool) {
	fields := map[string]json.RawMessage{}
	if len(payload) == 0 || string(payload) == jsonNull {
		return fields, true
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, false
	}
	return fields, true
}
