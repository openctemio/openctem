package ingest

// After-commit side effects of an ingest batch, durable and batched
// (docs/rfcs/RFC-122-ingest-receipts.md, "Dispositions").
//
// The automations a new finding starts used to run in a goroutine the
// moment a batch was stored: a crash or a restart lost them, and a burst of
// uploads started one goroutine per batch. With a side-effect queue wired,
// the batch's new finding ids (only those that count: not branch-only, not
// decided by a policy) are enqueued as one ingest job (kind side_effects,
// at most maxSideEffectFindings ids each) after the findings are committed;
// the ingest worker runs the automations from it, retrying on failure. The
// dispatcher's per-finding run key keeps a retried job from starting an
// automation twice.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// maxSideEffectFindings bounds the finding ids of one side-effect job.
const maxSideEffectFindings = 1000

// SideEffectQueue stores the side effects of an ingest batch
// (postgres.IngestJobRepository).
type SideEffectQueue interface {
	EnqueueSideEffects(ctx context.Context, tenantID shared.ID, payload []byte) error
}

// SetSideEffectQueue routes the after-commit side effects through the
// durable queue (nil keeps the direct callback).
func (s *Service) SetSideEffectQueue(q SideEffectQueue) { s.findingProcessor.sideEffects = q }

type sideEffectPayload struct {
	FindingIDs []string `json:"finding_ids"`
}

// enqueueCreated stores the side effects of newly created findings, in
// jobs of at most maxSideEffectFindings. It returns false when they could
// not be stored, so the caller runs them directly instead of losing them.
func (p *FindingProcessor) enqueueCreated(ctx context.Context, tenantID shared.ID, created []*vulnerability.Finding) bool {
	for start := 0; start < len(created); start += maxSideEffectFindings {
		end := min(start+maxSideEffectFindings, len(created))
		ids := make([]string, 0, end-start)
		for _, f := range created[start:end] {
			ids = append(ids, f.ID().String())
		}
		raw, err := json.Marshal(sideEffectPayload{FindingIDs: ids})
		if err == nil {
			err = p.sideEffects.EnqueueSideEffects(context.WithoutCancel(ctx), tenantID, raw)
		}
		if err != nil {
			p.logger.Warn("side effects not queued; running them now", "tenant_id", tenantID.String(), "error", err)
			if p.findingCreatedCallback != nil {
				p.findingCreatedCallback(ctx, tenantID, created[start:])
			}
			return false
		}
	}
	return true
}

// FindingLoader reads findings of a tenant by id (postgres.FindingRepository).
type FindingLoader interface {
	GetByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]*vulnerability.Finding, error)
}

// SideEffectRunner starts the automations of new findings and returns an
// error when they could not be started (so the job is retried).
type SideEffectRunner func(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error

// SideEffectProcessor runs side-effect jobs (the ingest worker, kind
// side_effects).
type SideEffectProcessor struct {
	findings FindingLoader
	run      SideEffectRunner
}

// NewSideEffectProcessor wires the processor.
func NewSideEffectProcessor(findings FindingLoader, run SideEffectRunner) *SideEffectProcessor {
	return &SideEffectProcessor{findings: findings, run: run}
}

// Process loads the job's findings (of the job's tenant only) and runs
// their side effects.
func (p *SideEffectProcessor) Process(ctx context.Context, job *ingestjob.Job) ([]byte, error) {
	if p == nil || p.findings == nil || p.run == nil {
		return nil, errors.New("side effects are not wired")
	}
	var pl sideEffectPayload
	if err := json.Unmarshal(job.Payload(), &pl); err != nil {
		return nil, ingestjob.Permanent("unreadable", err)
	}
	ids := make([]shared.ID, 0, len(pl.FindingIDs))
	for _, raw := range pl.FindingIDs {
		if id, err := shared.IDFromString(raw); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return []byte(`{"findings":0}`), nil
	}
	findings, err := p.findings.GetByIDs(ctx, job.TenantID(), ids)
	if err != nil {
		return nil, fmt.Errorf("load the findings: %w", err)
	}
	// A finding deleted meanwhile is simply gone; one of another tenant is
	// never returned (the read is tenant-scoped).
	if err := p.run(ctx, job.TenantID(), findings); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]int{"findings": len(findings)})
}

// DeadLetter implements KindProcessor: nothing to tell; the job keeps its
// error for an operator.
func (p *SideEffectProcessor) DeadLetter(context.Context, *ingestjob.Job, string) {}
