package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/ctis"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/ingestjob"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ctisIngestEnvelope is the wrapped ingest payload shape: { "report": { ... } }.
type ctisIngestEnvelope struct {
	Report ctis.Report `json:"report"`
}

// ParseReport decodes a raw ingest body into a CTIS report. It accepts both the
// wrapped form ({"report": {...}}) and the flat SDK form ({"version": ...}),
// rejecting unknown fields so an agent cannot smuggle extra keys. This is the
// single parser shared by the synchronous accept handler and the async worker.
func ParseReport(body []byte) (*ctis.Report, error) {
	// Wrapped form first.
	var env ctisIngestEnvelope
	wrapped := json.NewDecoder(bytes.NewReader(body))
	wrapped.DisallowUnknownFields()
	if err := wrapped.Decode(&env); err == nil && env.Report.Version != "" {
		report := env.Report
		return &report, nil
	}

	// Flat form.
	var report ctis.Report
	flat := json.NewDecoder(bytes.NewReader(body))
	flat.DisallowUnknownFields()
	if err := flat.Decode(&report); err != nil {
		return nil, fmt.Errorf("invalid CTIS payload: %w", err)
	}
	return &report, nil
}

// JobResult is the compact counts summary stored on a completed ingest job.
type JobResult struct {
	ReportID        string `json:"report_id"`
	AssetsCreated   int    `json:"assets_created"`
	AssetsUpdated   int    `json:"assets_updated"`
	FindingsCreated int    `json:"findings_created"`
	FindingsUpdated int    `json:"findings_updated"`
	FindingsSkipped int    `json:"findings_skipped"`
	CVEsCreated     int    `json:"cves_created"`
	CVEsUpdated     int    `json:"cves_updated"`
}

// ingester is the slice of *Service the job processor needs (kept small so the
// processor is unit-testable with a stub).
type ingester interface {
	Ingest(ctx context.Context, agt *agent.Agent, input Input) (*Output, error)
}

// JobProcessor turns a queued raw payload back into a CTIS report and runs it
// through the normal ingest pipeline. Used by the async worker (RFC-005).
type JobProcessor struct {
	service ingester
}

// NewJobProcessor wires a processor over the ingest service.
func NewJobProcessor(service *Service) *JobProcessor {
	return &JobProcessor{service: service}
}

// Process parses the job payload and ingests it under a synthetic agent built
// from the job's stored identity (the agent was already authenticated when the
// job was accepted, so no re-auth/DB fetch is needed). Returns the marshaled
// counts to store on the completed job.
func (p *JobProcessor) Process(ctx context.Context, job *ingestjob.Job) ([]byte, error) {
	report, err := ParseReport(job.Payload())
	if err != nil {
		return nil, err
	}
	if report.Version == "" {
		report.Version = "1.0"
	}

	tenantID := job.TenantID()
	agentID := shared.ID{}
	if job.AgentID() != nil {
		agentID = *job.AgentID()
	}
	agt := &agent.Agent{
		ID:       agentID,
		TenantID: &tenantID,
		Status:   agent.AgentStatusActive,
	}

	output, err := p.service.Ingest(ctx, agt, Input{Report: report})
	if err != nil {
		return nil, err
	}

	result := JobResult{
		ReportID:        output.ReportID,
		AssetsCreated:   output.AssetsCreated,
		AssetsUpdated:   output.AssetsUpdated,
		FindingsCreated: output.FindingsCreated,
		FindingsUpdated: output.FindingsUpdated,
		FindingsSkipped: output.FindingsSkipped,
		CVEsCreated:     output.CVEsCreated,
		CVEsUpdated:     output.CVEsUpdated,
	}
	return json.Marshal(result)
}
