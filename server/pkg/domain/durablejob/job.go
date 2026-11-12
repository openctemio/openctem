// Package durablejob holds background jobs that must not be lost: rows
// written in the same database transaction as the change that needs them,
// and run by a worker that retries them (api/docs/architecture/durable-jobs.md).
package durablejob

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind names what a job does.
type Kind string

// The kinds (the table's CHECK constraint lists the same values).
const (
	KindJiraStatusSync   Kind = "jira_status_sync"
	KindGitHubStatusSync Kind = "github_status_sync"
	KindInvitationEmail  Kind = "invitation_email"
)

// Job is a job to queue. SubjectID is the finding or invitation it is
// about; Payload is kind-specific and sealed when it holds a secret.
type Job struct {
	Kind      Kind
	TenantID  shared.ID
	SubjectID shared.ID
	Payload   string
}

// Claimed is a job a worker holds. Attempts counts this run.
type Claimed struct {
	Job
	ID       shared.ID
	Attempts int
}

// Store persists and claims jobs.
type Store interface {
	// Claim takes up to limit due jobs of the given kinds for lease.
	Claim(ctx context.Context, kinds []Kind, limit int, lease time.Duration) ([]Claimed, error)
	// Complete removes a job that ran.
	Complete(ctx context.Context, j Claimed) error
	// Retry makes a job due again at the given time.
	Retry(ctx context.Context, j Claimed, at time.Time, reason string) error
	// Bury keeps a job that will not be retried, without its payload.
	Bury(ctx context.Context, j Claimed, reason string) error
}

type ctxKey struct{}

// WithEnqueue returns a context that asks the repository write it is passed
// to (and only a write that changed a row) to queue jobs in its transaction.
func WithEnqueue(ctx context.Context, jobs ...Job) context.Context {
	if len(jobs) == 0 {
		return ctx
	}
	prev := FromContext(ctx)
	all := make([]Job, 0, len(prev)+len(jobs))
	all = append(all, prev...)
	all = append(all, jobs...)
	return context.WithValue(ctx, ctxKey{}, all)
}

// FromContext returns the jobs WithEnqueue put on ctx.
func FromContext(ctx context.Context) []Job {
	jobs, _ := ctx.Value(ctxKey{}).([]Job)
	return jobs
}

// StatusSyncJobs are the outbound ticket status pushes for a finding whose
// status changed. A finding links to at most one provider; the push for the
// other one is a no-op.
func StatusSyncJobs(tenantID, findingID shared.ID) []Job {
	return []Job{
		{Kind: KindJiraStatusSync, TenantID: tenantID, SubjectID: findingID},
		{Kind: KindGitHubStatusSync, TenantID: tenantID, SubjectID: findingID},
	}
}
