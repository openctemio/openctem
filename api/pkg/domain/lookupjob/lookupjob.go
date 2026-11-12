// Package lookupjob holds lookup jobs (docs/architecture/certificate-transparency-monitoring.md):
// a passive question the platform asks one of its instance-scope sensors on
// behalf of one organization, because the platform makes no outbound request
// itself. The first capability is lookup.ct@1 (contract package ctlookup).
//
// A job is bound to its tenant_id when the platform creates it. The sensor
// that claims it only answers: it never names the organization, and the
// answer is read back by (tenant, job id).
package lookupjob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/contract/ctlookup"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Capabilities served through lookup jobs, with the tool that runs each.
var Tools = map[string]string{ctlookup.Capability: ctlookup.Tool}

// Statuses.
const (
	StatusOpen    = "open"
	StatusClaimed = "claimed"
	StatusDone    = "done"
	StatusFailed  = "failed"
	StatusRefused = "refused"
)

// Errors.
var (
	// ErrClosed: the job is not claimed by this sensor (another sensor's,
	// answered already, or gone).
	ErrClosed = fmt.Errorf("%w: lookup job not open for this sensor", shared.ErrNotFound)
	// ErrNotFound: no such job of this tenant.
	ErrNotFound = fmt.Errorf("%w: lookup job not found", shared.ErrNotFound)
	// ErrInvalid: a job that breaks the rules (unknown capability, bad
	// target).
	ErrInvalid = errors.New("lookup job: invalid")
)

// Job is one question.
type Job struct {
	ID         shared.ID
	TenantID   shared.ID
	Capability string
	Tool       string
	Target     string
	Input      json.RawMessage
	Status     string
	SensorID   *shared.ID
	ClaimedAt  *time.Time
	Result     json.RawMessage
	ErrorCode  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	DoneAt     *time.Time
}

// Terminal reports whether the job has its outcome.
func (j *Job) Terminal() bool {
	return j.Status == StatusDone || j.Status == StatusFailed || j.Status == StatusRefused
}

// Repository stores lookup jobs.
type Repository interface {
	// Create inserts an open job.
	Create(ctx context.Context, j *Job) error
	// Claim takes the oldest open, unexpired job of one of capabilities
	// for the sensor, or nil.
	Claim(ctx context.Context, sensorID shared.ID, capabilities []string, now time.Time) (*Job, error)
	// Finish records the outcome of a job the sensor claimed, once; false
	// when the job is not claimed by that sensor (ErrClosed upstream).
	FinishForPlatform(ctx context.Context, id, sensorID shared.ID, status string, result json.RawMessage, code string, now time.Time) (bool, error)
	// Get returns a job of the tenant.
	Get(ctx context.Context, tenantID, id shared.ID) (*Job, error)
	// Delete removes a job of the tenant.
	Delete(ctx context.Context, tenantID, id shared.ID) error
	// Purge removes jobs created before t, of any tenant (housekeeping).
	Purge(ctx context.Context, before time.Time) (int64, error)
	// EligibleSensorExists reports whether an active, reachable
	// instance-scope sensor reports the capability, seen since since.
	EligibleSensorExists(ctx context.Context, capability string, since time.Time) (bool, error)
}
