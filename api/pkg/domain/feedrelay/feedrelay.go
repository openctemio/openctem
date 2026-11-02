// Package feedrelay holds the rounds of the feed relay
// (docs/rfcs/RFC-142-feed-relay.md): the files the platform asked its
// designated relay sensor to fetch for one feed, and the outcome. Feed data
// is platform-wide catalog data: a round belongs to no organization.
package feedrelay

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Feeds a round may serve.
const (
	FeedVulnFeed     = "vulnfeed"
	FeedVersionCheck = "versioncheck"
)

// Phases. head, manifests and chunks ask the relay for files; imported and
// failed are bookkeeping rows that close a cycle (no files).
const (
	PhaseHead      = "head"
	PhaseManifests = "manifests"
	PhaseChunks    = "chunks"
	PhaseImported  = "imported"
	PhaseFailed    = "failed"
)

// Statuses.
const (
	StatusOpen    = "open"
	StatusDone    = "done"
	StatusRefused = "refused"
	StatusExpired = "expired"
	StatusFailed  = "failed"
)

// Stale reasons and round error codes (the console turns each into one
// sentence; never upstream text).
const (
	CodeNoRelayDesignated = "no_relay_designated"
	CodeRelayOffline      = "relay_offline"
	CodeSignerRefused     = "signer_refused"
	CodeSensorRefused     = "sensor_refused"
	CodeUpstreamMissing   = "upstream_missing"
	CodePinMismatch       = "pin_mismatch"
	CodeVerifyFailed      = "verify_failed"
	CodeRollbackRefused   = "rollback_refused"
	CodeImportFailed      = "import_failed"
	CodePlanFailed        = "plan_failed"
	CodeNothingDelivered  = "nothing_delivered"
	CodeRoundExpired      = "round_expired"
	CodeSpoolFull         = "spool_full"
)

// Errors.
var (
	// ErrNotFound: no such round for this sensor.
	ErrNotFound = fmt.Errorf("%w: feed relay round not found", shared.ErrNotFound)
	// ErrRoundClosed: the round is not open, expired, or claimed by another
	// sensor.
	ErrRoundClosed = fmt.Errorf("%w: feed relay round is not open", shared.ErrNotFound)
	// ErrDuplicate: the file was already uploaded in this round with other
	// bytes (one upload per file name per round).
	ErrDuplicate = fmt.Errorf("%w: file already uploaded in this round", shared.ErrValidation)
	// ErrRoundFull / ErrSpoolFull: the round's byte budget or the spool's
	// total quota would be exceeded.
	ErrRoundFull = fmt.Errorf("%w: feed relay round byte budget exceeded", shared.ErrValidation)
	ErrSpoolFull = fmt.Errorf("%w: feed relay spool is full", shared.ErrValidation)
)

// File is one file of a round. SHA256 and Size pin it when known.
type File struct {
	Name     string `json:"name"`
	SHA256   string `json:"sha256,omitempty"`
	Size     int64  `json:"size,omitempty"`
	MaxBytes int64  `json:"max_bytes"`
}

// Outcome is the relay's report for one file.
type Outcome struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Code   string `json:"code,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// Report is the relay's report of a round.
type Report struct {
	Files   []Outcome `json:"files"`
	Refused string    `json:"refused,omitempty"`
}

// Round is one round. SensorID is the designated sensor that claimed it
// (nil: open and not claimed yet, or a bookkeeping row).
type Round struct {
	ID             shared.ID
	SensorID       *shared.ID
	ClaimedAt      *time.Time
	Feed           string
	Phase          string
	Status         string
	Origins        []string
	Files          []File
	Report         *Report
	DeliveredBytes int64
	ErrorCode      string
	ErrorDetail    string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	DeliveredAt    *time.Time
}

// File returns the round's file of that name.
func (r *Round) File(name string) (File, bool) {
	for _, f := range r.Files {
		if f.Name == name {
			return f, true
		}
	}
	return File{}, false
}

// Delivered counts the files the relay delivered.
func (r *Round) Delivered() int {
	if r.Report == nil {
		return 0
	}
	n := 0
	for _, o := range r.Report.Files {
		if o.Status == "ok" {
			n++
		}
	}
	return n
}

// WantedBytes is the sum of the pinned sizes of the round's files (0 when
// none is pinned).
func (r *Round) WantedBytes() int64 {
	var n int64
	for _, f := range r.Files {
		n += f.Size
	}
	return n
}

// HasOutcomeCode reports whether the relay reported that code for a file.
func (r *Round) HasOutcomeCode(code string) bool {
	if r.Report == nil {
		return false
	}
	for _, o := range r.Report.Files {
		if o.Code == code {
			return true
		}
	}
	return false
}

// ClaimRule is who may claim an open round.
type ClaimRule struct {
	// SensorID claims.
	SensorID shared.ID
	// Designated are the sensors designated now: a round claimed by a
	// sensor no longer designated may be claimed again at once.
	Designated []shared.ID
	// StaleBefore: a round claimed before this time with nothing uploaded
	// may be claimed by another designated sensor.
	StaleBefore time.Time
	Now         time.Time
}

// SpoolFile is one file of the spool (without its bytes).
type SpoolFile struct {
	Name   string
	SHA256 string
	Size   int64
}

// Upload is a verified file to store in the spool.
type Upload struct {
	RoundID  shared.ID
	SensorID shared.ID
	Feed     string
	Name     string
	SHA256   string
	Data     []byte
	// RoundBudget caps the bytes one round may deliver, SpoolQuota the
	// spool's total.
	RoundBudget int64
	SpoolQuota  int64
	Now         time.Time
}

// SensorActivity is what a relay sensor served recently.
type SensorActivity struct {
	LastDeliveredAt *time.Time
	Bytes           int64
}

// Repository stores rounds.
type Repository interface {
	Create(ctx context.Context, r *Round) error
	// GetForSensor returns the round when that sensor claimed it.
	GetForSensor(ctx context.Context, id, sensorID shared.ID) (*Round, error)
	// Claim gives the caller the oldest open, unexpired round it may claim
	// (see ClaimRule), or nil. The caller's own claimed round comes back
	// again (a restarted relay resumes it).
	Claim(ctx context.Context, rule ClaimRule) (*Round, error)
	// Latest returns the newest round of a feed, or nil.
	Latest(ctx context.Context, feed string) (*Round, error)
	// LatestOfPhase returns the newest round of a feed in a phase, or nil.
	LatestOfPhase(ctx context.Context, feed, phase string) (*Round, error)
	// Finish closes an open round of that sensor (status, report). false:
	// the round was not open.
	Finish(ctx context.Context, id, sensorID shared.ID, status string, rep *Report, at time.Time) (bool, error)
	// Fail closes an open round as failed with a code and a detail.
	Fail(ctx context.Context, id shared.ID, code, detail string, at time.Time) error
	// ExpireOpen marks open rounds past their expiry expired.
	ExpireOpen(ctx context.Context, now time.Time) (int, error)
	// DeleteBefore removes rounds created before t (retention).
	DeleteBefore(ctx context.Context, t time.Time) (int, error)
	// Activity returns, per sensor, the last round it delivered and the
	// bytes it delivered since since.
	Activity(ctx context.Context, sensorIDs []shared.ID, since time.Time) (map[shared.ID]SensorActivity, error)
	// BootstrapSensor returns the sensor that enrolled with that instance
	// enrollment token, or nil.
	BootstrapSensor(ctx context.Context, tokenID shared.ID) (*shared.ID, error)
}

// Spool stores the relayed files, shared by every API replica.
type Spool interface {
	// Store checks, in one transaction, that the round is open, claimed by
	// the uploader and unexpired (ErrRoundClosed), that the file was not
	// already uploaded in it with other bytes (ErrDuplicate; the same bytes
	// again is a no-op), the round's budget (ErrRoundFull) and the spool's
	// quota (ErrSpoolFull, also recorded on the round); then upserts the file
	// and adds its size to the round.
	Store(ctx context.Context, u Upload) error
	// List returns a feed's files (no bytes).
	List(ctx context.Context, feed string) ([]SpoolFile, error)
	// Read returns one file's bytes.
	Read(ctx context.Context, feed, name string) ([]byte, error)
	// Prune deletes a feed's files keep does not name.
	Prune(ctx context.Context, feed string, keep []string) (int, error)
	// Clear deletes every file.
	Clear(ctx context.Context) (int, error)
}
