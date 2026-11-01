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

// ErrNotFound: no such round for this sensor.
var ErrNotFound = fmt.Errorf("%w: feed relay round not found", shared.ErrNotFound)

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

// Round is one round.
type Round struct {
	ID          shared.ID
	SensorID    shared.ID
	Feed        string
	Phase       string
	Status      string
	Origins     []string
	Files       []File
	Report      *Report
	ErrorCode   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	DeliveredAt *time.Time
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

// Repository stores rounds.
type Repository interface {
	Create(ctx context.Context, r *Round) error
	// GetForSensor returns the round when it was issued to that sensor.
	GetForSensor(ctx context.Context, id, sensorID shared.ID) (*Round, error)
	// NextOpen returns the sensor's oldest open round that has not expired,
	// or nil.
	NextOpen(ctx context.Context, sensorID shared.ID, now time.Time) (*Round, error)
	// Latest returns the newest round of a feed, or nil.
	Latest(ctx context.Context, feed string) (*Round, error)
	// LatestOfPhase returns the newest round of a feed in a phase, or nil.
	LatestOfPhase(ctx context.Context, feed, phase string) (*Round, error)
	// Finish closes an open round of that sensor (status, report). false:
	// the round was not open.
	Finish(ctx context.Context, id, sensorID shared.ID, status string, rep *Report, at time.Time) (bool, error)
	// ExpireOpen marks open rounds past their expiry expired.
	ExpireOpen(ctx context.Context, now time.Time) (int, error)
	// DeleteBefore removes rounds created before t (retention).
	DeleteBefore(ctx context.Context, t time.Time) (int, error)
}
