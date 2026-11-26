package aianalysis

// The organization's switch and limits on changes AI agents make without a
// person (docs/architecture/ai-autonomy.md). Only changes that add risk
// information (confirming a finding) can happen without a person at all;
// anything that lowers risk is a request in every setting. This setting caps
// the automatic ones and can stop them at once: a paused organization, or
// one over its limit, gets the AI agent's suggestion as a comment instead.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Default limits on automatic changes per organization.
const (
	DefaultAutoChangesPerHour = 100
	DefaultAutoChangesPerDay  = 500
	// MaxAutoChangesLimit bounds a finite limit.
	MaxAutoChangesLimit = 100000
)

// Reasons an automatic change was held as a suggestion by this setting.
const (
	HoldAutonomyPaused = "autonomy_paused"
	HoldLimitReached   = "limit_reached"
)

// Autonomy is the organization's setting. A nil limit is unlimited.
type Autonomy struct {
	Paused   bool
	PausedAt *time.Time
	PausedBy string
	PerHour  *int
	PerDay   *int

	UpdatedAt *time.Time
	UpdatedBy string
}

// DefaultAutonomy is the setting of an organization that never saved one:
// not paused, 100 an hour, 500 a day.
func DefaultAutonomy() Autonomy {
	h, d := DefaultAutoChangesPerHour, DefaultAutoChangesPerDay
	return Autonomy{PerHour: &h, PerDay: &d}
}

// Validate checks the limits: unlimited (nil) or 0 to MaxAutoChangesLimit.
// A zero limit holds every automatic change, like a pause.
func (a Autonomy) Validate() error {
	for name, v := range map[string]*int{"per_hour": a.PerHour, "per_day": a.PerDay} {
		if v != nil && (*v < 0 || *v > MaxAutoChangesLimit) {
			return fmt.Errorf("%w: %s must be between 0 and %d, or unlimited", shared.ErrValidation, name, MaxAutoChangesLimit)
		}
	}
	return nil
}

// Reasons a change of the setting loosens it.
const (
	LoosenResumed      = "resumed"
	LoosenLimitRaised  = "limit_raised"
	LoosenLimitRemoved = "limit_removed"
)

// AutonomyLoosened lists why next lets more changes happen without a person
// than before (empty: a tightening or no change).
func AutonomyLoosened(before, next Autonomy) []string {
	var out []string
	if before.Paused && !next.Paused {
		out = append(out, LoosenResumed)
	}
	for _, p := range [][2]*int{{before.PerHour, next.PerHour}, {before.PerDay, next.PerDay}} {
		b, n := p[0], p[1]
		switch {
		case b != nil && n == nil:
			out = appendOnce(out, LoosenLimitRemoved)
		case b != nil && n != nil && *n > *b:
			out = appendOnce(out, LoosenLimitRaised)
		}
	}
	return out
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// AutonomyRepository stores the setting (tenant_ai_settings.autonomy) and
// counts automatic changes. Every method is tenant-scoped.
type AutonomyRepository interface {
	// GetAutonomy returns the stored setting; ok is false when the
	// organization never saved one.
	GetAutonomy(ctx context.Context, tenantID shared.ID) (Autonomy, bool, error)
	// SaveAutonomy writes next only while the stored setting is still
	// expected (nil: none saved yet), so a change decided on a stale read
	// (for example a raise judged against an older, higher limit) is never
	// written; false when it was not written.
	SaveAutonomy(ctx context.Context, tenantID shared.ID, expected *Autonomy, next Autonomy) (bool, error)
	// ReserveAutoChange counts one automatic change at now when the changes
	// of the current clock hour stay within perHour and those of the last
	// 24 clock hours within perDay (nil: unlimited); false when a limit is
	// reached, and nothing is counted. Concurrent callers of one
	// organization are serialized.
	ReserveAutoChange(ctx context.Context, tenantID shared.ID, perHour, perDay *int, now time.Time) (bool, error)
}
