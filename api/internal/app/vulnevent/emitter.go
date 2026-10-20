// Package vulnevent emits the platform-wide log of material vulnerability
// changes after each corpus import and each KEV or EPSS sync. It compares
// what changed with what it saw before, so a change is reported once and a
// replay reports nothing; the first run records the current state without
// reporting anything.
//
// Threat model: every input is a public fact (signed vulnerability bundle,
// CISA KEV, FIRST EPSS) and the output is a global table with no tenant
// data, read only by the platform's alert planner. A poisoned feed can add
// events, which the planner bounds per organization (rate cap, levels that
// need exploitation evidence); it cannot learn anything about tenants.
//
// Design: docs/rfcs/RFC-117-emerging-threat-alerts.md.
package vulnevent

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/vulnevent"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Tuning.
const (
	pageSize = 1000
	// Retention of the log.
	Retention = 2 * 365 * 24 * time.Hour
	// maxPages bounds one run; the rest continues on the next.
	maxPages = 500
)

// Emitter writes vuln_events.
type Emitter struct {
	store  vulnevent.Store
	logger *logger.Logger
	now    func() time.Time
}

// NewEmitter creates an Emitter.
func NewEmitter(store vulnevent.Store, log *logger.Logger) *Emitter {
	return &Emitter{store: store, logger: log.With("service", "vuln_events"), now: time.Now}
}

// SetClockForTest replaces the clock.
func SetClockForTest(e *Emitter, now func() time.Time) { e.now = now }

// EmitCorpus reports the material changes of the CVE records written since
// the last call. The first call records every record and reports nothing.
func (e *Emitter) EmitCorpus(ctx context.Context) (int, error) {
	at, key, ok, err := e.store.CorpusCursor(ctx)
	if err != nil {
		return 0, err
	}
	if !ok {
		n, err := e.store.BaselineCorpus(ctx)
		if err != nil {
			return 0, err
		}
		e.logger.Info("vulnerability event baseline recorded", "records", n)
		return 0, nil
	}
	emitted := 0
	for range maxPages {
		changes, err := e.store.ChangedRecords(ctx, at, key, pageSize)
		if err != nil {
			return emitted, err
		}
		if len(changes) == 0 {
			break
		}
		now := e.now().UTC()
		var events []vulnevent.Event
		states := make([]vulnevent.State, 0, len(changes))
		for _, c := range changes {
			events = append(events, vulnevent.Diff(c.Prev, c.Cur, now)...)
			states = append(states, c.Cur)
		}
		last := changes[len(changes)-1]
		if err := e.store.Record(ctx, events, states, last.SyncedAt, last.Cur.VulnID); err != nil {
			return emitted, fmt.Errorf("record events: %w", err)
		}
		emitted += len(events)
		at, key = last.SyncedAt, last.Cur.VulnID
		if len(changes) < pageSize {
			break
		}
	}
	if emitted > 0 {
		e.logger.Info("vulnerability events emitted", "source", "corpus", "events", emitted)
	}
	return emitted, nil
}

// EmitKEV reports the CVEs that entered the KEV catalog since the last call.
func (e *Emitter) EmitKEV(ctx context.Context) (int, error) {
	n, err := e.store.SyncKEV(ctx)
	if err == nil && n > 0 {
		e.logger.Info("vulnerability events emitted", "source", "kev", "events", n)
	}
	return n, err
}

// EmitEPSS reports the tracked CVEs whose EPSS score crossed into a higher
// band since the last call.
func (e *Emitter) EmitEPSS(ctx context.Context) (int, error) {
	n, err := e.store.SyncEPSS(ctx)
	if err == nil && n > 0 {
		e.logger.Info("vulnerability events emitted", "source", "epss", "events", n)
	}
	return n, err
}

// Prune deletes events past the retention.
func (e *Emitter) Prune(ctx context.Context) (int64, error) {
	return e.store.Prune(ctx, e.now().Add(-Retention))
}
