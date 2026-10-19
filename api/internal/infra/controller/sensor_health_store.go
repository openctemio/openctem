package controller

// The health controller over the liveness store (docs/architecture/sensors.md,
// "Heartbeat soft state"; research/191 §4A.3, §4A.4).

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// livenessByID is the fast path's read of a few rows.
type livenessByID interface {
	ListLivenessCandidatesByIDForPlatform(ctx context.Context, ids []shared.ID) (time.Time, []sensor.LivenessCandidate, error)
}

// reconcileFromStore walks the ladder with the store's deadlines merged in
// (the later of the store's and Postgres's wins, so a heartbeat that fell
// back to Postgres while the store was unreachable counts).
//
// Nobody is moved while the store cannot be read (Postgres holds only
// checkpoints, which would convict a healthy fleet), nor during the
// cold-start grace that follows a store that came back empty or after an
// outage: it is rebuilt from the Postgres checkpoint and every live sensor
// heartbeats into it within the grace.
func (c *SensorHealthController) reconcileFromStore(ctx context.Context, hold string) (int, error) {
	inGrace, err := c.checkStore(ctx)
	if err != nil {
		metrics.SensorLivenessStoreErrorsTotal.WithLabelValues("generation").Inc()
		c.logger.Warn("sensor liveness store unreachable: no sensor is moved down the ladder until it is back",
			"controller", "sensor-health", "error", err)
		return 0, nil
	}

	var (
		now        time.Time
		candidates []sensor.LivenessCandidate
	)
	if time.Since(c.lastFull) >= storeFullSweep {
		now, candidates, err = c.liveness.ListLivenessCandidates(ctx)
		if err == nil {
			c.lastFull = time.Now()
		}
	} else {
		now, candidates, err = c.overdueCandidates(ctx)
	}
	if err != nil {
		c.logger.Error("failed to list sensor heartbeat deadlines", "controller", "sensor-health", "error", err)
		return 0, err
	}
	if len(candidates) == 0 {
		return 0, nil
	}

	keys := make([]sensor.LivenessKey, len(candidates))
	for i, cand := range candidates {
		keys[i] = sensor.LivenessKeyOf(cand.TenantID, cand.ID)
	}
	snaps, err := c.store.Snapshots(ctx, keys)
	if err != nil {
		metrics.SensorLivenessStoreErrorsTotal.WithLabelValues("snapshots").Inc()
		c.storeDown = true
		c.logger.Warn("sensor liveness store unreachable: no sensor is moved down the ladder until it is back",
			"controller", "sensor-health", "error", err)
		return 0, nil
	}
	if inGrace {
		return 0, nil
	}

	deadlines := make(map[shared.ID]sensor.HeartbeatDeadline, len(candidates))
	for _, cand := range candidates {
		deadlines[cand.ID] = snaps[cand.ID].Deadline(cand.Deadline)
	}
	moves := c.judge(now, candidates, deadlines, hold)

	// The store records each verdict while the sensor's entry is unchanged:
	// a heartbeat that landed since wins (it is not moved), and one that
	// lands after it is written to Postgres, which then fails the
	// compare-and-set below or sets it back online.
	for step, cands := range moves {
		kept := cands[:0]
		for _, cand := range cands {
			ok, err := c.store.Judge(ctx, sensor.LivenessKeyOf(cand.TenantID, cand.ID), snaps[cand.ID].SeenAt)
			if err != nil {
				metrics.SensorLivenessStoreErrorsTotal.WithLabelValues("judge").Inc()
				continue
			}
			if ok {
				kept = append(kept, cand)
			}
		}
		moves[step] = kept
	}
	return c.apply(ctx, moves)
}

// overdueCandidates reads the rows of the sensors the store's due index has
// past their deadline, and drops from the index the ones Postgres no longer
// watches (offline, revoked or deleted).
func (c *SensorHealthController) overdueCandidates(ctx context.Context) (time.Time, []sensor.LivenessCandidate, error) {
	_, overdue, err := c.store.Overdue(ctx, sensor.LadderGraceFloor, storeOverdueLimit)
	if err != nil {
		metrics.SensorLivenessStoreErrorsTotal.WithLabelValues("overdue").Inc()
		return time.Time{}, nil, err
	}
	if len(overdue) == 0 {
		return time.Time{}, nil, nil
	}
	byID, ok := c.liveness.(livenessByID)
	if !ok {
		return c.liveness.ListLivenessCandidates(ctx)
	}
	ids := make([]shared.ID, len(overdue))
	for i, o := range overdue {
		ids[i] = o.Key.Sensor
	}
	now, candidates, err := byID.ListLivenessCandidatesByIDForPlatform(ctx, ids)
	if err != nil {
		return time.Time{}, nil, err
	}
	live := make(map[shared.ID]bool, len(candidates))
	for _, cand := range candidates {
		live[cand.ID] = true
	}
	var gone []sensor.LivenessKey
	for _, o := range overdue {
		if !live[o.Key.Sensor] {
			gone = append(gone, o.Key)
		}
	}
	if len(gone) > 0 {
		_ = c.store.Unwatch(ctx, gone)
	}
	return now, candidates, nil
}

// checkStore notices a store that is new, was emptied, changed generation
// or is back after an outage, rebuilds it from the Postgres checkpoint and
// starts the cold-start grace. It reports whether the grace runs.
func (c *SensorHealthController) checkStore(ctx context.Context) (bool, error) {
	gen, created, err := c.store.Generation(ctx)
	if err != nil {
		c.storeDown = true
		return false, err
	}
	if created || c.storeDown || (c.gen != "" && gen != c.gen) {
		if err := c.rebuildStore(ctx); err != nil {
			c.storeDown = true
			return false, err
		}
		c.logger.Warn("sensor liveness store rebuilt from the Postgres checkpoint; convictions are held for the cold-start grace",
			"controller", "sensor-health", "grace", sensor.LivenessColdStartGrace, "new_store", created)
	}
	c.gen, c.storeDown = gen, false
	return c.store.InGrace(ctx)
}

// rebuildStore seeds the store with every watched sensor's checkpoint, due
// no earlier than the end of the grace, and starts the grace.
func (c *SensorHealthController) rebuildStore(ctx context.Context) error {
	if err := c.store.StartGrace(ctx, sensor.LivenessColdStartGrace); err != nil {
		return err
	}
	now, candidates, err := c.liveness.ListLivenessCandidates(ctx)
	if err != nil {
		return err
	}
	floor := now.Add(sensor.LivenessColdStartGrace)
	seeds := make([]sensor.LivenessSeed, 0, len(candidates))
	for _, cand := range candidates {
		if cand.Deadline.LastSeenAt == nil {
			continue
		}
		due := floor
		if d := cand.Deadline.DueAt; d != nil && d.After(due) {
			due = *d
		}
		seeds = append(seeds, sensor.LivenessSeed{
			Key: sensor.LivenessKeyOf(cand.TenantID, cand.ID), SeenAt: *cand.Deadline.LastSeenAt,
			DueAt: due, Interval: cand.Deadline.Interval,
		})
	}
	if err := c.store.Seed(ctx, seeds); err != nil {
		return err
	}
	metrics.SensorLivenessRebuildsTotal.Inc()
	return nil
}

// unwatch drops convicted-offline sensors from the store's due index (a
// heartbeat puts them back).
func (c *SensorHealthController) unwatch(ctx context.Context, cands []sensor.LivenessCandidate, moved []shared.ID) {
	if c.store == nil || len(moved) == 0 {
		return
	}
	tenant := make(map[shared.ID]*shared.ID, len(cands))
	for _, cand := range cands {
		tenant[cand.ID] = cand.TenantID
	}
	keys := make([]sensor.LivenessKey, 0, len(moved))
	for _, id := range moved {
		keys = append(keys, sensor.LivenessKeyOf(tenant[id], id))
	}
	_ = c.store.Unwatch(ctx, keys)
}

// compareShadow counts the sensors whose ladder step from the store differs
// from the step from Postgres (shadow mode; Postgres decides). Sensors the
// store has no entry for yet are not counted.
func (c *SensorHealthController) compareShadow(ctx context.Context, now time.Time, candidates []sensor.LivenessCandidate) {
	if c.store == nil || len(candidates) == 0 {
		return
	}
	if grace, err := c.checkStore(ctx); err != nil || grace {
		return
	}
	keys := make([]sensor.LivenessKey, len(candidates))
	for i, cand := range candidates {
		keys[i] = sensor.LivenessKeyOf(cand.TenantID, cand.ID)
	}
	snaps, err := c.store.Snapshots(ctx, keys)
	if err != nil {
		metrics.SensorLivenessStoreErrorsTotal.WithLabelValues("snapshots").Inc()
		return
	}
	for _, cand := range candidates {
		snap, ok := snaps[cand.ID]
		if !ok {
			continue
		}
		seen, due := snap.SeenAt, snap.DueAt
		fromStore := sensor.Ladder(now, sensor.HeartbeatDeadline{LastSeenAt: &seen, DueAt: &due, Interval: snap.Interval}).State
		fromPG := sensor.Ladder(now, cand.Deadline).State
		if fromStore != fromPG {
			metrics.SensorLivenessDisagreementsTotal.WithLabelValues(string(fromPG), string(fromStore)).Inc()
		}
	}
}
