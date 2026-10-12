package ingest

// Sensor lookup reach (research/84 F-BOLA-2, F-BOLA-3): what the sensor
// lookups (POST /fingerprints/check, POST /fingerprints/baseline-diff,
// GET /suppressions) may answer about. A sensor in one zone must not learn
// which findings, repositories or suppressed paths exist in another.
//
// A sensor reaches the assets covered by
//   - the targets of the commands assigned to it that are open, or ended in
//     the last ReachCommandWindow (the targets result binding uses), and
//   - the address ranges of the scan zones it serves.
//
// A collector (sensor type) and a sensor whose grant profile is collector or
// ci-runner push results nobody asked for, anywhere in the tenant: their
// lookups stay tenant-wide. Outside its reach a sensor gets the answer it
// would get for something that does not exist (fingerprint missing,
// repository unknown, rule absent), so there is no existence oracle; every
// such answer is safe for the caller (it re-sends a finding the platform
// deduplicates, or treats a finding as new).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ReachCommandWindow is how long after a command ended its targets stay in
// the reach of the sensor that ran it (a retry queue re-checks fingerprints
// of a report it could not send at once).
const ReachCommandWindow = 24 * time.Hour

// ReachInputs are what a sensor's reach is built from.
type ReachInputs struct {
	// CommandPayloads are the payloads of the commands assigned to the
	// sensor that are open or ended inside the window.
	CommandPayloads []json.RawMessage
	// ZoneRanges are the CIDR ranges of the scan zones the sensor serves.
	ZoneRanges []string
}

// AssetLocator is what reach coverage reads of an asset.
type AssetLocator struct {
	ID         shared.ID
	Name       string
	Properties map[string]any
}

// ReachSource reads the inputs of sensor reach. Every method is scoped by
// tenant.
type ReachSource interface {
	SensorReachInputs(ctx context.Context, tenantID, sensorID shared.ID, since time.Time) (ReachInputs, error)
	FingerprintAssetIDs(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string][]shared.ID, error)
	AssetLocators(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]AssetLocator, error)
}

// SetReachSource wires the store sensor reach is read from. Without it a
// sensor's lookups reach nothing outside the tenant-wide roles (fail closed).
func (s *Service) SetReachSource(r ReachSource) { s.reach = r }

// sensorReach is one sensor's reach.
type sensorReach struct {
	all   bool
	scope *alterScope
}

func (r sensorReach) covers(name string, properties map[string]any) bool {
	return r.all || r.scope.coversLocated(name, properties)
}

// lookupsTenantWide reports whether the sensor's lookups answer about the
// whole tenant: a collector, or a sensor with a collector or ci-runner grant.
func (s *Service) lookupsTenantWide(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID) (bool, error) {
	if RoleMayPushUnsolicited(s.sensorTypeOf(ctx, agt)) {
		return true, nil
	}
	if s.grants == nil {
		return false, nil
	}
	g, err := s.grants.Get(ctx, tenantID, agt.ID)
	if errors.Is(err, shared.ErrNotFound) || (err == nil && g == nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read sensor grant: %w", err)
	}
	base, _, _ := strings.Cut(g.Profile, ":")
	return base == sensor.ProfileCollector || base == sensor.ProfileCIRunner, nil
}

// reachOf builds the sensor's reach.
func (s *Service) reachOf(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID) (sensorReach, error) {
	wide, err := s.lookupsTenantWide(ctx, agt, tenantID)
	if err != nil {
		return sensorReach{}, err
	}
	if wide {
		return sensorReach{all: true}, nil
	}
	r := sensorReach{scope: &alterScope{allowed: map[shared.ID]bool{}}}
	if s.reach == nil {
		return r, nil
	}
	in, err := s.reach.SensorReachInputs(ctx, tenantID, agt.ID, time.Now().Add(-ReachCommandWindow))
	if err != nil {
		return sensorReach{}, fmt.Errorf("read sensor reach: %w", err)
	}
	var targets []string
	for _, p := range in.CommandPayloads {
		targets = append(targets, CommandTargets(&command.Command{Payload: p})...)
	}
	targets = append(targets, in.ZoneRanges...)
	r.scope.targets = newCoverTargets(targets)
	return r, nil
}

// reachableAssets returns the ids among ids the reach covers (one query).
func (s *Service) reachableAssets(ctx context.Context, tenantID shared.ID, r sensorReach, ids []shared.ID) (map[shared.ID]bool, error) {
	out := make(map[shared.ID]bool, len(ids))
	if r.all {
		for _, id := range ids {
			out[id] = true
		}
		return out, nil
	}
	if len(ids) == 0 || len(r.scope.targets) == 0 || s.reach == nil {
		return out, nil
	}
	locs, err := s.reach.AssetLocators(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("read asset locators: %w", err)
	}
	for _, l := range locs {
		if r.covers(l.Name, l.Properties) {
			out[l.ID] = true
		}
	}
	return out, nil
}

// SensorReachableAssets returns which of ids the sensor's lookups may answer
// about (GET /suppressions keeps only the rules on these assets).
func (s *Service) SensorReachableAssets(ctx context.Context, agt *sensor.Sensor, ids []shared.ID) (map[shared.ID]bool, error) {
	if agt == nil || agt.TenantID == nil {
		return map[shared.ID]bool{}, nil
	}
	r, err := s.reachOf(ctx, agt, *agt.TenantID)
	if err != nil {
		return nil, err
	}
	return s.reachableAssets(ctx, *agt.TenantID, r, ids)
}

// reachableFingerprints keeps the known fingerprints (requested key →
// stored key) whose findings sit on an asset the reach covers.
func (s *Service) reachableFingerprints(ctx context.Context, tenantID shared.ID, r sensorReach, known map[string]string) (map[string]string, error) {
	if r.all || len(known) == 0 {
		return known, nil
	}
	out := map[string]string{}
	if len(r.scope.targets) == 0 || s.reach == nil {
		return out, nil
	}
	stored := make([]string, 0, len(known))
	seen := map[string]bool{}
	for _, k := range known {
		if !seen[k] {
			seen[k] = true
			stored = append(stored, k)
		}
	}
	assetsOf, err := s.reach.FingerprintAssetIDs(ctx, tenantID, stored)
	if err != nil {
		return nil, fmt.Errorf("read finding assets: %w", err)
	}
	var ids []shared.ID
	idSeen := map[shared.ID]bool{}
	for _, list := range assetsOf {
		for _, id := range list {
			if !idSeen[id] {
				idSeen[id] = true
				ids = append(ids, id)
			}
		}
	}
	ok, err := s.reachableAssets(ctx, tenantID, r, ids)
	if err != nil {
		return nil, err
	}
	for req, k := range known {
		for _, id := range assetsOf[k] {
			if ok[id] {
				out[req] = k
				break
			}
		}
	}
	return out, nil
}
