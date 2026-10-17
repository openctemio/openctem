package signer

// The signer's zone ledger (docs/rfcs/RFC-100-shared-sensors.md §6.1): the
// instance scan zones an instance administrator created, each with its
// ranges, the organizations it is assigned to and the shared sensors that
// serve it, kept in ledger.log beside the scope ledger.
//
// A statement for a shared sensor that names a zone is signed only when:
//
//   - the zone is in this ledger;
//   - it is assigned to the statement's organization (overlapping private
//     ranges of different organizations are told apart by the zone: a zone
//     assigned to organization B never signs organization A's job);
//   - the claiming sensor serves it;
//   - the statement carries exactly the zone's ranges.
//
// The shared-job rules (shared.go) then let internal targets through only
// inside those ranges. Zone checks are enforced in every ledger mode: they
// are new, so no installed job depends on them being skipped.
//
// The ledger changes only through POST /v1/ledger/zones from the API's
// console service (super admin, step-up, reason, admin audit) and every
// change is a hash-chained ledger.log line naming the administrator. A
// compromised API can record a zone; the organization's scope ledger still
// bounds every target, and the sensor's local policy and private-range
// switch still bound what a shared sensor reaches.

import (
	"net/http"
	"slices"
	"time"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Zone ledger record kinds and refusal reasons.
const (
	recordZonePut    = "zone_put"
	recordZoneDelete = "zone_delete"

	ReasonZoneMalformed   = "zone_malformed"
	ReasonZoneNotInLedger = "zone_not_in_ledger"
	ReasonZoneNotAssigned = "zone_not_assigned"
	ReasonZoneSensor      = "zone_sensor"
	ReasonZoneRanges      = "zone_ranges"
)

// validateZoneChange checks a zone change before it is recorded.
func validateZoneChange(ch jobsign.ZoneChange) *refusal {
	if len(ch.Requester) > 200 {
		return refuse(http.StatusBadRequest, ReasonZoneMalformed, "requester is too long")
	}
	switch {
	case ch.Put != nil && ch.DeleteID == "":
		return validateLedgerZone(*ch.Put)
	case ch.Put == nil && ch.DeleteID != "":
		if canonicalID(ch.DeleteID) == "" {
			return refuse(http.StatusBadRequest, ReasonZoneMalformed, "delete_id must be a canonical uuid")
		}
		return nil
	}
	return refuse(http.StatusBadRequest, ReasonZoneMalformed, "exactly one of put and delete_id is required")
}

func validateLedgerZone(z jobsign.LedgerZone) *refusal {
	if canonicalID(z.ID) == "" {
		return refuse(http.StatusBadRequest, ReasonZoneMalformed, "id must be a canonical uuid")
	}
	ranges, err := jobsign.CanonicalZoneRanges(z.Ranges)
	if err != nil {
		return refuse(http.StatusBadRequest, ReasonZoneMalformed, "%v", err)
	}
	if !sameStrings(ranges, z.Ranges) {
		return refuse(http.StatusBadRequest, ReasonZoneMalformed, "ranges must be canonical and sorted")
	}
	if len(z.Tenants) > jobsign.MaxZoneTenants || len(z.Sensors) > jobsign.MaxZoneSensors {
		return refuse(http.StatusRequestEntityTooLarge, ReasonZoneMalformed,
			"a zone has at most %d organizations and %d sensors", jobsign.MaxZoneTenants, jobsign.MaxZoneSensors)
	}
	for _, ids := range [][]string{z.Tenants, z.Sensors} {
		for _, id := range ids {
			if canonicalID(id) == "" {
				return refuse(http.StatusBadRequest, ReasonZoneMalformed, "tenants and sensors must be canonical uuids")
			}
		}
	}
	return nil
}

// replayZone applies a zone record read back from the log.
func (l *Ledger) replayZone(r LedgerRecord) {
	if l.zones == nil {
		l.zones = map[string]jobsign.LedgerZone{}
	}
	switch {
	case r.Kind == recordZonePut && r.Zone != nil:
		l.zones[r.Zone.ID] = *r.Zone
	case r.Kind == recordZoneDelete:
		delete(l.zones, r.ZoneID)
	}
}

// ApplyZone records one zone change. It is recorded in every ledger mode.
func (l *Ledger) ApplyZone(ch jobsign.ZoneChange, now time.Time) (jobsign.ZoneChangeResult, *refusal) {
	if r := validateZoneChange(ch); r != nil {
		return jobsign.ZoneChangeResult{}, r
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.zones == nil {
		l.zones = map[string]jobsign.LedgerZone{}
	}
	rec := &LedgerRecord{Time: now.UTC(), Requester: ch.Requester}
	if ch.Put != nil {
		if _, ok := l.zones[ch.Put.ID]; !ok && len(l.zones) >= jobsign.MaxZones {
			return jobsign.ZoneChangeResult{}, refuse(http.StatusRequestEntityTooLarge, ReasonZoneMalformed, "at most %d zones", jobsign.MaxZones)
		}
		z := *ch.Put
		rec.Kind, rec.Zone = recordZonePut, &z
	} else {
		if _, ok := l.zones[ch.DeleteID]; !ok {
			return jobsign.ZoneChangeResult{Zones: len(l.zones)}, nil
		}
		rec.Kind, rec.ZoneID = recordZoneDelete, ch.DeleteID
	}
	if err := l.log.append(rec); err != nil {
		l.logger.Error("ledger log not written; zone change not applied", "error", oneLine(err.Error()))
		return jobsign.ZoneChangeResult{}, refuse(http.StatusInternalServerError, ReasonInternal, "ledger log unavailable")
	}
	l.replayZone(*rec)
	l.logger.Info("zone ledger change applied", "kind", rec.Kind, "zone_id", canonicalID(rec.ZoneID+zoneID(rec.Zone)))
	return jobsign.ZoneChangeResult{Zones: len(l.zones)}, nil
}

func zoneID(z *jobsign.LedgerZone) string {
	if z == nil {
		return ""
	}
	return z.ID
}

// CheckZone checks the zone a shared job's statement names against the zone
// ledger. A statement without a zone passes here (the shared-job rules
// refuse its internal targets).
func (l *Ledger) CheckZone(st *jobsign.Statement) *refusal {
	if st.Zone == nil || st.SensorScope != jobsign.SensorScopeInstance {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	z, ok := l.zones[st.Zone.ID]
	switch {
	case !ok:
		return refuse(http.StatusForbidden, ReasonZoneNotInLedger, "the job's zone is not in the signer's zone ledger")
	case !slices.Contains(z.Tenants, st.TenantID):
		return refuse(http.StatusForbidden, ReasonZoneNotAssigned, "the job's zone is not assigned to the job's organization")
	case !slices.Contains(z.Sensors, st.SensorID):
		return refuse(http.StatusForbidden, ReasonZoneSensor, "the claiming sensor does not serve the job's zone")
	case !sameStrings(z.Ranges, st.Zone.Ranges):
		return refuse(http.StatusForbidden, ReasonZoneRanges, "the job's zone ranges are not the zone's ranges")
	}
	return nil
}

// ZoneCount is how many zones the ledger holds.
func (l *Ledger) ZoneCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.zones)
}

func (s *Service) handleLedgerZones(w http.ResponseWriter, r *http.Request) {
	var ch jobsign.ZoneChange
	if !decodeLedgerBody(w, r, &ch) {
		return
	}
	res, ref := s.ledger.ApplyZone(ch, s.now())
	if ref != nil {
		s.logger.Warn("zone ledger change refused", "reason", ref.reason, "detail", oneLine(ref.detail))
		writeJSON(w, ref.status, jobsign.Refusal{Error: "refused", Reason: ref.reason, Detail: ref.detail})
		return
	}
	writeJSON(w, http.StatusOK, res)
}
