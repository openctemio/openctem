package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/openctemio/openctem/api/pkg/apierror"
)

// Poll mode of GET /sensors (changed_since): the sensors page refreshes the
// fleet every 15 s, because a sensor's state moves on with the clock (the
// online window is 40 s). Re-sending every sensor on every refresh costs a
// full page of sensors per poll and a second request for the stats; in poll
// mode one request answers with the stats and only the sensors whose answer
// changed since the caller's previous one.
//
// The cursor carries what the caller already holds, so the server keeps no
// state: a hash of the fleet's ids, then a 4-byte digest of each sensor's
// answer in id order. A sensor is "changed" when the digest of its answer now
// differs, which covers every source of change at once: a write to the row
// (whichever statement made it), the clock moving its state, the health
// policy, the product catalog and the caller's host-detail permission.
// When the fleet's ids differ (a sensor added or removed) or the cursor is
// unusable, the answer is a full snapshot.
//
// Isolation: the population is ListAllSensors for the tenant of the
// authenticated principal, exactly what the paginated list returns, with the
// same host redaction. A cursor only selects which of those rows are sent; a
// forged or foreign cursor yields a snapshot of the caller's own fleet.

const (
	sensorCursorVersion = "1."
	// maxSensorCursorLen bounds the query parameter (8 + 4×200 bytes, base64).
	maxSensorCursorLen = 1200
	// maxPolledFleet is the largest fleet that gets a cursor; a larger fleet
	// is answered in full on every poll (its cursor would not fit a URL).
	maxPolledFleet = 200
	fleetHashLen   = 8
	rowDigestLen   = 4
)

// SensorListChangesResponse is GET /sensors?changed_since= .
type SensorListChangesResponse struct {
	// Items are every sensor (full) or only the changed ones (not full).
	Items []*SensorResponse `json:"items"`
	// Total is the number of sensors in the fleet.
	Total   int  `json:"total"`
	Page    int  `json:"page"`
	PerPage int  `json:"per_page"`
	Full    bool `json:"full"`
	// Cursor is passed as changed_since on the next poll; absent for a fleet
	// above maxPolledFleet sensors.
	Cursor string               `json:"cursor,omitempty"`
	Stats  *SensorStatsResponse `json:"stats"`
}

// listChanges answers the poll mode of GET /sensors.
func (h *SensorHandler) listChanges(w http.ResponseWriter, r *http.Request, tenantID, cursor string) {
	q := r.URL.Query()
	for _, k := range []string{"type", "status", "health", "execution_mode", "search", "capabilities",
		"tools", "sdk_version", "has_capacity", "page", "per_page"} {
		if q.Has(k) {
			apierror.BadRequest("changed_since cannot be combined with filters or paging").WriteJSON(w)
			return
		}
	}
	if len(cursor) > maxSensorCursorLen {
		apierror.BadRequest("changed_since is too long").WriteJSON(w)
		return
	}

	ctx := r.Context()
	sensors, err := h.service.ListAllSensors(ctx, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	policy, now := h.policyFor(ctx, tenantID), h.now()
	stats, err := h.statsResponse(ctx, tenantID, sensors, policy)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	rows := make([]*SensorResponse, len(sensors))
	for i, a := range sensors {
		rows[i] = redactSensorHost(ctx, sensorResponseAt(a, policy, now))
	}
	items, full, next := sensorChanges(rows, cursor)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SensorListChangesResponse{
		Items: items, Total: len(rows), Page: 1, PerPage: len(items),
		Full: full, Cursor: next, Stats: stats,
	})
}

// sensorChanges returns the rows to send (all of them when the cursor does
// not describe this fleet), whether that is the full fleet, and the cursor
// for the next poll ("" above maxPolledFleet sensors).
func sensorChanges(rows []*SensorResponse, cursor string) ([]*SensorResponse, bool, string) {
	order := make([]int, len(rows))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return rows[order[a]].ID < rows[order[b]].ID })

	fleet := sha256.New()
	digests := make([]byte, 0, len(rows)*rowDigestLen)
	for _, i := range order {
		fleet.Write([]byte(rows[i].ID))
		fleet.Write([]byte{0})
		b, err := json.Marshal(rows[i])
		if err != nil {
			// Not expected for a plain struct; such a row always counts as changed.
			b = nil
		}
		sum := sha256.Sum256(b)
		digests = append(digests, sum[:rowDigestLen]...)
	}
	fleetHash := fleet.Sum(nil)[:fleetHashLen]

	next := ""
	if len(rows) <= maxPolledFleet {
		next = sensorCursorVersion + base64.RawURLEncoding.EncodeToString(append(append([]byte{}, fleetHash...), digests...))
	}

	prev, ok := decodeSensorCursor(cursor)
	if !ok || len(prev) != fleetHashLen+len(digests) || !bytes.Equal(prev[:fleetHashLen], fleetHash) {
		return rows, true, next
	}
	prevDigests := prev[fleetHashLen:]
	// Position of each row in id order, to compare in the list's own order.
	pos := make([]int, len(rows))
	for p, i := range order {
		pos[i] = p
	}
	changed := make([]*SensorResponse, 0, len(rows))
	for i, row := range rows {
		o := pos[i] * rowDigestLen
		if binary.BigEndian.Uint32(prevDigests[o:o+rowDigestLen]) != binary.BigEndian.Uint32(digests[o:o+rowDigestLen]) {
			changed = append(changed, row)
		}
	}
	return changed, false, next
}

func decodeSensorCursor(cursor string) ([]byte, bool) {
	if len(cursor) <= len(sensorCursorVersion) || cursor[:len(sensorCursorVersion)] != sensorCursorVersion {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor[len(sensorCursorVersion):])
	if err != nil || len(b) < fleetHashLen || (len(b)-fleetHashLen)%rowDigestLen != 0 {
		return nil, false
	}
	return b, true
}
