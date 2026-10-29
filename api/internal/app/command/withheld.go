package command

// Withheld commands leave a trace (docs/architecture/placement.md). The
// dispatch gate (local_policy.go) runs in code after the poll query, so a
// command every sensor withholds used to wait for its run deadline with
// nothing saying why. Now each refusal is recorded on the pending command
// (its placement code only, commanddom.WithheldRecorder), at most once per
// commanddom.WithheldRefresh per command and code, and logged at most once
// per withheldLogEvery per sensor and code. Neither the record nor the log
// carries a target, a setting or a payload: the code, the counts and ids.

import (
	"context"
	"sync"
	"time"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// withheldLogEvery is how often one sensor's refusals for one code are
// logged.
const withheldLogEvery = 10 * time.Minute

// withheldNotesCap bounds each limiter's memory; a full limiter starts
// over (at worst one extra write or log line per key).
const withheldNotesCap = 20000

// withheldNotes rate-limits the record and the log of refusals in this
// process. The zero value is ready.
type withheldNotes struct {
	mu       sync.Mutex
	recorded map[string]time.Time // command id + code
	logged   map[string]time.Time // sensor id + code
}

// due reports whether key is due in m (not seen within every), and marks it.
func due(m map[string]time.Time, key string, now time.Time, every time.Duration) bool {
	if last, ok := m[key]; ok && now.Sub(last) < every {
		return false
	}
	m[key] = now
	return true
}

// take returns the refusals to record and the per-code counts to log now,
// and marks them.
func (n *withheldNotes) take(sensorID string, refused map[shared.ID]string, now time.Time) (record map[shared.ID]string, logCounts map[string]int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.recorded == nil || len(n.recorded) > withheldNotesCap {
		n.recorded = map[string]time.Time{}
	}
	if n.logged == nil || len(n.logged) > withheldNotesCap {
		n.logged = map[string]time.Time{}
	}
	counts := map[string]int{}
	for id, code := range refused {
		if due(n.recorded, id.String()+"|"+code, now, commanddom.WithheldRefresh) {
			if record == nil {
				record = map[shared.ID]string{}
			}
			record[id] = code
		}
		counts[code]++
	}
	for code, c := range counts {
		if due(n.logged, sensorID+"|"+code, now, withheldLogEvery) {
			if logCounts == nil {
				logCounts = map[string]int{}
			}
			logCounts[code] = c
		}
	}
	return record, logCounts
}

// keepAccepted keeps the commands gate does not withhold, in order, and
// records and logs the ones it withholds from sensorID (rate-limited).
// tenantID owns cmds; a nil gate withholds nothing.
func (s *Service) keepAccepted(ctx context.Context, tenantID, sensorID shared.ID, gate *dispatchGate, cmds []*commanddom.Command) []*commanddom.Command {
	if gate == nil {
		return cmds
	}
	out := cmds[:0:0]
	var refused map[shared.ID]string
	for _, c := range cmds {
		r := gate.refusal(c)
		if r == nil {
			out = append(out, c)
			continue
		}
		if refused == nil {
			refused = map[shared.ID]string{}
		}
		refused[c.ID] = gateReason(r)
	}
	s.noteWithheld(ctx, tenantID, sensorID, refused)
	return out
}

// noteWithheld records and logs refused (command id -> placement code), as
// far as the limits allow. A failed record is logged, never returned: the
// trace must not change what the poll hands out.
func (s *Service) noteWithheld(ctx context.Context, tenantID, sensorID shared.ID, refused map[shared.ID]string) {
	if len(refused) == 0 {
		return
	}
	record, logCounts := s.withheld.take(sensorID.String(), refused, s.clock())
	for code, n := range logCounts {
		s.logger.Info("dispatch gate withheld commands from a sensor",
			"tenant_id", tenantID.String(), "sensor_id", sensorID.String(), "reason", code, "commands", n)
	}
	rec, ok := s.repo.(commanddom.WithheldRecorder)
	if !ok || len(record) == 0 {
		return
	}
	if err := rec.RecordWithheld(ctx, tenantID, record); err != nil {
		s.logger.Warn("cannot record withheld commands", "tenant_id", tenantID.String(), "error", err)
	}
}
