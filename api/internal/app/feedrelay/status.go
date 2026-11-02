package feedrelay

import (
	"context"
	"time"

	dom "github.com/openctemio/openctem/api/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RelaySensor is a designated sensor as the console shows it.
type RelaySensor struct {
	ID         string
	Sensor     *sensor.Sensor // nil: gone or no longer a platform sensor
	CanRelay   bool
	Online     bool
	LastServed *time.Time
	BytesToday int64
}

// FeedStatus is the console's view of one feed.
type FeedStatus struct {
	Feed       string
	Last       *dom.Round
	LastImport *dom.Round
	Freshness  Freshness
	// Current is the round of the cycle in progress (nil between cycles).
	Current *dom.Round
	// StaleReason is a code from the fixed list (dom.Code*), "" when the
	// feed is fine; Detail completes signer_refused.
	StaleReason string
	Detail      string
}

// Status is the setting, the relay sensors and each feed.
type Status struct {
	Settings   Settings
	Sensors    []RelaySensor
	Feeds      []FeedStatus
	NotRelayed []string
}

// Status reads the console view.
func (s *Service) Status(ctx context.Context) (Status, error) {
	st, err := s.Get(ctx)
	if err != nil {
		return Status{}, err
	}
	now := s.cfg.Now()
	out := Status{Settings: st, NotRelayed: append([]string{}, s.cfg.NotRelayed...)}
	ids := make([]shared.ID, 0, len(st.SensorIDs))
	for _, raw := range st.SensorIDs {
		if id, err := shared.IDFromString(raw); err == nil {
			ids = append(ids, id)
		}
	}
	activity, err := s.repo.Activity(ctx, ids, now.Add(-24*time.Hour))
	if err != nil {
		return Status{}, err
	}
	anyOnline := false
	for _, id := range ids {
		rs := RelaySensor{ID: id.String()}
		if sn, err := s.sensors.GetByID(ctx, id); err == nil && sn != nil && sn.IsShared() && sn.TenantID == nil {
			rs.Sensor = sn
			rs.CanRelay = eligible(sn)
			rs.Online = rs.CanRelay && sn.LastSeenAt != nil && now.Sub(*sn.LastSeenAt) < relayOffline
		}
		if a, ok := activity[id]; ok {
			rs.LastServed, rs.BytesToday = a.LastDeliveredAt, a.Bytes
		}
		anyOnline = anyOnline || rs.Online
		out.Sensors = append(out.Sensors, rs)
	}
	for _, name := range s.order {
		fs := FeedStatus{Feed: name}
		if fs.Last, err = s.repo.Latest(ctx, name); err != nil {
			return Status{}, err
		}
		if fs.LastImport, err = s.repo.LatestOfPhase(ctx, name, dom.PhaseImported); err != nil {
			return Status{}, err
		}
		if fr, err := s.feeds[name].Freshness(ctx); err == nil {
			fs.Freshness = fr
		}
		if fs.Last != nil && isFileRound(fs.Last) && fs.Last.Status == dom.StatusOpen {
			fs.Current = fs.Last
		}
		if st.Mode == ModeRelay {
			fs.StaleReason, fs.Detail = staleReason(len(ids) > 0, anyOnline, fs.Last)
		}
		out.Feeds = append(out.Feeds, fs)
	}
	return out, nil
}

// staleReason names why a feed in relay mode is not being refreshed.
func staleReason(hasRelay, online bool, last *dom.Round) (string, string) {
	switch {
	case !hasRelay:
		return dom.CodeNoRelayDesignated, ""
	case !online:
		return dom.CodeRelayOffline, ""
	case last == nil:
		return "", ""
	case last.Status == dom.StatusFailed:
		code := last.ErrorCode
		if code == "" {
			code = dom.CodeImportFailed
		}
		return code, last.ErrorDetail
	case last.Status == dom.StatusRefused:
		detail := ""
		if last.Report != nil {
			detail = last.Report.Refused
		}
		return dom.CodeSensorRefused, detail
	case last.Status == dom.StatusExpired:
		return dom.CodeRoundExpired, ""
	case last.ErrorCode == dom.CodeSpoolFull:
		return dom.CodeSpoolFull, ""
	}
	return "", ""
}
