package feedrelay

import (
	"context"
	"time"

	"golang.org/x/mod/semver"

	dom "github.com/openctemio/openctem/server/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

// RelaySensor is a designated sensor as the console shows it.
type RelaySensor struct {
	ID       string
	Sensor   *sensor.Sensor // nil: gone or no longer a platform sensor
	CanRelay bool
	// Reason is why it cannot relay (a Candidate* code, "" when it can).
	Reason     string
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

// Candidate is a platform sensor the console may offer as a relay. Reason
// says why one cannot relay ("" when it can), one of the Candidate* codes.
type Candidate struct {
	Sensor *sensor.Sensor
	Reason string
}

// Why a platform sensor cannot relay. The sensor reports the capability
// feed.relay@1 only when it can relay; when it does not, the reason is
// read from what it reports about itself (version, signed-job posture).
const (
	CandidateInactive = "inactive"
	// CandidateVersionTooOld: the sensor release has no feed relay
	// (MinRelaySensorVersion is the first that has).
	CandidateVersionTooOld = "version_too_old"
	// CandidateNoSigningKey: the sensor pins no job-signing key, so it
	// cannot check the platform's relay requests.
	CandidateNoSigningKey = "no_signing_key"
	// CandidateRelayOff: a recent sensor with a pinned key that does not
	// relay: the feed relay is turned off on its host (SENSOR_FEED_RELAY=0).
	CandidateRelayOff = "relay_off"
	// CandidateNoCapability: the sensor does not relay and reports too
	// little to say why (an older SDK without a posture report).
	CandidateNoCapability = "no_capability"
)

// MinRelaySensorVersion is the first sensor release with the feed relay.
const MinRelaySensorVersion = "v0.36.0"

// maxCandidates bounds the platform sensors listed.
const maxCandidates = 100

// CandidateReason says why a platform sensor cannot relay ("" when it can).
// Everything here is the sensor's own claim: it only explains, and never
// makes a sensor eligible (eligible decides that).
func CandidateReason(sn *sensor.Sensor) string {
	switch {
	case sn == nil:
		return CandidateNoCapability
	case sn.Status != sensor.SensorStatusActive:
		return CandidateInactive
	case sn.HasCapability(Capability):
		return ""
	}
	v := sensor.NormalizeVersion(sn.Version)
	if semver.IsValid(v) && semver.Compare(v, MinRelaySensorVersion) < 0 {
		return CandidateVersionTooOld
	}
	signed := ""
	if sn.Posture != nil && sn.Posture.Jobs != nil {
		signed = sn.Posture.Jobs.Signed
	}
	switch {
	case signed == sensor.SignedJobsOff:
		return CandidateNoSigningKey
	case semver.IsValid(v) && (signed == sensor.SignedJobsRequired || signed == sensor.SignedJobsVerifiedWhenPresent):
		return CandidateRelayOff
	}
	return CandidateNoCapability
}

// Candidates lists the platform's shared sensors and whether each can
// relay (never an organization's sensor).
func (s *Service) Candidates(ctx context.Context) ([]Candidate, error) {
	res, err := s.sensors.List(ctx, sensor.Filter{SharedOnly: true}, pagination.New(1, maxCandidates))
	if err != nil {
		return nil, err
	}
	out := make([]Candidate, 0, len(res.Data))
	for _, sn := range res.Data {
		if sn == nil || !sn.IsShared() || sn.TenantID != nil {
			continue
		}
		out = append(out, Candidate{Sensor: sn, Reason: CandidateReason(sn)})
	}
	return out, nil
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
			if !rs.CanRelay {
				rs.Reason = CandidateReason(sn)
			}
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
