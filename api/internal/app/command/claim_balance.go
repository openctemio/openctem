package command

// Spreading work across an organization's sensors
// (docs/architecture/placement.md, "Spreading work across sensors").
//
// Every eligible sensor is woken when a job is queued and the first claim
// wins, so without this the fastest sensor fills all its slots while an idle
// peer gets nothing. Before claiming, a sensor walks the fresh jobs it shares
// with its peers in queue order and gives each to the least-loaded sensor
// that may take it (most free slots for its size, then fewest recent claims,
// then itself); it claims only its share and leaves the rest pending for the
// peers, which were woken too. A job is shared only for
// commanddom.DefaultClaimBalanceWindow after it became claimable: a peer that
// does not claim it delays it by that much at most.

import (
	"context"
	"time"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// skipBalanced: a candidate left to a less-loaded sensor (claim_metrics.go).
const skipBalanced = "balanced"

// maxContestedRead bounds the fresh shared commands one claim reads.
const maxContestedRead = 200

// WithClaimBalanceWindow sets how long a fresh job is left to less-loaded
// sensors (commanddom.DefaultClaimBalanceWindow when not set); zero or less
// turns balancing off, so the first claim takes everything it may.
func WithClaimBalanceWindow(d time.Duration) Option {
	return func(s *Service) {
		s.balanceWindow = d
		s.balanceSet = true
	}
}

// claimBalanceWindow is the window in force.
func (s *Service) claimBalanceWindow() time.Duration {
	if !s.balanceSet {
		return commanddom.DefaultClaimBalanceWindow
	}
	return s.balanceWindow
}

// balanceClaim keeps the candidates this sensor should claim: every one it
// does not share with a peer, and of the shared ones as many as its share.
// self is the sensor's own load (free scan slots and job limit as this
// claim counts them). A repository that cannot tell, or a read error, keeps
// every candidate: balancing never blocks a claim.
func (s *Service) balanceClaim(ctx context.Context, tenantID, sensorID shared.ID, caps []string,
	cands []*commanddom.Command, slots, maxJobs int,
) []*commanddom.Command {
	window := s.claimBalanceWindow()
	contester, ok := s.repo.(commanddom.ClaimContester)
	if !ok || window <= 0 || len(cands) == 0 {
		return cands
	}
	contest, err := contester.ClaimContest(ctx, tenantID, sensorID, caps, window, maxContestedRead)
	if err != nil {
		s.logger.Warn("claim balance unavailable; claiming without it", "sensor_id", sensorID.String(), "error", err)
		return cands
	}
	self := commanddom.SensorLoad{Free: slots, Total: max(maxJobs, 1), Recent: contest.SelfRecent}
	kept := shareOf(cands, self, contest)
	claimSkipped(skipBalanced, len(cands), len(kept))
	return kept
}

// shareOf is the placement walk. It goes over the candidates in claim
// order, then the other contested commands (oldest first), giving each to
// the least-loaded of this sensor and the peers that may take it; a scan
// command no peer shares takes one of this sensor's slots. The sensor keeps
// every unshared candidate and its first n shared candidates, n being the
// shared commands the walk gave it: the shared commands are alike enough
// (same tenant, fresh, all claimable by it) that the count is what matters.
func shareOf(cands []*commanddom.Command, self commanddom.SensorLoad, contest commanddom.ClaimContest) []*commanddom.Command {
	if len(contest.Commands) == 0 {
		return cands
	}
	peersOf := make(map[shared.ID][]shared.ID, len(contest.Commands))
	for _, c := range contest.Commands {
		peersOf[c.ID] = c.Peers
	}
	loads := make(map[shared.ID]commanddom.SensorLoad, len(contest.Peers))
	for id, l := range contest.Peers {
		loads[id] = l
	}
	me := self
	share := 0
	place := func(peers []shared.ID) {
		best, bestLoad := shared.ID{}, me
		mine := true
		for _, p := range peers {
			l, ok := loads[p]
			if !ok || l.Free <= 0 {
				continue
			}
			if l.LessLoaded(bestLoad) {
				best, bestLoad, mine = p, l, false
			}
		}
		if mine {
			if me.Free > 0 {
				share++
				me.Free--
				me.Recent++
			}
			return
		}
		l := loads[best]
		l.Free--
		l.Recent++
		loads[best] = l
	}
	inCands := make(map[shared.ID]bool, len(cands))
	for _, c := range cands {
		inCands[c.ID] = true
		if peers, ok := peersOf[c.ID]; ok {
			place(peers)
		} else if c.Type == commanddom.CommandTypeScan && me.Free > 0 {
			me.Free--
			me.Recent++
		}
	}
	for _, c := range contest.Commands {
		if !inCands[c.ID] {
			place(c.Peers)
		}
	}
	out := make([]*commanddom.Command, 0, len(cands))
	for _, c := range cands {
		if _, isShared := peersOf[c.ID]; isShared {
			if share <= 0 {
				continue
			}
			share--
		}
		out = append(out, c)
	}
	return out
}
