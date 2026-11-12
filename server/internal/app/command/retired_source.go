package command

// Scans of a retired source (docs/architecture/source-retirement.md): when
// an organization stops using a tool of one of its sensors as a source of
// findings, ingest refuses the results, and the claim stops the work before
// the sensor runs it. The check runs at every claim of an organization
// sensor (the claim-N poll, the poll and the claim by id), so scheduled,
// manual and coverage runs are all covered, and so is a retirement made
// after the run was queued. The shared claim is not checked: a shared
// sensor is not one of the organization's sensors, so it cannot be retired.
//
// A scan job whose tool is retired on the claiming sensor is never handed
// to it:
//   - pinned to that sensor, or no other sensor of the organization may run
//     it: it fails at claim with SOURCE_RETIRED, and its step is skipped
//     with that reason (the rest of the run goes on);
//   - otherwise it stays pending for another sensor, with the placement
//     code source_retired recorded on it.
//
// The retirements are read from the job's organization and matched on the
// claiming sensor: a retirement names one of the organization's own
// sensors, so it never stops another organization's work. A lookup that fails withholds the job (nothing is dispatched on
// an error). Using the source again takes effect at the next claim: the
// lookup reads the live retirements, with no cache.

import (
	"context"
	"fmt"

	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/sourceretire"
)

// RetiredSourceReader reads an organization's live source retirements
// (postgres.SourceRetirementRepository, tenant-scoped).
type RetiredSourceReader interface {
	Live(ctx context.Context, tenantID shared.ID) ([]sourceretire.Selector, error)
}

// WithRetiredSources makes every claim refuse the scan jobs of a sensor
// tool the organization retired as a source.
func WithRetiredSources(r RetiredSourceReader) Option {
	return func(s *Service) { s.retiredSources = r }
}

// ErrSourceRetiredAtClaim: the job's tool is retired as a source on the
// claiming sensor and no other sensor may run it, so the job was failed
// with SOURCE_RETIRED. It reads as "claimed".
var ErrSourceRetiredAtClaim = fmt.Errorf("%w (%w): the organization stopped using this tool on the sensor as a source; the job was not sent",
	ErrCommandClaimed, shared.ErrConflict)

// ErrSourceRetiredHere: the job's tool is retired as a source on the
// claiming sensor; it stays pending for another sensor. It reads as
// "claimed".
var ErrSourceRetiredHere = fmt.Errorf("%w (%w): the organization stopped using this tool on the sensor as a source; the job waits for another sensor",
	ErrCommandClaimed, shared.ErrConflict)

// ErrRetiredSourcesUnavailable: the retired sources could not be read. It
// reads as "claimed"; the job stays pending for a later claim.
var ErrRetiredSourcesUnavailable = fmt.Errorf("%w (%w): the retired sources could not be read; try later",
	ErrCommandClaimed, shared.ErrConflict)

// FailureSourceRetired is the failure code of a job refused at claim
// because its tool is retired as a source on the sensor.
const FailureSourceRetired = scanrundom.FailureSourceRetired

// sourceRetiredMessage is the English reason a refused job and its step
// carry (the web app explains the code in the reader's language).
const sourceRetiredMessage = FailureSourceRetired + ": the organization stopped using this tool on the sensor as a source of findings, " +
	"and no other sensor may run it; the task was not sent. Use the source again to run it"

// retiredOutcome is what the claim does with one job.
type retiredOutcome int

const (
	retiredKeep     retiredOutcome = iota // not retired here: claim it
	retiredWithhold                       // stays pending (another sensor, or a lookup error)
	retiredRefuse                         // fail at claim with SOURCE_RETIRED
)

// retiredTool is the tool of a job the retirement check applies to: a scan
// or connector scan (its scanner); "" for every other job.
func retiredTool(c *commanddom.Command) string {
	if c.Type != commanddom.CommandTypeScan && c.Type != commanddom.CommandTypeConnectorScan {
		return ""
	}
	return commanddom.PayloadTool(c.Payload)
}

// decideRetired is the decision for job c claimed by sensorID, given the
// organization's live retirements sels. elsewhere reports whether another
// sensor of the organization, none of those the tool is retired on, may
// claim the job now; it is only asked for an unpinned job retired here.
func decideRetired(sels []sourceretire.Selector, sensorID shared.ID, c *commanddom.Command,
	elsewhere func(exclude []shared.ID) (bool, error),
) retiredOutcome {
	tool := retiredTool(c)
	if tool == "" {
		return retiredKeep
	}
	here := false
	for _, sel := range sels {
		if sel.RetiresSensorTool(sensorID, tool) {
			here = true
			break
		}
	}
	if !here {
		return retiredKeep
	}
	if c.SensorID != nil || elsewhere == nil {
		return retiredRefuse
	}
	exclude := sourceretire.SensorsRetiring(sels, tool) // sensorID among them
	ok, err := elsewhere(exclude)
	switch {
	case err != nil:
		return retiredWithhold // fail closed: never dispatched on an error
	case ok:
		return retiredWithhold
	}
	return retiredRefuse
}

// retiredHold keeps the jobs whose tool is not retired on sensorID, in
// order; the others are withheld (recorded as source_retired when another
// sensor may run them) or failed at claim. A nil reader keeps every job.
func (s *Service) retiredHold(ctx context.Context, sensorID shared.ID, cmds []*commanddom.Command) []*commanddom.Command {
	if s.retiredSources == nil || len(cmds) == 0 {
		return cmds
	}
	type lookup struct {
		sels []sourceretire.Selector
		err  error
	}
	byTenant := map[shared.ID]lookup{}
	out := cmds[:0:0]
	withheld := map[shared.ID]map[shared.ID]string{}
	for _, c := range cmds {
		if retiredTool(c) == "" {
			out = append(out, c)
			continue
		}
		l, ok := byTenant[c.TenantID]
		if !ok {
			l.sels, l.err = s.retiredSources.Live(ctx, c.TenantID)
			byTenant[c.TenantID] = l
			if l.err != nil {
				s.logger.Warn("retired sources could not be read; withholding scan jobs",
					"tenant_id", c.TenantID.String(), "sensor_id", sensorID.String(), "error", l.err)
			}
		}
		if l.err != nil {
			continue
		}
		switch s.decideRetiredFor(ctx, l.sels, sensorID, c) {
		case retiredKeep:
			out = append(out, c)
		case retiredWithhold:
			if withheld[c.TenantID] == nil {
				withheld[c.TenantID] = map[shared.ID]string{}
			}
			withheld[c.TenantID][c.ID] = commanddom.PlacementSourceRetired
		case retiredRefuse:
			s.failAtClaim(ctx, c, sourceRetiredMessage, FailureSourceRetired)
		}
	}
	for tenantID, refused := range withheld {
		s.noteWithheld(ctx, tenantID, sensorID, refused)
	}
	return out
}

// retiredHoldOne is retiredHold for the claim by id: nil when the job may
// be claimed, else the error the claim returns.
func (s *Service) retiredHoldOne(ctx context.Context, sensorID shared.ID, c *commanddom.Command) error {
	if s.retiredSources == nil || retiredTool(c) == "" {
		return nil
	}
	sels, err := s.retiredSources.Live(ctx, c.TenantID)
	if err != nil {
		s.logger.Warn("retired sources could not be read; withholding the job",
			"command_id", c.ID.String(), "sensor_id", sensorID.String(), "error", err)
		return ErrRetiredSourcesUnavailable
	}
	switch s.decideRetiredFor(ctx, sels, sensorID, c) {
	case retiredWithhold:
		s.noteWithheld(ctx, c.TenantID, sensorID, map[shared.ID]string{c.ID: commanddom.PlacementSourceRetired})
		return ErrSourceRetiredHere
	case retiredRefuse:
		s.failAtClaim(ctx, c, sourceRetiredMessage, FailureSourceRetired)
		return ErrSourceRetiredAtClaim
	}
	return nil
}

// decideRetiredFor is decideRetired with the repository's re-queue
// candidates as "another sensor may run it" (the same claim conditions as a
// refusal re-queue: active, dispatchable, in the job's zone, with its tool).
func (s *Service) decideRetiredFor(ctx context.Context, sels []sourceretire.Selector, sensorID shared.ID, c *commanddom.Command) retiredOutcome {
	finder, ok := s.repo.(RequeueCandidateFinder)
	if !ok {
		return decideRetired(sels, sensorID, c, nil)
	}
	return decideRetired(sels, sensorID, c, func(exclude []shared.ID) (bool, error) {
		cands, err := finder.RequeueCandidates(ctx, c.TenantID, c.ID, exclude)
		if err != nil {
			s.logger.Warn("cannot list other sensors for a job retired on this sensor; withholding it",
				"command_id", c.ID.String(), "error", err)
		}
		return len(cands) > 0, err
	})
}
