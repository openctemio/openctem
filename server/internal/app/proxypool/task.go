package proxypool

// Task-reported proxy faults (docs/architecture/sensor-proxies.md): the
// platform records the pool and endpoints it hands each pooled job and,
// when the job ends, charges the job's own proxy verdict to exactly those
// endpoints. The sensor never names an endpoint here: a job can only lower
// the health of endpoints the platform gave it, of its own tenant's pool.

import (
	"context"
	"fmt"
	"slices"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/metrics"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	pooldom "github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// quarantineSourceTasks is the metric source of a quarantine decided from
// the jobs' own results.
const quarantineSourceTasks = "task_reports"

// RecordJobEgress records the egress the platform handed a claimed job
// (the member it stamped on the delivered payload, never one a sensor
// sent). A job with no pool is not recorded.
func (s *Service) RecordJobEgress(ctx context.Context, tenantID, commandID, sensorID shared.ID, leaseEpoch int, eg *pooldom.JobEgress) error {
	if eg == nil || eg.Mode != pooldom.ModePool {
		return nil
	}
	pid, err := shared.IDFromString(eg.PoolID)
	if err != nil {
		return fmt.Errorf("%w: invalid pool id", shared.ErrValidation)
	}
	ids := make([]string, 0, len(eg.Endpoints))
	for _, e := range eg.Endpoints {
		ids = append(ids, e.ID)
	}
	return s.repo.RecordCommandEgress(ctx, pooldom.CommandEgress{TenantID: tenantID, CommandID: commandID, SensorID: sensorID,
		LeaseEpoch: leaseEpoch, PoolID: pid, Revision: eg.Revision, AppliesTo: eg.AppliesTo, EndpointIDs: ids})
}

// ObserveJobVerdict closes the job's recorded egress with its verdict and
// folds the verdicts of the window into the health of the endpoints the job
// was handed. A job without a record (direct, another sensor or lease, a
// repeat) changes nothing. A quarantine is audited and counted.
func (s *Service) ObserveJobVerdict(ctx context.Context, tenantID, commandID, sensorID shared.ID, leaseEpoch int, v pooldom.TaskVerdict) error {
	now := s.now().UTC()
	rec, err := s.repo.CloseCommandEgress(ctx, tenantID, commandID, sensorID, leaseEpoch, v, now)
	if err != nil || rec == nil {
		return err
	}
	metrics.ProxyTaskVerdictsTotal.WithLabelValues(v.Verdict).Inc()
	samples, err := s.repo.TaskSamples(ctx, tenantID, rec.PoolID, now.Add(-pooldom.TaskWindow))
	if err != nil {
		return err
	}
	if !v.Fault() && !slices.ContainsFunc(samples, func(t pooldom.TaskSample) bool { return t.Fault }) {
		// A clean job in a clean window: nothing to fold.
		return nil
	}
	lastErr := ""
	if v.Fault() {
		lastErr = fmt.Sprintf("a job reported %d host(s) the proxy pool could not carry (%s)", v.Faults, pooldom.ReasonProxyUnavailable)
	}
	type change struct {
		addr       string
		counts     pooldom.TaskCounts
		endpointID string
	}
	var quarantined []change
	err = s.repo.UpdateHealth(ctx, tenantID, rec.PoolID, func(eps []*pooldom.Endpoint) {
		for _, e := range eps {
			id := e.ID.String()
			if !slices.Contains(rec.EndpointIDs, id) {
				continue
			}
			counts := pooldom.CountTasks(samples, id, e.Health.TaskWindowStart(now))
			if e.Health.ApplyTasks(counts, v.Fault(), lastErr, now) && e.Health.State == pooldom.StateQuarantined {
				quarantined = append(quarantined, change{addr: e.Address(), counts: counts, endpointID: id})
			}
		}
	})
	if err != nil {
		return err
	}
	for _, c := range quarantined {
		metrics.ProxyEndpointQuarantinesTotal.WithLabelValues(quarantineSourceTasks).Inc()
		s.logger.Warn("proxy endpoint quarantined from task reports", "tenant_id", tenantID.String(), "pool_id", rec.PoolID.String(),
			"endpoint_id", c.endpointID, "faulted_jobs", c.counts.Faulted, "jobs", c.counts.Total, "command_id", commandID.String())
		s.logAudit(ctx, auditapp.AuditContext{TenantID: tenantID.String()},
			auditapp.NewSuccessEvent(auditdom.ActionProxyPoolEndpointQuarantine, auditdom.ResourceTypeProxyPool, rec.PoolID.String()).
				WithMessage(fmt.Sprintf("Proxy endpoint %s quarantined: %d of %d recent jobs reported hosts the pool could not carry",
					c.addr, c.counts.Faulted, c.counts.Total)).
				WithMetadata("endpoint", c.addr).
				WithMetadata("endpoint_id", c.endpointID).
				WithMetadata("source", quarantineSourceTasks).
				WithMetadata("faulted_jobs", c.counts.Faulted).
				WithMetadata("jobs", c.counts.Total).
				WithMetadata("command_id", commandID.String()).
				WithMetadata("reported_by_sensor", sensorID.String()).
				WithSeverity(auditdom.SeverityHigh))
	}
	return nil
}
