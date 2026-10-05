package easm

// Run-now and seed-triggered sweeps (research/22 P0-11). A sweep runs the
// Certificate Transparency monitor and then the DNS-only checks for one
// tenant, honouring the tenant\x27s switches (each service skips a tenant that
// turned it off). Run-now is limited to once per 15 minutes per tenant across
// replicas (a controller lease that is never released, so it expires); a new
// seed starts a sweep without that limit (the services\x27 own per-tenant locks
// keep two sweeps from overlapping). Sweeps run in the background with a
// time bound. Architecture: docs/architecture/easm.md.

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RunNowInterval is the minimum time between two run-now requests of one
// tenant.
const RunNowInterval = 15 * time.Minute

// sweepTimeout bounds one background sweep.
const sweepTimeout = 30 * time.Minute

// ErrSweepTooSoon is returned when the tenant asked for a sweep less than
// RunNowInterval ago.
var ErrSweepTooSoon = errors.New("a sweep was requested less than 15 minutes ago")

// SweepCT runs the CT monitor for one tenant (*certmonitor.Service).
type SweepCT interface {
	MonitorTenant(ctx context.Context, tenantID shared.ID) (int, error)
}

// SweepDNS runs the DNS-only checks for one tenant (*easmdns.Service).
type SweepDNS interface {
	MonitorTenant(ctx context.Context, tenantID shared.ID) (easmdns.RunResult, error)
	MonitorEmail(ctx context.Context, tenantID shared.ID) (easmdns.RunResult, error)
}

// RunNowLimiter admits one run-now per tenant per window.
type RunNowLimiter interface {
	// Acquire returns ok=false and when the window ends if the tenant asked
	// within it.
	Acquire(ctx context.Context, tenantID shared.ID, window time.Duration) (ok bool, until time.Time, err error)
}

// SweepService starts tenant sweeps.
type SweepService struct {
	ct      SweepCT
	dns     SweepDNS
	limiter RunNowLimiter
	logger  *logger.Logger
	// run starts f in the background (tests run it inline).
	run func(f func())
	now func() time.Time
}

// NewSweepService wires the sweep. ct or dns may be nil when that part is
// off platform-wide.
func NewSweepService(ct SweepCT, dns SweepDNS, limiter RunNowLimiter, log *logger.Logger) *SweepService {
	if log == nil {
		log = logger.NewNop()
	}
	return &SweepService{ct: ct, dns: dns, limiter: limiter, logger: log.With("service", "easm_sweep"),
		run: func(f func()) { go f() }, now: time.Now}
}

// SweepTicket says a sweep started and when the next run-now is allowed.
type SweepTicket struct {
	StartedAt    time.Time `json:"started_at"`
	NextRunNowAt time.Time `json:"next_run_now_at"`
	CTIncluded   bool      `json:"ct_included"`
	DNSIncluded  bool      `json:"dns_included"`
}

// RunNow starts a sweep for the tenant unless one was requested within
// RunNowInterval (ErrSweepTooSoon, with the time it is allowed again). A
// limiter failure refuses (fail closed).
func (s *SweepService) RunNow(ctx context.Context, tenantID shared.ID) (*SweepTicket, time.Time, error) {
	if s.limiter == nil {
		return nil, time.Time{}, errors.New("run-now is not configured")
	}
	ok, until, err := s.limiter.Acquire(ctx, tenantID, RunNowInterval)
	if err != nil {
		return nil, time.Time{}, err
	}
	if !ok {
		return nil, until, ErrSweepTooSoon
	}
	t := s.start(tenantID, "run_now")
	t.NextRunNowAt = t.StartedAt.Add(RunNowInterval)
	return t, time.Time{}, nil
}

// SweepForSeed starts a sweep after a seed was added, so its first results
// arrive in minutes, not at the next daily run.
func (s *SweepService) SweepForSeed(tenantID shared.ID) {
	if s == nil {
		return
	}
	s.start(tenantID, "seed_created")
}

func (s *SweepService) start(tenantID shared.ID, reason string) *SweepTicket {
	t := &SweepTicket{StartedAt: s.now().UTC(), CTIncluded: s.ct != nil, DNSIncluded: s.dns != nil}
	s.run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
		defer cancel()
		s.sweep(ctx, tenantID, reason)
	})
	return t
}

func (s *SweepService) sweep(ctx context.Context, tenantID shared.ID, reason string) {
	if s.ct != nil {
		n, err := s.ct.MonitorTenant(ctx, tenantID)
		if err != nil {
			s.logger.Warn("easm sweep: CT failed", "tenant_id", tenantID.String(), "reason", reason, "error", err)
		} else {
			s.logger.Info("easm sweep: CT done", "tenant_id", tenantID.String(), "reason", reason, "exposures", n)
		}
	}
	if s.dns != nil {
		if _, err := s.dns.MonitorTenant(ctx, tenantID); err != nil {
			s.logger.Warn("easm sweep: dangling-DNS check failed", "tenant_id", tenantID.String(), "reason", reason, "error", err)
		}
		if _, err := s.dns.MonitorEmail(ctx, tenantID); err != nil {
			s.logger.Warn("easm sweep: email-posture check failed", "tenant_id", tenantID.String(), "reason", reason, "error", err)
		}
	}
}
