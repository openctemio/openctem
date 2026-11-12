// Package lookupjob asks the platform's instance-scope sensors passive
// questions on behalf of one organization (docs/architecture/certificate-transparency-monitoring.md):
// the platform makes no outbound request for them itself.
//
// Ask creates a job bound to the organization and waits for its answer. A
// platform sensor that reports the capability claims the job (Next), gets
// it signed by the job signer (command type lookup, the organization's
// tenant id, the instance scope, this sensor), and reports the answer
// (Done). An organization's sensor is never offered a job and is refused on
// both routes. The answer is read back by (tenant, job id), so it can only
// reach the organization that asked; the caller still validates it (the
// sensor is not trusted).
package lookupjob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/lookupjob"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Defaults.
const (
	// DefaultTimeout bounds one Ask (claim, upstream queries, answer).
	DefaultTimeout = 120 * time.Second
	// DefaultPoll is how often Ask reads its job back.
	DefaultPoll = 500 * time.Millisecond
	// RetryIdle is the Retry-After for a sensor when no job is open.
	RetryIdle = 5 * time.Second
	// MaxResultBytes bounds a stored answer.
	MaxResultBytes = 9 << 20
	// sensorFresh: a sensor seen within this window counts as available.
	sensorFresh = 5 * time.Minute
	// purgeAfter: jobs older than this are removed whatever their state.
	purgeAfter = 24 * time.Hour
)

// Errors of Ask.
var (
	// ErrUnavailable: no platform sensor serves the capability (or no job
	// signer is configured).
	ErrUnavailable = errors.New("no platform sensor serves this lookup")
	// ErrTimeout: no answer in time.
	ErrTimeout = errors.New("the platform sensor did not answer in time")
	// ErrNotEligible: the sensor may not serve lookup jobs (not an
	// active instance-scope sensor reporting a served capability).
	ErrNotEligible = errors.New("this sensor does not serve lookup jobs")
)

// FailedError: the sensor answered without a result (refused or failed).
type FailedError struct {
	Status string
	Code   string
}

func (e *FailedError) Error() string { return "lookup " + e.Status + ": " + e.Code }

// Signer signs job statements (the job signer client).
type Signer interface {
	SignJob(ctx context.Context, st jobsign.Statement) (json.RawMessage, error)
}

// Config configures the Service.
type Config struct {
	// Signer signs the jobs; nil: lookups are unavailable (a sensor that
	// pins the job-signing key would refuse an unsigned job).
	Signer  Signer
	Timeout time.Duration
	Poll    time.Duration
	Now     func() time.Time
}

// Service runs lookup jobs.
type Service struct {
	cfg    Config
	repo   lookupjob.Repository
	logger *logger.Logger
}

// NewService creates the service.
func NewService(cfg Config, repo lookupjob.Repository, log *logger.Logger) *Service {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Poll <= 0 {
		cfg.Poll = DefaultPoll
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{cfg: cfg, repo: repo, logger: log.With("service", "lookup_jobs")}
}

// Available reports whether a lookup of capability can be asked now: a job
// signer is configured and an active, reachable instance-scope sensor
// reports the capability.
func (s *Service) Available(ctx context.Context, capability string) bool {
	if s == nil || s.cfg.Signer == nil {
		return false
	}
	if _, ok := lookupjob.Tools[capability]; !ok {
		return false
	}
	ok, err := s.repo.EligibleSensorExists(ctx, capability, s.cfg.Now().Add(-sensorFresh))
	if err != nil {
		s.logger.Warn("lookup jobs: sensor check failed", "error", err)
		return false
	}
	return ok
}

// Ask asks capability about target for tenantID and returns the sensor's
// answer (raw JSON, to be validated by the caller against what it asked).
func (s *Service) Ask(ctx context.Context, tenantID shared.ID, capability, target string, input any) (json.RawMessage, error) {
	tool, ok := lookupjob.Tools[capability]
	if !ok || tenantID.IsZero() || target == "" || len(target) > 253 {
		return nil, lookupjob.ErrInvalid
	}
	if !s.Available(ctx, capability) {
		return nil, ErrUnavailable
	}
	in, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("lookup input: %w", err)
	}
	now := s.cfg.Now()
	if _, err := s.repo.Purge(ctx, now.Add(-purgeAfter)); err != nil {
		s.logger.Warn("lookup jobs: purge failed", "error", err)
	}
	j := &lookupjob.Job{ID: shared.NewID(), TenantID: tenantID, Capability: capability, Tool: tool, Target: target,
		Input: in, Status: lookupjob.StatusOpen, CreatedAt: now, ExpiresAt: now.Add(s.cfg.Timeout)}
	if err := s.repo.Create(ctx, j); err != nil {
		return nil, err
	}
	// The row is the question only: whatever happens, it goes.
	defer func() {
		if err := s.repo.Delete(context.WithoutCancel(ctx), tenantID, j.ID); err != nil {
			s.logger.Warn("lookup jobs: job not removed", "error", err)
		}
	}()
	wctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	t := time.NewTicker(s.cfg.Poll)
	defer t.Stop()
	for {
		select {
		case <-wctx.Done():
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrTimeout
		case <-t.C:
		}
		got, err := s.repo.Get(wctx, tenantID, j.ID)
		if err != nil {
			if wctx.Err() != nil {
				continue
			}
			return nil, err
		}
		if !got.Terminal() {
			continue
		}
		if got.Status != lookupjob.StatusDone {
			return nil, &FailedError{Status: got.Status, Code: got.ErrorCode}
		}
		return got.Result, nil
	}
}

// Next is a claimed job with its exact payload bytes and its signed
// statement.
type Next struct {
	ID        string          `json:"id"`
	Payload   json.RawMessage `json:"payload"`
	SignedJob json.RawMessage `json:"signed_job"`
}

// payload is a job's signed payload (sdk-go lookupjob.Payload): scanner and
// targets are what the statement names.
type payload struct {
	Scanner    string          `json:"scanner"`
	Targets    []string        `json:"targets"`
	Capability string          `json:"capability"`
	Input      json.RawMessage `json:"input"`
}

// served returns the capabilities sn may serve; nil when it may serve none.
func served(sn *sensor.Sensor) []string {
	if sn == nil || !sn.IsShared() || sn.TenantID != nil || sn.Status != sensor.SensorStatusActive {
		return nil
	}
	var out []string
	for c := range lookupjob.Tools {
		if sn.HasCapability(c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// Next claims the sensor's next job and signs it. With no job it returns
// nil and how long the sensor should wait.
func (s *Service) Next(ctx context.Context, sn *sensor.Sensor) (*Next, time.Duration, error) {
	caps := served(sn)
	if len(caps) == 0 {
		return nil, 0, ErrNotEligible
	}
	if s.cfg.Signer == nil {
		return nil, 10 * RetryIdle, nil
	}
	now := s.cfg.Now()
	j, err := s.repo.Claim(ctx, sn.ID, caps, now)
	if err != nil {
		return nil, 0, err
	}
	if j == nil {
		return nil, RetryIdle, nil
	}
	pb, err := json.Marshal(payload{Scanner: j.Tool, Targets: []string{j.Target}, Capability: j.Capability, Input: j.Input})
	if err != nil {
		return nil, 0, err
	}
	expires := now.Add(jobsign.MaxTTL)
	if j.ExpiresAt.Before(expires) {
		expires = j.ExpiresAt
	}
	env, err := s.cfg.Signer.SignJob(ctx, jobsign.Statement{
		Kind: jobsign.Kind, TenantID: j.TenantID.String(), SensorID: sn.ID.String(),
		SensorScope: jobsign.SensorScopeInstance, CommandID: j.ID.String(), CommandType: jobsign.CommandTypeLookup,
		Tool: j.Tool, PayloadSHA256: jobsign.PayloadDigest(pb), Targets: []string{j.Target},
		IssuedAt: now.UTC(), ExpiresAt: expires.UTC(),
	})
	var rf *jobsign.RefusalError
	if errors.As(err, &rf) {
		// An excluded name, for example: the job ends refused and the
		// asker backs off; the sensor asks again at once.
		s.logger.Warn("lookup jobs: the job signer refused a job", "reason", clip(rf.Reason, 64), "tenant_id", j.TenantID.String())
		if _, ferr := s.repo.FinishForPlatform(ctx, j.ID, sn.ID, lookupjob.StatusRefused, nil, "signer_"+clip(rf.Reason, 50), now); ferr != nil {
			return nil, 0, ferr
		}
		return nil, 0, nil
	}
	if err != nil {
		// Not signed now: release nothing, the job expires and the asker
		// times out (the platform never answers in the sensor's place).
		return nil, 0, fmt.Errorf("sign lookup job: %w", err)
	}
	return &Next{ID: j.ID.String(), Payload: pb, SignedJob: env}, 0, nil
}

// Result is what a sensor reports (sdk-go lookupjob.Result).
type Result struct {
	Output  json.RawMessage `json:"output,omitempty"`
	Refused string          `json:"refused,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// Done records the outcome of a job the sensor claimed. A job of another
// sensor, an answered one or an unknown id is ErrClosed (one answer).
func (s *Service) Done(ctx context.Context, sn *sensor.Sensor, jobID string, res Result) error {
	if len(served(sn)) == 0 {
		return ErrNotEligible
	}
	id, err := shared.IDFromString(jobID)
	if err != nil {
		return lookupjob.ErrClosed
	}
	status, code := lookupjob.StatusDone, ""
	var out json.RawMessage
	switch {
	case res.Refused != "":
		status, code = lookupjob.StatusRefused, "sensor_"+clip(code0(res.Refused), 50)
	case res.Error != "":
		status, code = lookupjob.StatusFailed, "sensor_"+clip(code0(res.Error), 50)
	case len(res.Output) == 0 || len(res.Output) > MaxResultBytes || !json.Valid(res.Output):
		status, code = lookupjob.StatusFailed, "bad_answer"
	default:
		out = res.Output
	}
	ok, err := s.repo.FinishForPlatform(ctx, id, sn.ID, status, out, code, s.cfg.Now())
	if err != nil {
		return err
	}
	if !ok {
		return lookupjob.ErrClosed
	}
	return nil
}

// code0 keeps a short, safe code from what a sensor sent.
func code0(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return -1
	}, strings.ToLower(s))
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
