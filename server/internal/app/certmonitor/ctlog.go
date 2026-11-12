package certmonitor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/openctemio/contract/ctlookup"

	"github.com/openctemio/openctem/api/internal/app/lookupjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The platform never connects to a CT source itself (zero platform egress:
// the platform talks only to its sensors). Every CT query is a lookup job
// (capability lookup.ct@1) that a platform-owned, instance-scope sensor
// answers for one organization. The sensor queries crt.sh, then Cert
// Spotter, with its own pacing, retries, cache and keys. The platform does
// not trust the answer: it is decoded strictly, bounded, and passed through
// ctlookup.Validate against the domain the platform asked about, so a name
// outside that domain never reaches an organization's exposures. Without
// such a sensor the sweep queries nothing and CT monitoring is reported
// unavailable with ReasonNeedsPlatformSensor; certificate-transparency names
// still reach the inventory through the passive subdomain discovery that
// runs on sensors (subfinder's crt.sh and Cert Spotter sources).

// ReasonNeedsPlatformSensor is why CT monitoring is unavailable when no
// platform sensor serves CT lookups.
const ReasonNeedsPlatformSensor = "needs_platform_sensor"

// ErrNeedsPlatformSensor: a CT query was asked for and no platform sensor
// can answer it.
var ErrNeedsPlatformSensor = errors.New("certificate transparency lookups need a platform sensor; the platform makes no CT request itself")

// Names of the CT sources, recorded per domain in ct_monitor_state.last_source.
const (
	SourceCRTSH       = ctlookup.SourceCRTSH
	SourceCertSpotter = ctlookup.SourceCertSpotter
)

// CTSource answers CT lookups for the platform.
type CTSource interface {
	// Available reports whether a lookup can be asked now.
	Available(ctx context.Context) bool
	// Lookup returns the answer for domain (normalised), asked for
	// tenantID. The answer is untrusted: the caller validates it.
	// ErrNeedsPlatformSensor when no sensor can answer.
	Lookup(ctx context.Context, tenantID shared.ID, domain string) (ctlookup.Output, error)
}

// Asker asks a lookup job (internal/app/lookupjob.Service).
type Asker interface {
	Available(ctx context.Context, capability string) bool
	Ask(ctx context.Context, tenantID shared.ID, capability, target string, input any) (json.RawMessage, error)
}

// SensorSource is the CTSource of a running platform: lookup jobs on the
// platform's instance-scope sensors that report lookup.ct@1.
type SensorSource struct{ Jobs Asker }

// Available reports whether such a sensor is connected.
func (s SensorSource) Available(ctx context.Context) bool {
	return s.Jobs != nil && s.Jobs.Available(ctx, ctlookup.Capability)
}

// Lookup asks one lookup job and decodes its answer strictly.
func (s SensorSource) Lookup(ctx context.Context, tenantID shared.ID, domain string) (ctlookup.Output, error) {
	if s.Jobs == nil {
		return ctlookup.Output{}, ErrNeedsPlatformSensor
	}
	raw, err := s.Jobs.Ask(ctx, tenantID, ctlookup.Capability, domain, ctlookup.Input{Domain: domain})
	if errors.Is(err, lookupjob.ErrUnavailable) {
		return ctlookup.Output{}, ErrNeedsPlatformSensor
	}
	if err != nil {
		return ctlookup.Output{}, err
	}
	return decodeOutput(raw)
}

// errBadAnswer: the sensor's answer does not decode as a lookup.ct@1 output.
var errBadAnswer = errors.New("the platform sensor's CT answer is not a lookup.ct@1 output")

func decodeOutput(raw []byte) (ctlookup.Output, error) {
	if len(raw) > ctlookup.MaxOutputBytes {
		return ctlookup.Output{}, fmt.Errorf("%w: %d bytes, at most %d", errBadAnswer, len(raw), ctlookup.MaxOutputBytes)
	}
	var out ctlookup.Output
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return ctlookup.Output{}, fmt.Errorf("%w: %w", errBadAnswer, err)
	}
	return out, nil
}

// fetchResult is what one domain query produced.
type fetchResult struct {
	entries []crtEntry
	source  string
	// dropped counts names the answer held outside the queried domain.
	dropped int
}

// sourceError: no CT source answered (each source's state).
type sourceError struct{ states []ctlookup.SourceStatus }

func (e *sourceError) Error() string {
	parts := make([]string, 0, len(e.states))
	for _, s := range e.states {
		p := s.Source + ": " + s.State
		if s.RetryAfterS > 0 {
			p += fmt.Sprintf(" (retry after %ds)", s.RetryAfterS)
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "no CT source answered"
	}
	return strings.Join(parts, "; ")
}

// retryAfter is the longest wait a source asked for.
func (e *sourceError) retryAfter() time.Duration {
	var d int
	for _, s := range e.states {
		d = max(d, s.RetryAfterS)
	}
	return time.Duration(d) * time.Second
}

// sweepClient queries CT for the domains of one sweep of one tenant.
type sweepClient struct {
	s      *Service
	tenant shared.ID
}

// fetch asks the platform sensor about domain and keeps the records of the
// source that answered, bound to domain. A failure of every source is a
// *sourceError (the domain backs off); no sensor is ErrNeedsPlatformSensor.
func (c *sweepClient) fetch(ctx context.Context, domain string) (fetchResult, error) {
	if c.s.source == nil {
		return fetchResult{}, ErrNeedsPlatformSensor
	}
	out, err := c.s.source.Lookup(ctx, c.tenant, domain)
	if err != nil {
		return fetchResult{}, err
	}
	// Never trust the sensor: the same rule it applied, against the domain
	// the platform asked about.
	clean, rep, err := ctlookup.Validate(domain, out)
	if err != nil {
		return fetchResult{}, fmt.Errorf("%w: %w", errBadAnswer, err)
	}
	source := ""
	for _, st := range clean.SourceStatus {
		if st.State == ctlookup.StateOK {
			source = st.Source
			break
		}
	}
	if source == "" {
		return fetchResult{}, &sourceError{states: clean.SourceStatus}
	}
	entries := make([]crtEntry, 0, len(clean.Records))
	for _, r := range clean.Records {
		if r.Source != source {
			continue
		}
		entries = append(entries, crtEntry{
			NameValue: strings.Join(r.DNSNames, "\n"), NotBefore: r.NotBefore, NotAfter: r.NotAfter,
			IssuerName: r.Issuer, SerialNumber: r.Serial,
		})
	}
	return fetchResult{entries: entries, source: source, dropped: rep.DroppedNames}, nil
}

// jitter returns a uniformly random duration in [0, max]. It reads
// crypto/rand: the value only spreads waits, but one random source for the
// codebase keeps the weak-random ban simple. If the system source fails, the
// wait is the full max, which is still a valid back-off.
func jitter(maxD time.Duration) time.Duration {
	if maxD <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxD)+1))
	if err != nil {
		return maxD
	}
	return time.Duration(n.Int64())
}

// sleep waits d or until ctx is done. Tests set noSleep.
func (s *Service) sleep(ctx context.Context, d time.Duration) error {
	if s.noSleep || d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
