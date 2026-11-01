package command

// The scan identification markers a job carries (docs/architecture/
// scan-identification.md): the platform's layer and the organization's,
// merged per job for the job's own tenant into http_policy, before the
// bug-bounty program rules go over them (program_rules.go). The sensor adds
// its host owner's local layer and may not change a locked name.

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanident"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PlatformIdentitySource returns the platform layer of the scan
// identification markers (*scanidentity.Service).
type PlatformIdentitySource interface {
	PlatformLayer(ctx context.Context) (scanident.PlatformLayer, error)
}

// WithPlatformIdentity merges the platform's scan identification layer under
// the organization's in every scan, retest and validate job's http_policy.
func WithPlatformIdentity(p PlatformIdentitySource) Option {
	return func(s *Service) { s.platformIdentity = p }
}

// jobIdentity returns the merged identity of tenantID's jobs and the
// organization's other tool HTTP settings. Either layer that cannot be read
// fails (a job never leaves without a layer in force).
func (s *Service) jobIdentity(ctx context.Context, tenantID shared.ID) (scanident.Effective, sensordom.ToolHTTPPolicy, error) {
	var org sensordom.ToolHTTPPolicy
	if s.httpPolicy != nil {
		p, err := s.httpPolicy.ToolHTTPPolicy(ctx, tenantID)
		if err != nil {
			return scanident.Effective{}, org, fmt.Errorf("read the organization's tool HTTP policy: %w", err)
		}
		org = p
	}
	var plat scanident.PlatformLayer
	if s.platformIdentity != nil {
		p, err := s.platformIdentity.PlatformLayer(ctx)
		if err != nil {
			return scanident.Effective{}, org, fmt.Errorf("read the platform scan identification: %w", err)
		}
		plat = p
	}
	names := make([]string, 0, len(org.Headers))
	for n := range org.Headers {
		names = append(names, n)
	}
	slices.SortFunc(names, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	layer := scanident.OrganizationLayer{UserAgent: org.UserAgent}
	for _, n := range names {
		layer.Headers = append(layer.Headers, scanident.Header{Name: n, Value: org.Headers[n]})
	}
	return scanident.Merge(plat, layer), org, nil
}

// jobHTTPPolicy is the http_policy a job of tenantID carries.
func (s *Service) jobHTTPPolicy(ctx context.Context, tenantID shared.ID) (sensordom.ToolHTTPPolicy, error) {
	eff, org, err := s.jobIdentity(ctx, tenantID)
	if err != nil {
		return sensordom.ToolHTTPPolicy{}, err
	}
	return sensordom.ToolHTTPPolicy{
		UserAgent:        eff.UserAgent,
		AllowInsecureTLS: org.AllowInsecureTLS,
		Headers:          eff.HeaderMap(),
		LockedHeaders:    eff.LockedNames(),
		UserAgentLocked:  eff.UserAgentLocked,
	}, nil
}
