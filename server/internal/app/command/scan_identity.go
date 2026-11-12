package command

// The scan identification markers a job carries (docs/architecture/
// scan-identification.md): the platform's layer and the organization's,
// merged per job for the job's own tenant into http_policy, before the
// bug-bounty program rules go over them (program_rules.go). The sensor adds
// its host owner's local layer and may not change a locked name.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/contract/identity"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
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
	layer := scanident.OrganizationLayer{UserAgent: org.UserAgent, UserAgents: org.UserAgents, Query: org.Query,
		IdentificationRequired: org.IdentificationRequired}
	for _, n := range names {
		layer.Headers = append(layer.Headers, scanident.Header{Name: n, Value: org.Headers[n]})
	}
	return scanident.Merge(plat, layer), org, nil
}

// jobHTTPPolicy is the http_policy job c carries (its own tenant's layers).
func (s *Service) jobHTTPPolicy(ctx context.Context, c *commanddom.Command) (sensordom.ToolHTTPPolicy, error) {
	eff, org, err := s.jobIdentity(ctx, c.TenantID)
	if err != nil {
		return sensordom.ToolHTTPPolicy{}, err
	}
	pol := sensordom.ToolHTTPPolicy{
		UserAgent:              eff.UserAgent,
		AllowInsecureTLS:       org.AllowInsecureTLS,
		Headers:                eff.HeaderMap(),
		LockedHeaders:          eff.LockedNames(),
		UserAgentLocked:        eff.UserAgentLocked,
		Query:                  eff.Query,
		IdentificationRequired: eff.IdentificationRequired,
	}
	// The list travels only when it rotates; the first value stays in
	// user_agent for a sensor without rotation.
	if len(eff.UserAgents) > 1 {
		pol.UserAgents, pol.UserAgentKey = eff.UserAgents, userAgentKey(c)
	}
	return pol, nil
}

// userAgentKey is the rotation key of job c: its scan run's id, so every
// task of one run sends one value to one host, else the command id. A run id
// the contract refuses as a key falls back to the command id.
func userAgentKey(c *commanddom.Command) string {
	var p struct {
		ScanRunID string `json:"scan_run_id"`
	}
	if json.Unmarshal(c.Payload, &p) == nil && p.ScanRunID != "" && identity.CheckKey(p.ScanRunID) == nil {
		return p.ScanRunID
	}
	return c.ID.String()
}
