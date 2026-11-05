package contentpin

// The derived candidate list of a path discovery job
// (docs/architecture/web-discovery.md): built at claim time from the
// organization's own web inventory for the job's origins, filtered with the
// strict discovery exclusions, and carried inline in the signed job. No
// pack is pinned for a job that asks only for the derived list.
//
// Threat model. Every row read is the job's own organization's
// (WebPathSource is tenant-scoped); one organization's paths never reach
// another's job. The list is bounded (lines and the inline byte cap) and
// never stored. A path under a path exclusion that is not allowed is left
// out with the sensor's reading of paths (contract/webpath), so case,
// encoding, dot segments and parameters cannot slip a candidate past an
// exclusion; the tool and the forwarder check again.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/ctis/v2/weburl"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// ListDerived is the lists value of the derived candidate list.
const ListDerived = "derived"

// maxDerivedLines bounds one job's derived list before the byte cap.
const maxDerivedLines = 20_000

// maxDerivedOrigins bounds the origins one job's derived list draws on.
const maxDerivedOrigins = 16

// WebPathSource reads the inputs of an origin's derived list. Every
// implementation is scoped to tenantID.
type WebPathSource interface {
	DerivedInput(ctx context.Context, tenantID shared.ID, origin string) (webendpoint.DerivedInput, error)
}

// DiscoveryDenySource lists the path prefixes path discovery never requests
// on the targets' hosts (*scope.Service).
type DiscoveryDenySource interface {
	DiscoveryDenyPaths(ctx context.Context, tenantID shared.ID, targets []string) ([]string, error)
}

// PackOriginSource reads the stored facts of an organization's web origins
// (the path discovery ledger's repository). Every implementation is scoped
// to tenantID.
type PackOriginSource interface {
	PathOriginFacts(ctx context.Context, tenantID shared.ID, origins []string) (map[string]covdom.PathOriginFacts, error)
}

// SetPackOrigins wires the scope check of a wordlist pack. Unwired, a job
// that asks for a pack is refused (fail closed).
func (p *Planner) SetPackOrigins(src PackOriginSource) { p.packOrigins = src }

// requirePackOrigins refuses a pack list unless every origin of the job is a
// live web service of the organization that an active scope entry names.
func (p *Planner) requirePackOrigins(ctx context.Context, tenantID shared.ID, targets []string) error {
	if p.packOrigins == nil {
		return refuse("a wordlist pack for path discovery is not configured")
	}
	origins := originsOf(targets)
	if len(origins) == 0 {
		return refuse("a path discovery job needs a web origin target")
	}
	facts, err := p.packOrigins.PathOriginFacts(ctx, tenantID, origins)
	if err != nil {
		return fmt.Errorf("read origin scope: %w", err)
	}
	for _, o := range origins {
		if f, ok := facts[o]; !ok || !f.ScopeEntry {
			return refuse("a wordlist pack runs only on origins an active scope entry names")
		}
	}
	return nil
}

// SetWebPaths wires the derived list of path discovery. Unwired, a job that
// asks for it is refused (it has nothing else to check).
func (p *Planner) SetWebPaths(src WebPathSource, deny DiscoveryDenySource) {
	p.webPaths, p.discoveryDeny = src, deny
}

// discoveryLists are the lists a path discovery job asks for (scanner
// config "lists"; the derived list when it names none).
func discoveryLists(payload json.RawMessage) []string {
	var p struct {
		Config        map[string]any `json:"config"`
		ScannerConfig map[string]any `json:"scanner_config"`
	}
	_ = json.Unmarshal(payload, &p)
	for _, cfg := range []map[string]any{p.ScannerConfig, p.Config} {
		raw, ok := cfg["lists"].([]any)
		if !ok {
			continue
		}
		var out []string
		for _, v := range raw {
			if s, ok := v.(string); ok {
				out = append(out, strings.ToLower(strings.TrimSpace(s)))
			}
		}
		return out
	}
	return []string{ListDerived}
}

// needsPack reports whether a path discovery job reads a pack list (any
// list but the derived one).
func needsPack(lists []string) bool {
	return slices.ContainsFunc(lists, func(l string) bool { return l != ListDerived })
}

// derivedWebPaths builds the derived list of the job's origins.
func (p *Planner) derivedWebPaths(ctx context.Context, tenantID shared.ID, slot string, targets []string) (*protov2.JobInput, error) {
	if p.webPaths == nil || p.discoveryDeny == nil {
		return nil, refuse("path discovery lists are not configured")
	}
	origins := originsOf(targets)
	if len(origins) == 0 {
		return nil, refuse("a path discovery job needs a web origin target")
	}
	deny, err := p.discoveryDeny.DiscoveryDenyPaths(ctx, tenantID, origins)
	if err != nil {
		return nil, fmt.Errorf("read path exclusions: %w", err)
	}
	var all []string
	truncated := false
	seen := map[string]bool{}
	for _, o := range origins {
		in, err := p.webPaths.DerivedInput(ctx, tenantID, o)
		if err != nil {
			return nil, fmt.Errorf("read derived inputs: %w", err)
		}
		d := webendpoint.DerivedCandidates(in, deny, maxDerivedLines)
		truncated = truncated || d.Truncated
		for _, path := range d.Paths {
			if !seen[path] {
				seen[path] = true
				all = append(all, path)
			}
		}
	}
	if len(all) > maxDerivedLines {
		all, truncated = all[:maxDerivedLines], true
	}
	if len(all) == 0 {
		return nil, refuse("no candidate paths: the organization's inventory gives nothing new to check on these origins")
	}
	in, err := encodeInput(slot, PurposeWebPaths, all)
	if err != nil {
		return nil, err
	}
	if in == nil {
		return nil, refuse("the derived path list does not fit the inline cap")
	}
	if in.Lines < len(all) {
		truncated = true
	}
	in.Source = scanrundom.InputSourceDerived
	p.logger.Info("derived path list built", "tenant_id", tenantID.String(), "origins", len(origins),
		"lines", in.Lines, "truncated", truncated)
	return in, nil
}

// originsOf are the web origins among the job's targets, normalised,
// deduplicated and bounded.
func originsOf(targets []string) []string {
	out := make([]string, 0, min(len(targets), maxDerivedOrigins))
	seen := map[string]bool{}
	for _, t := range targets {
		u, err := weburl.Parse(strings.TrimSpace(t))
		if err != nil {
			continue
		}
		o := u.Origin()
		if seen[o] {
			continue
		}
		seen[o] = true
		out = append(out, o)
		if len(out) >= maxDerivedOrigins {
			break
		}
	}
	return out
}

// isDiscovery reports whether the payload is a path discovery job.
func isDiscovery(payload json.RawMessage) bool { return commanddom.IsDiscoveryJob(payload) }
