package scan

// The takeover exception (research/22 decision E13): a scan that runs only
// the nuclei `takeover` templates may probe a dependency asset that has an
// open dangling_cname. The ownership gate decides which assets qualify
// (easm.ActiveGate.TakeoverAdmitted*); this file decides which scans are
// takeover-only. Architecture: docs/architecture/active-probe-gate.md.

import (
	"context"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
)

// TakeoverGate is the optional part of the AttributionGate that admits
// dependency assets with an open dangling_cname to a takeover-only scan.
type TakeoverGate interface {
	TakeoverAdmittedAssets(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]bool, error)
	TakeoverAdmittedTargets(ctx context.Context, tenantID shared.ID, targets []string) (map[string]bool, error)
}

// takeoverProbeKeys are the only scanner settings a takeover-only scan may
// carry: anything that could select other templates (templates, workflows,
// template ids or URLs, other tags) makes it an ordinary scan.
var takeoverProbeKeys = map[string]bool{
	"tags": true, "severity": true, "rate_limit": true, "concurrency": true, "timeout": true, "retries": true,
}

// IsTakeoverOnlyProbe reports whether a scan runs nuclei with exactly the
// `takeover` tag and no other template selection.
func IsTakeoverOnlyProbe(scannerName string, config map[string]any) bool {
	if !tooldom.SameTool(scannerName, "nuclei") || len(config) == 0 {
		return false
	}
	for k := range config {
		if !takeoverProbeKeys[k] {
			return false
		}
	}
	var tags []string
	switch v := config["tags"].(type) {
	case []string:
		tags = v
	case []any:
		for _, t := range v {
			s, ok := t.(string)
			if !ok {
				return false
			}
			tags = append(tags, s)
		}
	case string:
		tags = strings.Split(v, ",")
	default:
		return false
	}
	if len(tags) != 1 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(tags[0]), "takeover")
}

// admitTakeoverTargets removes from blocked the entries the gate admits for
// a takeover-only scan: dependency assets with an open dangling_cname. Keys
// are asset ids when byAsset, typed targets otherwise. A gate without the
// exception, or a failed lookup, admits nothing (the refusal stands).
func (s *Service) admitTakeoverTargets(ctx context.Context, tenantID shared.ID, blocked map[string]attribution.State, byAsset bool) error {
	tg, ok := s.attributionGate.(TakeoverGate)
	if !ok || len(blocked) == 0 {
		return nil
	}
	keys := make([]string, 0, len(blocked))
	for k, st := range blocked {
		if st == attribution.StateDependency {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	var (
		admitted map[string]bool
		err      error
	)
	if byAsset {
		admitted, err = tg.TakeoverAdmittedAssets(ctx, tenantID, keys)
	} else {
		admitted, err = tg.TakeoverAdmittedTargets(ctx, tenantID, keys)
	}
	if err != nil {
		return err
	}
	for k := range admitted {
		if blocked[k] == attribution.StateDependency {
			delete(blocked, k)
		}
	}
	return nil
}
