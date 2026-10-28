package scan

// Verification of sensitive web paths (docs/architecture/web-content-pipeline.md):
// the web verification planner hands one group of endpoint URLs and the
// signed templates that prove them to this function, which starts the run as
// the web_verify policy. Like a coverage run, one URL that may not be
// scanned never refuses the batch: it is reported with the gate's code and
// the rest runs. The run is active (T1) and never intrusive: a path that
// needs an intrusive check is not verified this way. The run files a
// finding only through a template hit, in the normal ingest of the
// sensor's result; this function writes none.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// WebVerifyTag marks web verification scans.
const WebVerifyTag = "auto-web-verify"

// maxWebVerifyTargets caps one verification run.
const maxWebVerifyTargets = 100

// maxWebVerifyTemplates caps the templates of one run.
const maxWebVerifyTemplates = 20

// WebVerifyInput is one group of URLs checked with one set of templates.
type WebVerifyInput struct {
	TenantID    shared.ID
	TemplateIDs []string
	// Targets are the endpoint URLs; Assets maps each (lower-case) URL to
	// the origin asset id it is on, so the ownership gate checks the asset.
	Targets []string
	Assets  map[string]string
}

// WebVerifyResult is what was started. RunID is nil when nothing was left.
type WebVerifyResult struct {
	RunID   *shared.ID
	Kept    []string
	Refused []RefusedTarget
}

// ErrWebVerifyBusy: the previous run of the same template set is still
// active; the group waits for the next pass.
var ErrWebVerifyBusy = errors.New("web verification run of this template set still active")

// WebVerifyGroupKey is the managed key of a template set: the same set
// always reuses one scan.
func WebVerifyGroupKey(templateIDs []string) string {
	ids := append([]string(nil), templateIDs...)
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, ",")))
	return "web_verify:" + hex.EncodeToString(sum[:6])
}

// StartWebVerification starts the templates on the URLs, as the system.
func (s *Service) StartWebVerification(ctx context.Context, in WebVerifyInput) (*WebVerifyResult, error) {
	if in.TenantID.IsZero() || len(in.Targets) == 0 || len(in.TemplateIDs) == 0 {
		return nil, fmt.Errorf("%w: tenant, targets and templates are required", shared.ErrValidation)
	}
	if len(in.Targets) > maxWebVerifyTargets || len(in.TemplateIDs) > maxWebVerifyTemplates {
		return nil, fmt.Errorf("%w: at most %d targets and %d templates per verification run", shared.ErrValidation, maxWebVerifyTargets, maxWebVerifyTemplates)
	}
	st, ok := stage.Lookup(stage.VulnTemplates)
	if !ok || st.Tier >= stage.TierIntrusive {
		return nil, fmt.Errorf("%w: web verification never starts an intrusive stage", shared.ErrValidation)
	}
	tool := st.DefaultTool()
	if tool == "" {
		return nil, fmt.Errorf("%w: %s has no tool", shared.ErrValidation, st.Key)
	}
	tier := scopedom.TierActive
	assets := make(map[string]DispatchAsset, len(in.Assets))
	for u, id := range in.Assets {
		assets[strings.ToLower(u)] = DispatchAsset{IDs: []string{id}}
	}
	gated, err := s.ResolveDispatchTargets(ctx, DispatchTargetsInput{
		TenantID:        in.TenantID,
		Targets:         in.Targets,
		Assets:          assets,
		SystemPolicy:    string(scan.ManagedByWebVerify),
		Tier:            &tier,
		SkipZoneRouting: false,
		MaxTargets:      maxWebVerifyTargets,
		Path:            "web_verify",
		Tool:            tool,
		Capability:      string(stage.VulnTemplates),
	})
	if err != nil {
		return nil, fmt.Errorf("web verification targets not checked, nothing dispatched: %w", err)
	}
	res := &WebVerifyResult{Refused: gated.Refused}
	allowed := make(map[string]bool, len(gated.Allowed))
	for _, t := range gated.Allowed {
		allowed[strings.ToLower(t)] = true
	}
	for _, t := range gated.Excluded {
		res.Refused = append(res.Refused, RefusedTarget{Target: t, Code: "excluded", Reason: "excluded"})
	}
	for _, t := range in.Targets {
		if allowed[strings.ToLower(strings.TrimSpace(t))] {
			res.Kept = append(res.Kept, strings.TrimSpace(t))
		}
	}
	if len(res.Kept) == 0 {
		return res, nil
	}

	key := WebVerifyGroupKey(in.TemplateIDs)
	sc, err := s.webVerifyScan(ctx, in.TenantID, key, in.TemplateIDs, tool)
	if err != nil {
		return nil, err
	}
	sc.SetTargets(res.Kept)
	perJob := st.ChunkSizeFor(tool)
	if perJob <= 0 {
		perJob = defaultCoverageChunk
	}
	ids := append([]string(nil), in.TemplateIDs...)
	sort.Strings(ids)
	if err := sc.SetSingleScanner(tool, map[string]any{"targets": res.Kept, "template_ids": ids}, perJob); err != nil {
		return nil, fmt.Errorf("failed to set scanner: %w", err)
	}
	if err := s.applyIntensity(ctx, sc, string(scan.IntensityActive)); err != nil {
		return nil, err
	}
	if err := s.scanRepo.Update(ctx, sc); err != nil {
		return nil, fmt.Errorf("failed to update web verification scan: %w", err)
	}
	run, err := s.TriggerScan(ctx, TriggerScanExecInput{
		TenantID:      in.TenantID.String(),
		ScanID:        sc.ID.String(),
		SkipIfRunning: true,
		NoBlockedRun:  true,
		TriggerType:   scanworkflow.TriggerTypeSystem,
		TriggeredBy:   PolicyTriggerPrefix + string(scan.ManagedByWebVerify),
		Context:       map[string]any{"trigger": "web_verify", "target_count": len(res.Kept)},
	})
	if err != nil {
		if errors.Is(err, ErrScanRunInProgress) {
			return nil, ErrWebVerifyBusy
		}
		return nil, fmt.Errorf("failed to trigger web verification: %w", err)
	}
	res.RunID = &run.ID
	return res, nil
}

// webVerifyScan returns the tenant's verification scan of a template set,
// creating it on first use. It is found by its managed key, never by name.
func (s *Service) webVerifyScan(ctx context.Context, tenantID shared.ID, key string, templateIDs []string, tool string) (*scan.Scan, error) {
	sc, err := s.scanRepo.GetManaged(ctx, tenantID, scan.ManagedByWebVerify, key)
	if err == nil {
		return sc, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("load web verification scan: %w", err)
	}
	base := "Web verification: " + strings.TrimPrefix(key, "web_verify:")
	var createErr error
	for _, name := range []string{base, base + " (platform)", ""} {
		if name == "" {
			name = fmt.Sprintf("%s (%s)", base, shared.NewID().String()[:8])
		}
		sc, err = scan.NewScan(tenantID, name, shared.ID{}, scan.ScanTypeSingle)
		if err != nil {
			return nil, fmt.Errorf("failed to create scan: %w", err)
		}
		sc.AdHoc = true
		sc.ManagedBy, sc.ManagedKey = scan.ManagedByWebVerify, key
		sc.Description = "Verification of sensitive web paths with " + strings.Join(templateIDs, ", ")
		sc.SetTags([]string{WebVerifyTag})
		if err := sc.SetSingleScanner(tool, map[string]any{}, 1); err != nil {
			return nil, fmt.Errorf("failed to set scanner: %w", err)
		}
		if createErr = s.scanRepo.Create(ctx, sc); createErr == nil {
			s.logAudit(ctx, AuditContext{TenantID: tenantID.String()},
				NewSuccessEvent(audit.ActionScanConfigManagedCreated, audit.ResourceTypeScanConfig, sc.ID.String()).
					WithResourceName(sc.Name).
					WithMetadata("managed_by", string(scan.ManagedByWebVerify)).
					WithMetadata("managed_key", key))
			return sc, nil
		}
		if !errors.Is(createErr, shared.ErrAlreadyExists) {
			break
		}
		if got, gerr := s.scanRepo.GetManaged(ctx, tenantID, scan.ManagedByWebVerify, key); gerr == nil {
			return got, nil
		}
	}
	return nil, fmt.Errorf("failed to create web verification scan: %w", createErr)
}
