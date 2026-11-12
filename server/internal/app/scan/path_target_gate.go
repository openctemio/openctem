package scan

// Repositories go to code scanning only (docs/architecture/active-probe-gate.md,
// "Repositories and path targets"). A repository asset, and any target in
// the form of a repository or another path without a scheme
// ("github.com/acme/app", "git@github.com:acme/app"), is handed only to a
// tool that scans code or images. A network tool (port scan, HTTP probe,
// templates, DNS, crawling) given one would send traffic to the host part,
// which for a repository is a code host many organizations share, not an
// asset of the organization.
//
// Where it is enforced:
//   - a single-scanner run (resolveScanTargets), and every workflow step
//     (FilterStepTargets): by the tool's catalog stage, else by the target
//     types the tool declares; a tool nothing is known about gets none;
//   - the stage kind gate (stage.FilterKinds) for every catalog stage;
//   - the claim-time re-check (refusePathTargets): a job whose tool or
//     capability the catalog places on a network stage loses them.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// isPathTarget reports whether a target is a repository: an inventory
// target by its stored type (typeOf), any other in the path form. An
// inventory target of another type (a container image) is left to the type
// gate.
func isPathTarget(t string, typeOf func(string) (asset.TypeRef, bool)) bool {
	if typeOf != nil {
		if ref, typed := typeOf(t); typed {
			return stage.IsRepositoryType(ref)
		}
	}
	return stage.ClassifyTarget(t) == stage.KindPath
}

// toolTakesPathTargets reports whether a run of the tool may be handed a
// repository. The catalog decides for the tools and capabilities it knows
// (code and image stages only); a tenant tool decides by the target types
// it declares (a repository or a container image among them). A tool that declares nothing, or
// that does not exist, gets none (fail closed).
func (s *Service) toolTakesPathTargets(ctx context.Context, tenantID shared.ID, toolName string, caps []string) (bool, error) {
	if ok, known := stage.TakesPathTargets(toolName, caps); known {
		return ok, nil
	}
	if strings.TrimSpace(toolName) == "" || s.toolRepo == nil {
		return false, nil
	}
	t, err := s.toolRepo.GetByName(ctx, tenantID, toolName)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("repository target check: get tool %q: %w", toolName, err)
	}
	if t == nil || len(t.SupportedTargets) == 0 {
		return false, nil
	}
	compat, err := newTypeCompatibility(ctx, s.targetMappingRepo, t.SupportedTargets)
	if err != nil {
		return false, fmt.Errorf("repository target check: %w", err)
	}
	for _, ref := range []asset.TypeRef{{Type: asset.AssetTypeRepository}, {Type: asset.AssetTypeContainer}} {
		if ok, decidable := compat.decide(ref); ok && decidable {
			return true, nil
		}
	}
	return false, nil
}

// filterPathTargets leaves out the repositories a tool that does not scan
// code would be handed. It returns the targets kept, in order, how many
// were left out and why.
func (s *Service) filterPathTargets(ctx context.Context, tenantID shared.ID, toolName string, caps []string,
	targets []string, typeOf func(string) (asset.TypeRef, bool),
) (kept []string, refused int, reason string, err error) {
	n := 0
	for _, t := range targets {
		if isPathTarget(t, typeOf) {
			n++
		}
	}
	if n == 0 {
		return targets, 0, "", nil
	}
	ok, err := s.toolTakesPathTargets(ctx, tenantID, toolName, caps)
	if err != nil {
		return nil, 0, "", err
	}
	if ok {
		return targets, 0, "", nil
	}
	kept = make([]string, 0, len(targets)-n)
	for _, t := range targets {
		if !isPathTarget(t, typeOf) {
			kept = append(kept, t)
		}
	}
	name := strings.TrimSpace(toolName)
	if name == "" {
		name = "this step"
	}
	return kept, n, fmt.Sprintf("%d repository or path target(s): %s does not scan code (%s)", n, name, stage.ReasonPathTarget), nil
}

// gateScannerPaths leaves out of a single-scanner run every repository the
// scanner does not scan code for, counted as incompatible with the reason
// (stored on the run as a dispatch warning).
func (s *Service) gateScannerPaths(ctx context.Context, tenantID shared.ID, scanner string, out *resolvedTargets, typeOf func(string) (asset.TypeRef, bool)) error {
	if scanner == "" {
		return nil
	}
	kept, n, reason, err := s.filterPathTargets(ctx, tenantID, scanner, nil, out.Targets, typeOf)
	if err != nil || n == 0 {
		return err
	}
	out.Incompatible += n
	out.Targets = kept
	if out.IncompatibleReason != "" {
		out.IncompatibleReason += "; "
	}
	out.IncompatibleReason += reason
	out.Warnings = append(out.Warnings, fmt.Sprintf("%d target(s) were skipped: %s", n, reason))
	return nil
}

// refusePathTargets refuses, for a job the catalog places on a stage that
// takes network kinds (in.Job: the claim-time re-check), every target in
// the path form. A job the catalog cannot place was decided when it was
// built, from what is known of its tool.
func (s *Service) refusePathTargets(_ context.Context, in DispatchTargetsInput, kept []string, out *DispatchTargets) ([]string, error) {
	if in.Job == nil || len(kept) == 0 {
		return kept, nil
	}
	var caps []string
	if c := strings.TrimSpace(in.Job.Capability); c != "" {
		caps = []string{c}
	}
	if ok, known := stage.TakesPathTargets(in.Job.Tool, caps); ok || !known {
		return kept, nil
	}
	allowed := make([]string, 0, len(kept))
	refused := 0
	for _, t := range kept {
		if stage.ClassifyTarget(t) == stage.KindPath {
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: stage.ReasonPathTarget, Code: scopedom.RefusalInvalidTarget})
			refused++
			continue
		}
		allowed = append(allowed, t)
	}
	if refused > 0 && !in.DryRun && s.logger != nil {
		s.logger.Warn("SECURITY: repository targets refused for a network job",
			"tenant_id", in.TenantID.String(), "path", in.gatePath(), "tool", in.Job.Tool, "count", refused)
	}
	return allowed, nil
}
