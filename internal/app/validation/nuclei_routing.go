package validation

import (
	"context"
	"strings"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// RFC-011.2 Phase 2b — routing a finding to the `nuclei` re-verify executor.
//
// The API stays an orchestrator: it never runs nuclei. It only decides whether
// a finding's own detection signature can be re-run by a nuclei-capable agent
// (capability-gated, exactly like safe-check), builds the detection signature
// the agent needs, and refuses signatures that map to a non-detection
// (destructive) template class. The authoritative, tag-accurate safety gate is
// enforced agent-side (`-exclude-tags dos,fuzz,intrusive` + template must have a
// safe matcher); this file is the API-side half of that defense.

// nucleiTechnique is the ATT&CK technique recorded for a nuclei re-verify. It is
// a technique the safe-check kind does NOT support (see kindSupportsTechnique),
// so the selector only ever returns KindNuclei for it — never a silent
// safe-check downgrade under a nuclei technique label. T1190 (Exploit
// Public-Facing Application) is the honest label for re-running a finding's own
// detection template.
const nucleiTechnique TechniqueID = "T1190"

// excludedValidationTags are nuclei template classes that are never run for
// re-verification because they are destructive or noisy rather than a
// non-intrusive detection: denial-of-service, fuzzing, brute-force, and
// anything explicitly flagged intrusive. Mirrors the agent-side allowlist so the
// two ends of the contract cannot drift. Kept lowercase for case-insensitive
// substring matching against a template signature.
var excludedValidationTags = []string{"dos", "fuzz", "intrusive", "brute-force", "bruteforce"}

// templateSignatureAllowed reports whether a finding's detection signature may
// be re-run as a nuclei validation job. It rejects a signature whose id/CVE
// token embeds an excluded-tag marker (a template such as `apache-dos` or
// `http-fuzz`), which is the API's best-effort, defense-in-depth check: the API
// does not carry the nuclei template corpus, so the tag-accurate gate lives on
// the agent. It also rejects a path-traversal-shaped id so a signature can never
// be turned into a `-t ../../etc/...` file selector on the agent.
func templateSignatureAllowed(sig string) bool {
	sig = strings.TrimSpace(strings.ToLower(sig))
	if sig == "" {
		return false
	}
	if strings.Contains(sig, "..") || strings.Contains(sig, "/") || strings.Contains(sig, "\\") {
		return false
	}
	for _, tag := range excludedValidationTags {
		if strings.Contains(sig, tag) {
			return false
		}
	}
	return true
}

// nucleiSignature extracts the detection signature a nuclei re-verify would
// re-run for a finding, and whether one usable + allowed signature exists.
//
//   - templateID: the finding's own nuclei template id, when the finding was
//     raised by nuclei (ToolName == "nuclei") and carries a rule id. This is the
//     exact, same-detection re-run.
//   - cveID: the finding's CVE, used as a CVE→template candidate when the
//     finding's original scanner was NOT nuclei (Tenable/Trivy/…). nuclei ships
//     CVE-named templates, so `-id CVE-YYYY-NNNN` re-runs the matching template
//     where one exists; the agent verifies existence and returns inconclusive
//     (never a false downgrade) when no such template is installed.
//
// ok is false when the finding has no re-runnable signature (→ caller falls back
// to safe-check, "reachability only") or the signature resolves to an excluded
// (destructive) template class.
func nucleiSignature(f *vulnerability.Finding) (templateID, cveID string, ok bool) {
	if f == nil {
		return "", "", false
	}

	// nuclei-native finding: re-run its exact template.
	if strings.EqualFold(f.ToolName(), "nuclei") {
		if id := strings.TrimSpace(f.RuleID()); id != "" && templateSignatureAllowed(id) {
			return id, strings.TrimSpace(f.CVEID()), true
		}
	}

	// Cross-scanner finding: fall back to a CVE→template candidate.
	if cve := strings.TrimSpace(f.CVEID()); cve != "" && templateSignatureAllowed(cve) {
		return "", cve, true
	}

	return "", "", false
}

// NucleiAvailability reports whether a nuclei-validation-capable agent is
// currently online for a tenant. It is the deeper-rung sibling of
// AgentAvailability: a `validate:nuclei`-advertising agent implies a
// `validate`-advertising one, but not vice-versa, so the two gates are distinct.
// Optional on RunService — a nil gate means the fleet advertises no nuclei
// executor, so routing stays safe-check-only (Phase 2a behavior). This keeps 2b
// inert-safe: with no nuclei agent, dispatch is byte-for-byte what it is today.
type NucleiAvailability interface {
	HasNucleiValidationAgent(ctx context.Context, tenantID shared.ID) (bool, error)
}
