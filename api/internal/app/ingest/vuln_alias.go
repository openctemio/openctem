package ingest

// Canonical vulnerability ids at ingest (RFC-043 §17.2).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
//
// A finding that names only advisory ids (GHSA, OSV ecosystem ids) is keyed
// on the CVE the signed feed ties them to, so a tool that reports
// GHSA-35jh-r3h4-6jhm and one that reports CVE-2021-23337 for the same
// package on the same asset report one finding. The feed alone asserts an
// alias; a report's ids decide only its own key. A finding stored under the
// advisory key takes the CVE key on its next sighting (its triage stays);
// when another finding already holds the CVE key, the two are linked as the
// same issue, never merged.

import (
	"context"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// VulnAliasResolver resolves advisory ids to the CVE the feed aliases them
// to (the postgres CVE corpus repository).
type VulnAliasResolver interface {
	ResolveVulnIDAliases(ctx context.Context, ids []string) (map[string]string, error)
}

// SetVulnAliasResolver wires feed aliases into keying (nil: off).
func (p *FindingProcessor) SetVulnAliasResolver(r VulnAliasResolver) { p.vulnAliases = r }

// AliasCollision is a finding still stored under its advisory key while
// another finding holds the CVE key the feed now gives it.
type AliasCollision struct {
	Former, Canonical string
}

// aliasCollisionLinker links such pairs as the same issue (the postgres
// finding issue link repository).
type aliasCollisionLinker interface {
	LinkAliasCollisions(ctx context.Context, tenantID shared.ID, pairs []AliasCollision) (int, error)
}

// aliasableKind reports whether a finding's key names a vulnerability id
// the feed can canonicalise: SCA, network and DAST.
func aliasableKind(f *ctis.Finding) bool {
	switch identityKind(f) {
	case vulnerability.IdentityKindSCA, vulnerability.IdentityKindNetwork, vulnerability.IdentityKindDAST:
		return true
	}
	return false
}

func namesCVE(f *ctis.Finding) bool {
	v := f.Vulnerability
	if v == nil {
		return false
	}
	if strings.TrimSpace(v.CVEID) != "" {
		return true
	}
	for _, c := range v.CVEIDs {
		if strings.TrimSpace(c) != "" {
			return true
		}
	}
	return false
}

// findingAdvisoryIDs are the advisory ids a finding names: its typed ids
// and its rule id when that is an advisory id.
func findingAdvisoryIDs(f *ctis.Finding) []string {
	raw := []string{f.RuleID}
	if f.Vulnerability != nil {
		for _, id := range f.Vulnerability.IDs {
			raw = append(raw, id.ID)
		}
	}
	return vulnerability.AdvisoryIDsOf(raw...)
}

// canonicalVulnIDsOf gives each SCA, network or DAST item that names no CVE
// the CVE its advisory ids alias, when the feed ties all of them to one
// CVE, and hands set the key the item had before (its former key).
func canonicalVulnIDsOf[T any](ctx context.Context, p *FindingProcessor, items []T,
	get func(*T) (shared.ID, *ctis.Finding), set func(item *T, former string),
) {
	if p.vulnAliases == nil {
		return
	}
	idsOf := make(map[int][]string)
	var all []string
	seen := map[string]bool{}
	for i := range items {
		a, f := get(&items[i])
		if a.IsZero() || namesCVE(f) || !aliasableKind(f) {
			continue
		}
		ids := findingAdvisoryIDs(f)
		if len(ids) == 0 {
			continue
		}
		idsOf[i] = ids
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				all = append(all, id)
			}
		}
	}
	if len(all) == 0 {
		return
	}
	aliases, err := p.vulnAliases.ResolveVulnIDAliases(ctx, all)
	if err != nil {
		p.logger.Warn("vulnerability id aliases not resolved", "error", err)
		return
	}
	for i, ids := range idsOf {
		cve, ok := vulnerability.CVEOfAdvisories(ids, aliases)
		if !ok {
			continue
		}
		a, f := get(&items[i])
		former := ""
		if k, ok := identityV2(a, f, "", 0); ok {
			former = k.Fingerprint()
		}
		v := ctis.VulnerabilityDetails{}
		if f.Vulnerability != nil {
			v = *f.Vulnerability
		}
		v.CVEID = cve
		v.CVEIDs = []string{cve}
		f.Vulnerability = &v
		set(&items[i], former)
	}
}

// linkAliasCollisions links each finding still stored under its advisory
// key to the finding that holds the CVE key, as the same issue.
func (p *FindingProcessor) linkAliasCollisions(ctx context.Context, tenantID shared.ID, pairs []AliasCollision) {
	if len(pairs) == 0 || p.issueLinks == nil {
		return
	}
	l, ok := p.issueLinks.(aliasCollisionLinker)
	if !ok {
		return
	}
	n, err := l.LinkAliasCollisions(ctx, tenantID, pairs)
	if err != nil {
		p.logger.Warn("vulnerability alias collisions not linked", "error", err)
		return
	}
	if n > 0 {
		p.logger.Info("linked findings that one vulnerability alias joins", "count", n)
	}
}
