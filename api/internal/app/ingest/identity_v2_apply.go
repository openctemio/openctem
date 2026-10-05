package ingest

import (
	"context"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// applyIdentityV2Of computes the version-2 identity of every item and hands
// it to set; items without one keep their version-1 key.
func applyIdentityV2Of[T any](p *FindingProcessor, tenantID shared.ID, tool *ctis.Tool, items []T,
	get func(*T) (shared.ID, *ctis.Finding), set func(*T, vulnerability.IdentityKey),
) {
	findings := make([]ctis.Finding, len(items))
	assets := make([]shared.ID, len(items))
	for i := range items {
		a, f := get(&items[i])
		assets[i], findings[i] = a, *f
	}
	occ := sastOccurrences(findings, func(i int) shared.ID { return assets[i] }, tool)
	for i := range items {
		f := &findings[i]
		secretHMAC := ""
		if f.Secret != nil && f.Secret.MaskedValue != "" {
			// Keyed per tenant with a server secret; never logged.
			secretHMAC = p.secretFingerprinter.Fingerprint(tenantID, f.Secret.MaskedValue)
		}
		if k, ok := identityV2(assets[i], f, tool, secretHMAC, occ[i]); ok {
			set(&items[i], k)
		}
	}
}

// fingerprintAdopter is implemented by the postgres finding repository.
// Optional: a repository without it (tests, mocks) re-keys nothing.
type fingerprintAdopter interface {
	CheckFingerprintsExist(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]bool, error)
	AdoptFingerprint(ctx context.Context, tenantID shared.ID, from, to string, identityKey []byte, version int) (bool, error)
}

// adoptV1KeysOf re-keys, to its version-2 key, a finding that is still
// stored under the version-1 key an item of this batch produces, when no
// finding has the version-2 key yet. Its triage, tickets and history stay;
// the version-1 key becomes an alias (RFC-043 §6, "re-keyed on the next
// sighting"). A version-1 finding is taken over by the first item only.
func adoptV1KeysOf[T any](ctx context.Context, p *FindingProcessor, tenantID shared.ID, items []T,
	keys func(T) (v1 string, identity *vulnerability.IdentityKey),
) {
	adopter, ok := p.repo.(fingerprintAdopter)
	if !ok {
		return
	}
	type pair struct {
		v1, v2 string
		raw    []byte
	}
	pairs := make([]pair, 0, len(items))
	v2s := make([]string, 0, len(items))
	for _, it := range items {
		v1, k := keys(it)
		if k == nil || v1 == "" {
			continue
		}
		v2 := k.Fingerprint()
		if v2 == "" || v2 == v1 {
			continue
		}
		raw, err := vulnerability.MarshalIdentityKey(*k)
		if err != nil {
			continue
		}
		pairs = append(pairs, pair{v1: v1, v2: v2, raw: raw})
		v2s = append(v2s, v2)
	}
	if len(pairs) == 0 {
		return
	}
	// Version-2 keys someone already holds (directly or as an alias) need
	// nothing.
	held, err := adopter.CheckFingerprintsExist(ctx, tenantID, v2s)
	if err != nil {
		p.logger.Warn("failed to check version-2 finding keys", "error", err)
		return
	}
	for alias := range resolveFingerprintAliasesOf(ctx, p, tenantID, v2s, func(s string) string { return s }) {
		held[alias] = true
	}
	v1s := make([]string, 0, len(pairs))
	for _, pr := range pairs {
		if !held[pr.v2] {
			v1s = append(v1s, pr.v1)
		}
	}
	if len(v1s) == 0 {
		return
	}
	v1Current := resolveFingerprintAliasesOf(ctx, p, tenantID, v1s, func(s string) string { return s })
	adopted, claimed := 0, map[string]bool{}
	for _, pr := range pairs {
		if held[pr.v2] {
			continue
		}
		from := pr.v1
		if cur, ok := v1Current[pr.v1]; ok {
			from = cur
		}
		if claimed[from] {
			continue
		}
		claimed[from] = true
		moved, err := adopter.AdoptFingerprint(ctx, tenantID, from, pr.v2, pr.raw, vulnerability.IdentityVersion)
		if err != nil {
			p.logger.Warn("failed to re-key a finding to its version-2 identity", "error", err)
			continue
		}
		if moved {
			adopted++
		}
	}
	if adopted > 0 {
		p.logger.Info("re-keyed findings to their version-2 identity", "count", adopted)
	}
}

// applyIdentityToFinding stamps the version-2 identity on a built finding
// whose key is that identity (not when the key was translated to an existing
// finding's), and keeps the sensor's own fingerprint as a sighting key (D1).
func applyIdentityToFinding(f *vulnerability.Finding, identity *vulnerability.IdentityKey, reported *ctis.Finding) {
	if f == nil {
		return
	}
	if identity != nil && f.Fingerprint() == identity.Fingerprint() {
		_ = f.SetIdentity(*identity)
	}
	if identity != nil && reported != nil && reported.Fingerprint != "" && len(reported.Fingerprint) <= 256 {
		f.AddPartialFingerprint(partialSensorFingerprint, reported.Fingerprint)
	}
}

// VersionOneFingerprint is the version-1 key ingest gave f on assetID before
// the version-2 recipes (RFC-043 §6). The golden corpus uses it to build
// version-1 rows and prove they are re-keyed without losing state.
func VersionOneFingerprint(assetID shared.ID, f *ctis.Finding, tool *ctis.Tool) string {
	fp, _ := generateFindingFingerprint(assetID, f, tool)
	return fp
}
