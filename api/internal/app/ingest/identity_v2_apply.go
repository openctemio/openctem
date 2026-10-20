package ingest

import (
	"context"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// applyIdentityV2Of computes the version-2 identity of every item and hands
// it to set, with the former keys a finding may still be stored under within
// version 2 (a SAST finding anchored on its line before its reports carried
// the code; a secret keyed on its mask). Items without one keep their
// version-1 key.
func applyIdentityV2Of[T any](p *FindingProcessor, tenantID shared.ID, items []T,
	get func(*T) (shared.ID, *ctis.Finding), set func(item *T, k vulnerability.IdentityKey, formers []string),
) {
	findings := make([]ctis.Finding, len(items))
	assets := make([]shared.ID, len(items))
	for i := range items {
		a, f := get(&items[i])
		assets[i], findings[i] = a, *f
	}
	occ := sastOccurrences(findings, func(i int) shared.ID { return assets[i] })
	for i := range items {
		f := &findings[i]
		if identityKind(f) == vulnerability.IdentityKindSecret {
			if k, formers, ok := p.secretIdentity(tenantID, assets[i], f); ok {
				set(&items[i], k, formers)
			}
			continue
		}
		if k, ok := identityV2(assets[i], f, "", occ[i]); ok {
			var formers []string
			if former := formerKey(assets[i], f, k); former != "" {
				formers = append(formers, former)
			}
			set(&items[i], k, formers)
		}
	}
}

// secretIdentity keys a secret on a keyed hash of the raw value: the
// producer's (secretHMAC/v1; the raw value never leaves the producer),
// re-keyed per tenant with a server secret, else the server's own when the
// report carried the raw value (keyRawSecrets). Neither is ever logged. Without one, the mask is
// only part of a key that also names the rule and secret type, and the line
// when the mask shows too little of the secret (SecretMaskIdentity), never
// the identity on its own. formers are the keys an earlier ingest gave the same
// secret: the mask-anchored key and the mask-only key of older versions.
func (p *FindingProcessor) secretIdentity(tenantID, assetID shared.ID, f *ctis.Finding) (vulnerability.IdentityKey, []string, bool) {
	asset := assetID.String()
	path := locationPath(f)
	maskedHMAC, rule, stype, line := "", f.RuleID, "", 0
	if f.Secret != nil {
		stype = f.Secret.SecretType
		if f.Secret.MaskedValue != "" {
			maskedHMAC = p.secretFingerprinter.Fingerprint(tenantID, f.Secret.MaskedValue)
		}
	}
	if f.Location != nil && f.Secret != nil && !vulnerability.SecretMaskDistinctive(f.Secret.MaskedValue) {
		line = f.Location.StartLine
	}
	var formers []string
	maskKey, maskOK := vulnerability.SecretMaskIdentity(asset, maskedHMAC, path, rule, stype, line)
	secretHMAC := p.rawSecretHMAC(tenantID, f)
	if k, ok := vulnerability.SecretIdentity(asset, secretHMAC, path); ok {
		if maskOK {
			formers = append(formers, maskKey.Fingerprint())
		}
		if old, ok := vulnerability.SecretIdentity(asset, maskedHMAC, path); ok {
			formers = append(formers, old.Fingerprint())
		}
		return k, formers, true
	}
	if !maskOK {
		return vulnerability.IdentityKey{}, nil, false
	}
	if old, ok := vulnerability.SecretIdentity(asset, maskedHMAC, path); ok {
		formers = append(formers, old.Fingerprint())
	}
	return maskKey, formers, true
}

// fingerprintAdopter is implemented by the postgres finding repository.
// Optional: a repository without it (tests, mocks) re-keys nothing.
type fingerprintAdopter interface {
	CheckFingerprintsExist(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]bool, error)
	AdoptFingerprint(ctx context.Context, tenantID shared.ID, from, to string, identityKey []byte, version int, g vulnerability.AdoptGuard) (bool, error)
}

// adoptKeys is what one item offers to a re-key: the key a stored finding
// may still carry, the item's identity, and the guard naming its issue.
type adoptKeys struct {
	from     string
	identity *vulnerability.IdentityKey
	guard    vulnerability.AdoptGuard
}

// adoptV1KeysOf re-keys, to its version-2 key, a finding that is still
// stored under the version-1 key an item of this batch produces, when no
// finding has the version-2 key yet. Its triage, tickets and history stay;
// the version-1 key becomes an alias (RFC-043 §6, "re-keyed on the next
// sighting"). A version-1 finding is taken over by the first item only.
func adoptV1KeysOf[T any](ctx context.Context, p *FindingProcessor, tenantID shared.ID, items []T,
	keys func(T) adoptKeys,
) {
	adopter, ok := p.repo.(fingerprintAdopter)
	if !ok {
		return
	}
	adoptKeysOf(ctx, p, tenantID, items, keys, adopter, adopter.AdoptFingerprint, true)
}

// formerAdopter re-keys within one recipe version (the postgres finding
// repository). Optional, like fingerprintAdopter.
type formerAdopter interface {
	fingerprintAdopter
	AdoptFormerFingerprint(ctx context.Context, tenantID shared.ID, from, to string, identityKey []byte, version int, g vulnerability.AdoptGuard) (bool, error)
}

// adoptFormerKeysOf re-keys a finding still stored under the former
// version-2 key an item names (sastFormerLineKey) to the item's key, with the
// same rules as adoptV1KeysOf.
func adoptFormerKeysOf[T any](ctx context.Context, p *FindingProcessor, tenantID shared.ID, items []T,
	keys func(T) adoptKeys,
) {
	adopter, ok := p.repo.(formerAdopter)
	if !ok {
		return
	}
	// A former key is adopted only from the finding still stored under it,
	// never through an alias: a key another finding already gave up must not
	// pull that finding over (two secrets with one mask).
	adoptKeysOf(ctx, p, tenantID, items, keys, adopter, adopter.AdoptFormerFingerprint, false)
}

func adoptKeysOf[T any](ctx context.Context, p *FindingProcessor, tenantID shared.ID, items []T,
	keys func(T) adoptKeys, adopter fingerprintAdopter,
	adopt func(ctx context.Context, tenantID shared.ID, from, to string, identityKey []byte, version int, g vulnerability.AdoptGuard) (bool, error),
	followAliases bool,
) {
	type pair struct {
		v1, v2 string
		raw    []byte
		guard  vulnerability.AdoptGuard
	}
	pairs := make([]pair, 0, len(items))
	v2s := make([]string, 0, len(items))
	for _, it := range items {
		ak := keys(it)
		v1, k := ak.from, ak.identity
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
		pairs = append(pairs, pair{v1: v1, v2: v2, raw: raw, guard: ak.guard})
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
	v1Current := map[string]string{}
	if followAliases {
		v1Current = resolveFingerprintAliasesOf(ctx, p, tenantID, v1s, func(s string) string { return s })
	}
	// Only a version-1 key a live finding holds can be re-keyed. Checking
	// them in one query keeps a batch of new findings (nothing to adopt) from
	// issuing one no-op UPDATE per finding.
	froms := make([]string, 0, len(v1s))
	for _, v1 := range v1s {
		if cur, ok := v1Current[v1]; ok {
			froms = append(froms, cur)
		} else {
			froms = append(froms, v1)
		}
	}
	live, err := adopter.CheckFingerprintsExist(ctx, tenantID, froms)
	if err != nil {
		p.logger.Warn("failed to check version-1 finding keys", "error", err)
		return
	}
	adopted, claimed := 0, map[string]bool{}
	for _, pr := range pairs {
		if held[pr.v2] {
			continue
		}
		from := pr.v1
		if cur, ok := v1Current[pr.v1]; ok {
			from = cur
		}
		if claimed[from] || !live[from] {
			continue
		}
		claimed[from] = true
		moved, err := adopt(ctx, tenantID, from, pr.v2, pr.raw, vulnerability.IdentityVersion, pr.guard)
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

// clientKeyAdopter re-keys a version-1 finding stored under a key its report
// chose (the postgres finding repository). Optional, like fingerprintAdopter.
type clientKeyAdopter interface {
	fingerprintAdopter
	AdoptClientKeyedFingerprint(ctx context.Context, tenantID shared.ID, from, to string, g vulnerability.AdoptGuard) (bool, error)
}

// adoptLegacyClientKeysOf re-keys a finding still stored under the key the
// old ingest built from the report's own fingerprint (legacyClientFingerprint)
// to the item's server key: its version-2 key when a recipe applies, else its
// server version-1 key. The key alone never decides: the stored finding must
// be on the same asset with the same rule, tool and location (a strict
// guard), so a report that copies another finding's fingerprint cannot move
// that finding's triage onto a different issue. Aliases are not followed.
func adoptLegacyClientKeysOf[T any](ctx context.Context, p *FindingProcessor, tenantID shared.ID, items []T,
	keys func(T) (legacy, v1 string, identity *vulnerability.IdentityKey, guard vulnerability.AdoptGuard),
) {
	adopter, ok := p.repo.(clientKeyAdopter)
	if !ok {
		return
	}
	strict := func(it T) adoptKeys {
		legacy, _, identity, g := keys(it)
		g.Strict = true
		return adoptKeys{from: legacy, identity: identity, guard: g}
	}
	// Items with a version-2 identity: the same path as a version-1 key.
	adoptKeysOf(ctx, p, tenantID, items, strict, adopter, adopter.AdoptFingerprint, false)

	// Items that keep a version-1 key: legacy -> server version-1 key.
	type pair struct {
		from, to string
		guard    vulnerability.AdoptGuard
	}
	pairs := make([]pair, 0, len(items))
	froms := make([]string, 0, len(items))
	for _, it := range items {
		legacy, v1, identity, g := keys(it)
		if identity != nil || legacy == "" || v1 == "" || legacy == v1 {
			continue
		}
		pairs = append(pairs, pair{from: legacy, to: v1, guard: g})
		froms = append(froms, legacy)
	}
	if len(pairs) == 0 {
		return
	}
	live, err := adopter.CheckFingerprintsExist(ctx, tenantID, froms)
	if err != nil {
		p.logger.Warn("failed to check legacy finding keys", "error", err)
		return
	}
	claimed := map[string]bool{}
	for _, pr := range pairs {
		if claimed[pr.from] || !live[pr.from] {
			continue
		}
		claimed[pr.from] = true
		if _, err := adopter.AdoptClientKeyedFingerprint(ctx, tenantID, pr.from, pr.to, pr.guard); err != nil {
			p.logger.Warn("failed to re-key a finding from its report-chosen key", "error", err)
		}
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

// rawSecretHMAC is the keyed hash of a secret's raw value: the producer's
// (secretHMAC/v1) re-keyed per tenant with the server secret, else the
// server's own when the report carried the raw value (keyRawSecrets). It is
// the only thing a secret's identity and rotation group may be derived from:
// a mask ("REDACTED", "AKIA********") is shared by unrelated secrets. Empty
// when the report carried neither.
func (p *FindingProcessor) rawSecretHMAC(tenantID shared.ID, f *ctis.Finding) string {
	if f == nil {
		return ""
	}
	if v := f.PartialFingerprints[partialSecretHMAC]; v != "" {
		if h := p.secretFingerprinter.ProducerFingerprint(tenantID, v); h != "" {
			return h
		}
	}
	return f.PartialFingerprints[partialServerSecretHMAC]
}
