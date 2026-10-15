package cirun

// Per-field layering of gate policies
// (docs/rfcs/RFC-095-ci-per-repository-settings.md): a business unit or
// repository policy sets only the fields it lists and inherits the rest; an
// organization or business unit policy can lock fields, so that no layer
// below it can loosen them; a repository policy can expire.

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Gate policy fields, in display order.
const (
	FieldMode            = "mode"
	FieldFailOnSeverity  = "fail_on_severity"
	FieldNewFindingsOnly = "new_findings_only"
	FieldFailOnKEV       = "fail_on_kev"
	FieldEPSSThreshold   = "epss_threshold"
	FieldFixableOnly     = "fixable_only"
	FieldModes           = "modes"
	FieldAllowRepoPolicy = "allow_repo_policy"
	// FieldBaselineOnFirstRun records the gate baseline on a repository's
	// first verified default-branch run.
	FieldBaselineOnFirstRun = "baseline_on_first_run"
	// FieldBaselineGraceDays ends the baseline's grace: after it, baseline
	// findings block again.
	FieldBaselineGraceDays = "baseline_grace_days"
	// FieldBaselineSecretsBlock: secrets in the baseline still block
	// default-branch runs.
	FieldBaselineSecretsBlock = "baseline_secrets_block"
)

// PolicyFields are every field a layer can set or lock.
var PolicyFields = []string{FieldMode, FieldFailOnSeverity, FieldNewFindingsOnly, FieldFailOnKEV,
	FieldEPSSThreshold, FieldFixableOnly, FieldModes, FieldAllowRepoPolicy, FieldBaselineOnFirstRun,
	FieldBaselineGraceDays, FieldBaselineSecretsBlock}

// Bounds of a repository override.
const (
	MaxPolicyOverrideTTL = 365 * 24 * time.Hour
	MinPolicyReason      = 10
	MaxPolicyReason      = 500
)

// ErrFieldLocked: a change would loosen a field that a layer above locks.
var ErrFieldLocked = fmt.Errorf("%w: field locked", shared.ErrConflict)

// IsPolicyField reports whether f names a gate policy field.
func IsPolicyField(f string) bool { return slices.Contains(PolicyFields, f) }

// NormalizeFields checks a field list and returns it deduplicated in display
// order. Every error wraps shared.ErrValidation.
func NormalizeFields(in []string, what string) ([]string, error) {
	seen := map[string]bool{}
	for _, f := range in {
		if !IsPolicyField(f) {
			return nil, fmt.Errorf("%w: %s: unknown field %q", shared.ErrValidation, what, f)
		}
		seen[f] = true
	}
	out := make([]string, 0, len(seen))
	for _, f := range PolicyFields {
		if seen[f] {
			out = append(out, f)
		}
	}
	return out, nil
}

// Sets reports whether the policy sets field f.
func (p GatePolicy) Sets(f string) bool { return slices.Contains(p.Fields, f) }

// Locks reports whether the policy locks field f.
func (p GatePolicy) Locks(f string) bool { return slices.Contains(p.LockedFields, f) }

// ActiveAt reports whether the policy applies at t: enabled and not expired.
func (p GatePolicy) ActiveAt(t time.Time) bool {
	return p.Enabled && (p.ExpiresAt == nil || t.Before(*p.ExpiresAt))
}

// ValidateLayer checks the layering values of a policy: field lists, locks
// only above repositories, reason and expiry only on repositories.
func (p *GatePolicy) ValidateLayer(now time.Time) error {
	invalid := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", shared.ErrValidation, fmt.Sprintf(format, a...))
	}
	var err error
	if p.Fields, err = NormalizeFields(p.Fields, "fields"); err != nil {
		return err
	}
	if p.LockedFields, err = NormalizeFields(p.LockedFields, "locked_fields"); err != nil {
		return err
	}
	if p.ScopeType == ScopeTenant && len(p.Fields) != len(PolicyFields) {
		return invalid("the organization policy sets every field")
	}
	if p.ScopeType == ScopeRepository && len(p.LockedFields) > 0 {
		return invalid("a repository policy cannot lock fields")
	}
	p.Reason = strings.TrimSpace(p.Reason)
	if len([]rune(p.Reason)) > MaxPolicyReason || strings.ContainsFunc(p.Reason, unicode.IsControl) {
		return invalid("reason must be at most %d characters, without control characters", MaxPolicyReason)
	}
	if p.ExpiresAt != nil {
		if p.ScopeType != ScopeRepository {
			return invalid("only a repository policy can expire")
		}
		if !p.ExpiresAt.After(now) || p.ExpiresAt.Sub(now) > MaxPolicyOverrideTTL+time.Minute {
			return invalid("expires_at must be in the future and within 365 days")
		}
	}
	return nil
}

// copyField sets field f of dst from src.
func copyField(dst *GatePolicy, src GatePolicy, f string) {
	switch f {
	case FieldMode:
		dst.Mode = src.Mode
	case FieldFailOnSeverity:
		dst.FailOnSeverity = src.FailOnSeverity
	case FieldNewFindingsOnly:
		dst.NewFindingsOnly = src.NewFindingsOnly
	case FieldFailOnKEV:
		dst.FailOnKEV = src.FailOnKEV
	case FieldEPSSThreshold:
		if src.EPSSThreshold == nil {
			dst.EPSSThreshold = nil
		} else {
			v := *src.EPSSThreshold
			dst.EPSSThreshold = &v
		}
	case FieldFixableOnly:
		dst.FixableOnly = src.FixableOnly
	case FieldModes:
		dst.Modes = src.Modes
	case FieldAllowRepoPolicy:
		dst.AllowRepoPolicy = src.AllowRepoPolicy
	case FieldBaselineOnFirstRun:
		dst.BaselineOnFirstRun = src.BaselineOnFirstRun
	case FieldBaselineGraceDays:
		if src.BaselineGraceDays == nil {
			dst.BaselineGraceDays = nil
		} else {
			v := *src.BaselineGraceDays
			dst.BaselineGraceDays = &v
		}
	case FieldBaselineSecretsBlock:
		dst.BaselineSecretsBlock = src.BaselineSecretsBlock
	}
}

// FieldLoosens reports whether taking field f from next instead of base lets
// more findings pass.
func FieldLoosens(base, next GatePolicy, f string) bool {
	after := base
	copyField(&after, next, f)
	return len(Loosens(base, after)) > 0
}

// FieldValue is field f of p, for display and audit.
func FieldValue(p GatePolicy, f string) any {
	switch f {
	case FieldMode:
		return p.Mode
	case FieldFailOnSeverity:
		return p.FailOnSeverity
	case FieldNewFindingsOnly:
		return p.NewFindingsOnly
	case FieldFailOnKEV:
		return p.FailOnKEV
	case FieldEPSSThreshold:
		return p.EPSSThreshold
	case FieldFixableOnly:
		return p.FixableOnly
	case FieldModes:
		return p.Modes
	case FieldAllowRepoPolicy:
		return p.AllowRepoPolicy
	case FieldBaselineOnFirstRun:
		return p.BaselineOnFirstRun
	case FieldBaselineGraceDays:
		return p.BaselineGraceDays
	case FieldBaselineSecretsBlock:
		return p.BaselineSecretsBlock
	}
	return nil
}

// FieldResolution says where one field's effective value comes from.
type FieldResolution struct {
	Field string
	// Source is the layer of the value in force: default, tenant,
	// business_unit or repository.
	Source   string
	PolicyID *shared.ID
	// LockedBy is the layer that locks the field ("" when unlocked).
	LockedBy string
	// Ignored: the repository (or a business unit) sets a looser value that
	// a lock above drops.
	Ignored bool
}

// Resolution is the effective policy of one repository and its provenance.
type Resolution struct {
	Policy GatePolicy
	// Source is the most specific layer that contributes a field.
	Source string
	Fields []FieldResolution
	// Inherited is what applies without the repository's own policy.
	Inherited GatePolicy
	// Repository is the repository's own policy, whether or not it applies
	// (disabled or expired); nil when there is none.
	Repository *GatePolicy
	// RepositoryExpired: the repository policy has expired and is ignored.
	RepositoryExpired bool
}

// Field returns the resolution of field f.
func (r Resolution) Field(f string) FieldResolution {
	for _, fr := range r.Fields {
		if fr.Field == f {
			return fr
		}
	}
	return FieldResolution{Field: f, Source: ScopeDefault}
}

// Locked reports whether a layer above the repository locks field f.
func (r Resolution) Locked(f string) bool { return r.Field(f).LockedBy != "" }

var sourceRank = map[string]int{ScopeDefault: 0, ScopeTenant: 1, ScopeBusinessUnit: 2, ScopeRepository: 3}

// Resolve builds the effective policy of a repository from the policies
// that may apply to it (any scope, enabled or not): the built-in default,
// then the organization's fields, then per field the strictest of the
// business units that set it, then the repository's own fields while it is
// active at now. A business unit or repository value looser than the value
// above it is dropped when a layer above locks the field.
func Resolve(ps []GatePolicy, now time.Time) Resolution {
	eff := DefaultGatePolicy()
	fields := make(map[string]*FieldResolution, len(PolicyFields))
	for _, f := range PolicyFields {
		fields[f] = &FieldResolution{Field: f, Source: ScopeDefault}
	}
	var tenant, repo *GatePolicy
	var units []GatePolicy
	for i := range ps {
		switch ps[i].ScopeType {
		case ScopeTenant:
			tenant = &ps[i]
		case ScopeBusinessUnit:
			if ps[i].Enabled {
				units = append(units, ps[i])
			}
		case ScopeRepository:
			repo = &ps[i]
		}
	}
	lockedBy := map[string]string{}
	if tenant != nil && tenant.Enabled {
		for _, f := range tenant.Fields {
			copyField(&eff, *tenant, f)
			id := tenant.ID
			fields[f].Source, fields[f].PolicyID = ScopeTenant, &id
		}
		for _, f := range tenant.LockedFields {
			lockedBy[f] = ScopeTenant
		}
	}
	for _, f := range PolicyFields {
		var setting []GatePolicy
		for _, u := range units {
			if u.Sets(f) {
				setting = append(setting, u)
			}
		}
		if len(setting) == 0 {
			continue
		}
		s := Strictest(setting)
		if lockedBy[f] != "" && FieldLoosens(eff, s, f) {
			fields[f].Ignored = true
			continue
		}
		copyField(&eff, s, f)
		fields[f].Source = ScopeBusinessUnit
		fields[f].PolicyID = nil
		if len(setting) == 1 {
			id := setting[0].ID
			fields[f].PolicyID = &id
		}
	}
	for _, u := range units {
		for _, f := range u.LockedFields {
			if lockedBy[f] == "" {
				lockedBy[f] = ScopeBusinessUnit
			}
		}
	}
	for f, by := range lockedBy {
		fields[f].LockedBy = by
	}
	out := Resolution{Inherited: eff}
	if repo != nil {
		rp := *repo
		out.Repository = &rp
		out.RepositoryExpired = repo.Enabled && !repo.ActiveAt(now)
		if repo.ActiveAt(now) {
			for _, f := range repo.Fields {
				if lockedBy[f] != "" && FieldLoosens(eff, *repo, f) {
					fields[f].Ignored = true
					continue
				}
				copyField(&eff, *repo, f)
				id := repo.ID
				fields[f].Source, fields[f].PolicyID, fields[f].Ignored = ScopeRepository, &id, false
			}
		}
	}
	out.Source = ScopeDefault
	for _, f := range PolicyFields {
		out.Fields = append(out.Fields, *fields[f])
		if sourceRank[fields[f].Source] > sourceRank[out.Source] {
			out.Source = fields[f].Source
		}
	}
	eff.Enabled = true
	eff.ScopeType = out.Source
	out.Policy = eff
	return out
}

// ApplyLayer is what applies to a policy's scope with the policy on top of
// what it inherits: its fields over inherited while it is active at now.
// Fields a lock above protects keep the inherited value when the policy's
// value is looser.
func ApplyLayer(inherited GatePolicy, locked map[string]bool, p GatePolicy, now time.Time) GatePolicy {
	out := inherited
	if !p.ActiveAt(now) {
		return out
	}
	for _, f := range p.Fields {
		if locked[f] && FieldLoosens(inherited, p, f) {
			continue
		}
		copyField(&out, p, f)
	}
	return out
}

// LockedLoosens lists the fields of p that loosen a field a lock above
// protects (empty when none).
func LockedLoosens(inherited GatePolicy, locked map[string]bool, p GatePolicy) []string {
	var out []string
	for _, f := range p.Fields {
		if locked[f] && FieldLoosens(inherited, p, f) {
			out = append(out, f)
		}
	}
	return out
}
