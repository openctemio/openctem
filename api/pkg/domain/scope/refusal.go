package scope

// Structured refusal reasons (RFC-054 §6.5): every target the active-probe
// gate refuses carries a code, the caller's own rule that refused it (never
// another tenant's, never platform-policy detail) and the fixes that would
// let it through. A fix names the permission it needs; the API filters fixes
// for the caller where it knows the caller, and the client shows only what
// the viewer may do.

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Refusal codes.
const (
	RefusalInvalidTarget      = "invalid_target"
	RefusalDenyList           = "deny_list"
	RefusalExcluded           = "excluded"
	RefusalRejected           = "rejected"
	RefusalNeedsReview        = "needs_review"
	RefusalCandidate          = "candidate"
	RefusalDependency         = "dependency"
	RefusalMonitorOnly        = "monitor_only"
	RefusalNoEntry            = "no_entry"
	RefusalEntryPending       = "entry_pending"
	RefusalEntryExpired       = "entry_expired"
	RefusalEntryInactive      = "entry_inactive"
	RefusalTierExceeds        = "tier_exceeds"
	RefusalProofRequired      = "proof_required"
	RefusalOutOfDataScope     = "out_of_data_scope"
	RefusalNotAnAsset         = "not_an_asset"
	RefusalZoneNone           = "zone_none"
	RefusalZoneNoSensor       = "zone_no_sensor"
	RefusalZoneSensorMismatch = "zone_sensor_mismatch"
)

// Fix actions.
const (
	FixAddEntry         = "add_entry"
	FixAllowTemporarily = "allow_temporarily"
	FixRequestAccess    = "request_access"
	FixApproveEntry     = "approve_entry"
	FixRenewEntry       = "renew_entry"
	FixActivateEntry    = "activate_entry"
	FixRemoveExclusion  = "remove_exclusion"
	FixReviewAsset      = "review_asset"
	FixVerifyDomain     = "verify_domain"
	FixUseTenantSensor  = "use_tenant_sensor"
	FixAddZone          = "add_zone"
	FixContactSupport   = "contact_support"
)

// Permissions fixes need (strings, so the domain does not import RBAC).
const (
	permScopeApprove   = "attack_surface:scope:approve"
	permScopeWrite     = "attack_surface:scope:write"
	permExclApprove    = "attack_surface:scope:exclusions:approve"
	permAssetsWrite    = "assets:write"
	permScanZonesWrite = "sensors:zones:write"
)

// Fix is one action that would let a refused target through.
type Fix struct {
	Action     string `json:"action"`
	Pattern    string `json:"pattern,omitempty"`
	TargetType string `json:"target_type,omitempty"`
	Days       int    `json:"days,omitempty"`
	ID         string `json:"id,omitempty"`
	Domain     string `json:"domain,omitempty"`
	// Requires is the permission the action needs ("" = anyone who could scan).
	Requires string `json:"requires,omitempty"`
}

// RuleRef is the caller's own rule that refused a target, or platform policy
// (Kind platform_policy, nothing else).
type RuleRef struct {
	Kind    string `json:"kind"`
	ID      string `json:"id,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}

// Rule kinds.
const (
	RuleExclusion      = "exclusion"
	RuleScopeTarget    = "scope_target"
	RuleTombstone      = "tombstone"
	RuleAsset          = "asset"
	RulePlatformPolicy = "platform_policy"
)

// RefusalMessages are the messages shown with each code.
var RefusalMessages = map[string]string{
	RefusalInvalidTarget:      "Not a valid scan target here (malformed, loopback, link-local, metadata, or a private address outside every scan zone).",
	RefusalDenyList:           "The platform does not allow this target.",
	RefusalExcluded:           "An active scope exclusion covers this target.",
	RefusalRejected:           "Your organization marked this name, or a name above it, as not yours.",
	RefusalNeedsReview:        "This asset's ownership is waiting for review.",
	RefusalCandidate:          "This asset is a discovery candidate; its ownership is not confirmed.",
	RefusalDependency:         "This name runs on third-party infrastructure; only passive and takeover checks apply.",
	RefusalMonitorOnly:        "This asset is watched passively only.",
	RefusalNoEntry:            "No scope entry, seed or verified domain covers this target.",
	RefusalEntryPending:       "The scope entry that covers this target is waiting for approval.",
	RefusalEntryExpired:       "The scope entry that covered this target has expired.",
	RefusalEntryInactive:      "The scope entry that covers this target is deactivated.",
	RefusalTierExceeds:        "The scope entries covering this target do not allow this probe's tier.",
	RefusalProofRequired:      "This probe needs a verified domain of your organization.",
	RefusalOutOfDataScope:     "This asset is outside your data scope.",
	RefusalNotAnAsset:         "You may scan only assets in your data scope.",
	RefusalZoneNone:           "No scan zone covers this private target.",
	RefusalZoneNoSensor:       "The scan zone of this target has no sensors.",
	RefusalZoneSensorMismatch: "The chosen sensor is not in this target's scan zone.",
}

// Refusal is one refused target, as every API refusal and the dry run carry it.
type Refusal struct {
	Target  string   `json:"target"`
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Rule    *RuleRef `json:"rule,omitempty"`
	Fixes   []Fix    `json:"fixes,omitempty"`
}

// NewRefusal builds the refusal for a code, with its message and fixes.
func NewRefusal(target, code string, rule *RuleRef, oneOffDays int) Refusal {
	return Refusal{Target: target, Code: code, Message: RefusalMessages[code], Rule: rule, Fixes: FixesFor(code, target, rule, oneOffDays)}
}

// FixesFor lists the fixes for a refusal of target (oneOffDays: the one-off
// default; 0 = 7).
func FixesFor(code, target string, rule *RuleRef, oneOffDays int) []Fix {
	if oneOffDays <= 0 {
		oneOffDays = DefaultOneOffDays
	}
	host, typ := suggestTarget(target)
	id := ""
	if rule != nil {
		id = rule.ID
	}
	switch code {
	case RefusalNoEntry, RefusalNotAnAsset:
		var out []Fix
		if host != "" {
			out = append(out,
				Fix{Action: FixAllowTemporarily, Pattern: host, TargetType: typ, Days: oneOffDays, Requires: permScopeApprove},
				Fix{Action: FixRequestAccess, Pattern: host, TargetType: typ, Days: oneOffDays, Requires: permScopeWrite})
			if typ == string(TargetTypeDomain) {
				if root := registrable(host); root != "" {
					out = append(out, Fix{Action: FixAddEntry, Pattern: "*." + root, TargetType: typ, Requires: permScopeApprove})
				}
			} else {
				out = append(out, Fix{Action: FixAddEntry, Pattern: host, TargetType: typ, Requires: permScopeApprove})
			}
		}
		return out
	case RefusalEntryPending:
		return []Fix{{Action: FixApproveEntry, ID: id, Requires: permScopeApprove}}
	case RefusalEntryExpired:
		return []Fix{
			{Action: FixRenewEntry, ID: id, Days: oneOffDays, Requires: permScopeApprove},
			{Action: FixRequestAccess, Pattern: host, TargetType: typ, Days: oneOffDays, Requires: permScopeWrite},
		}
	case RefusalEntryInactive:
		return []Fix{{Action: FixActivateEntry, ID: id, Requires: permScopeApprove}}
	case RefusalExcluded:
		return []Fix{{Action: FixRemoveExclusion, ID: id, Requires: permExclApprove}}
	case RefusalRejected, RefusalNeedsReview, RefusalCandidate, RefusalDependency, RefusalMonitorOnly:
		return []Fix{{Action: FixReviewAsset, ID: id, Requires: permAssetsWrite}}
	case RefusalProofRequired:
		out := []Fix{{Action: FixUseTenantSensor}}
		if typ == string(TargetTypeDomain) {
			if root := registrable(host); root != "" {
				out = append([]Fix{{Action: FixVerifyDomain, Domain: root, Requires: permScopeApprove}}, out...)
			}
		}
		return out
	case RefusalZoneNone, RefusalZoneNoSensor, RefusalZoneSensorMismatch:
		return []Fix{{Action: FixAddZone, Requires: permScanZonesWrite}}
	case RefusalDenyList:
		return []Fix{{Action: FixContactSupport}}
	}
	return nil
}

// FilterFixes keeps the fixes the caller may take (has reports whether the
// caller holds a permission).
func FilterFixes(fixes []Fix, has func(perm string) bool) []Fix {
	out := fixes[:0:0]
	for _, f := range fixes {
		if f.Requires == "" || has(f.Requires) {
			out = append(out, f)
		}
	}
	// An approver allowing it needs no request.
	allow := false
	for _, f := range out {
		if f.Action == FixAllowTemporarily {
			allow = true
		}
	}
	if !allow {
		return out
	}
	kept := out[:0]
	for _, f := range out {
		if f.Action != FixRequestAccess {
			kept = append(kept, f)
		}
	}
	return kept
}

// suggestTarget is the host (or address) a fix would put in scope and its
// scope target type ("" when the target names neither).
func suggestTarget(target string) (string, string) {
	v := strings.TrimSpace(target)
	if h := urlHost(v); h != "" {
		v = h
	}
	if set, ok := parseIPSet(strings.Trim(v, "[]")); ok {
		if set.lo == set.hi {
			return set.lo.String(), string(TargetTypeIPAddress)
		}
		return v, string(TargetTypeCIDR)
	}
	_, host := splitDomainWildcard(v)
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if host == "" || !strings.Contains(host, ".") {
		return "", ""
	}
	return host, string(TargetTypeDomain)
}

// registrable is the registrable domain of host ("" when none).
func registrable(host string) string {
	r, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return r
}
