package permission

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
	"strings"
)

// Risk is how much harm a role can do in the wrong hands. The console shows
// it next to every role instead of a bare permission count.
type Risk string

const (
	// RiskLow: reads inside the holder's data scope.
	RiskLow Risk = "low"
	// RiskMedium: changes findings, assets or scans, runs scans, or approves.
	RiskMedium Risk = "medium"
	// RiskHigh: sees every asset, reads secrets, or manages people, roles,
	// keys or settings (a privileged role).
	RiskHigh Risk = "high"
	// RiskCritical: the owner and administrator roles, which pass every
	// permission check.
	RiskCritical Risk = "critical"
)

// Reason codes explain a role's risk. They are stable identifiers: the
// console translates them.
const (
	ReasonAdmin        = "admin"
	ReasonFullData     = "full_data"
	ReasonManagePeople = "manage_people"
	ReasonSecrets      = "secrets"
	ReasonAPIKeys      = "api_keys"
	ReasonSettings     = "settings"
	ReasonApprove      = "approve"
	ReasonRunScans     = "run_scans"
	ReasonDelete       = "delete"
)

// Access levels of an area in a Summary.
const (
	AccessView   = "view"
	AccessChange = "change"
)

// AreaAccess is what a role does in one product area (the first segment of
// a permission id: findings, scans, assets, team, ...).
type AreaAccess struct {
	Area  string `json:"area"`
	Level string `json:"level"`
}

// Summary describes a role in words a person can check: its risk, why, and
// what it does per area.
type Summary struct {
	Risk    Risk         `json:"risk"`
	Reasons []string     `json:"reasons"`
	Areas   []AreaAccess `json:"areas"`
}

var (
	peoplePerms   = []Permission{MembersInvite, MembersWrite, GroupsWrite, GroupsMembers, GroupsAssets, RolesWrite, RolesDelete, RolesAssign}
	secretPerms   = []Permission{SecretStoreRead, SecretStoreWrite, CredentialsReveal, EvidenceReveal}
	apiKeyPerms   = []Permission{APIKeysWrite}
	settingsPerms = []Permission{SettingsWrite}
	approvePerms  = []Permission{FindingsApprove, SuppressionsApprove, ScopeApprove, ScopeExclusionsApprove, ScansApprove}
	runScanPerms  = []Permission{ScansExecute}
)

// Summarize describes a permission set. adminBypass is true for the system
// owner and admin roles, whose permission list is informative only.
func Summarize(perms []string, fullData, adminBypass bool) Summary {
	has := func(set []Permission) bool {
		for _, p := range set {
			if slices.Contains(perms, string(p)) {
				return true
			}
		}
		return false
	}
	s := Summary{Reasons: []string{}, Areas: []AreaAccess{}}
	add := func(cond bool, reason string) {
		if cond {
			s.Reasons = append(s.Reasons, reason)
		}
	}
	add(adminBypass, ReasonAdmin)
	add(fullData, ReasonFullData)
	add(has(peoplePerms), ReasonManagePeople)
	add(has(secretPerms), ReasonSecrets)
	add(has(apiKeyPerms), ReasonAPIKeys)
	add(has(settingsPerms), ReasonSettings)
	add(has(approvePerms), ReasonApprove)
	add(has(runScanPerms), ReasonRunScans)

	writes, deletes := false, false
	levels := map[string]string{}
	for _, p := range perms {
		area, _, _ := strings.Cut(p, ":")
		if area == "" {
			continue
		}
		readOnly := strings.HasSuffix(p, ":read")
		if strings.HasSuffix(p, ":delete") {
			deletes = true
		}
		if !readOnly {
			writes = true
			levels[area] = AccessChange
		} else if levels[area] == "" {
			levels[area] = AccessView
		}
	}
	add(deletes, ReasonDelete)
	for area, level := range levels {
		s.Areas = append(s.Areas, AreaAccess{Area: area, Level: level})
	}
	sort.Slice(s.Areas, func(i, j int) bool {
		if s.Areas[i].Level != s.Areas[j].Level {
			return s.Areas[i].Level == AccessChange
		}
		return s.Areas[i].Area < s.Areas[j].Area
	})

	switch {
	case adminBypass:
		s.Risk = RiskCritical
	case fullData || IsPrivilegedRole(perms, false) || has(secretPerms):
		s.Risk = RiskHigh
	case writes:
		s.Risk = RiskMedium
	default:
		s.Risk = RiskLow
	}
	return s
}

// TemplateDigest is a short, stable digest of a template's grants (its
// sorted permissions and full data access). TestRoleTemplates_VersionPinned
// pins it with the template's version.
func TemplateDigest(t RoleTemplate) string {
	ps := ToStrings(t.Permissions)
	sort.Strings(ps)
	h := sha256.New()
	for _, p := range ps {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	if t.HasFullDataAccess {
		h.Write([]byte("full_data"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// TemplateDiff is what a template changed since a role took it: the
// permissions the current version adds and those it no longer has.
type TemplateDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// Empty reports whether the template's permissions did not change.
func (d TemplateDiff) Empty() bool { return len(d.Added) == 0 && len(d.Removed) == 0 }

// DiffTemplate compares the permissions a role took from a template (taken)
// with the template's current permissions.
func DiffTemplate(taken []string, current RoleTemplate) TemplateDiff {
	cur := ToStrings(current.Permissions)
	d := TemplateDiff{Added: []string{}, Removed: []string{}}
	for _, p := range cur {
		if !slices.Contains(taken, p) {
			d.Added = append(d.Added, p)
		}
	}
	for _, p := range taken {
		if !slices.Contains(cur, p) {
			d.Removed = append(d.Removed, p)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	return d
}

// ApplyTemplateDiff returns a role's permissions after taking a template
// update: the role's own edits are kept, the template's additions are added
// and its removals removed.
func ApplyTemplateDiff(rolePerms []string, d TemplateDiff) []string {
	out := make([]string, 0, len(rolePerms)+len(d.Added))
	for _, p := range rolePerms {
		if !slices.Contains(d.Removed, p) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, p := range d.Added {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}
