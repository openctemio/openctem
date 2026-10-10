// Package vex holds the organization's VEX statements: what the organization
// states about a vulnerability in a package it uses (not affected, affected,
// fixed, under investigation), for every asset or one asset, and how such a
// statement acts on the findings it covers.
//
// Design: api/docs/rfcs/RFC-070-software-components-inventory.md (sections
// "VEX statements" and "VEX"), architecture doc
// api/docs/architecture/software-components.md.
package vex

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Status is the exploitability status of a statement.
type Status string

// Statuses.
const (
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// IsValid reports whether s is a known status.
func (s Status) IsValid() bool {
	switch s {
	case StatusNotAffected, StatusAffected, StatusFixed, StatusUnderInvestigation:
		return true
	}
	return false
}

// Closes reports whether a statement of this status closes the findings it
// covers (not_affected: false positive; fixed: resolved). affected and
// under_investigation only annotate.
func (s Status) Closes() bool { return s == StatusNotAffected || s == StatusFixed }

// Justifications of a not_affected statement.
var justifications = map[string]bool{
	"component_not_present":                             true,
	"vulnerable_code_not_present":                       true,
	"vulnerable_code_not_in_execute_path":               true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true,
	"inline_mitigations_already_exist":                  true,
}

// IsJustification reports whether j is a known justification.
func IsJustification(j string) bool { return justifications[j] }

// Origins.
const (
	OriginManual   = "manual"
	OriginDocument = "document"
)

// Bounds.
const (
	MaxVulnIDLen     = 128
	MaxVersions      = 64
	MaxVersionLen    = 128
	MaxRangeLen      = 256
	MaxStatementLen  = 2000
	MaxDocumentRef   = 512
	MaxRangeTerms    = 8
	MaxExpiryHorizon = 5 * 365 * 24 * time.Hour
)

// Resolution methods a statement records on a finding it closed.
const (
	ResolutionNotAffected = "vex_not_affected"
	ResolutionFixed       = "vex_fixed"
)

// Errors.
var (
	ErrNotFound = fmt.Errorf("%w: vex statement not found", shared.ErrNotFound)
	ErrConflict = fmt.Errorf("%w: a statement for this vulnerability, package, asset and versions already exists", shared.ErrConflict)
)

func invalid(msg string) error { return fmt.Errorf("%w: %s", shared.ErrValidation, msg) }

// Statement is one VEX statement of a tenant.
type Statement struct {
	ID              shared.ID
	TenantID        shared.ID
	VulnID          string
	ProductID       shared.ID
	Versions        []string
	VersionRange    string
	AssetID         *shared.ID
	Status          Status
	Justification   string
	ImpactStatement string
	ActionStatement string
	Origin          string
	DocumentRef     string
	ExpiresAt       *time.Time
	ExpiredAt       *time.Time
	CreatedBy       *shared.ID
	UpdatedBy       *shared.ID
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

var vulnIDRE = regexp.MustCompile(`^[A-Z0-9][A-Z0-9._:-]{1,127}$`)

// NormalizeVulnID upper-cases and checks a vulnerability id (CVE, GHSA, OSV
// or a scanner rule id).
func NormalizeVulnID(s string) (string, error) {
	v := strings.ToUpper(strings.TrimSpace(s))
	if !vulnIDRE.MatchString(v) {
		return "", invalid("vuln_id must be a vulnerability id such as CVE-2024-3094 or GHSA-xxxx-xxxx-xxxx")
	}
	return v, nil
}

// cleanText trims s, removes control characters other than newline and tab
// and refuses text over max runes.
func cleanText(s string, maxLen int, field string) (string, error) {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	if len([]rune(s)) > maxLen {
		return "", invalid(fmt.Sprintf("%s is longer than %d characters", field, maxLen))
	}
	return s, nil
}

// Normalize checks and cleans the statement's content (everything but ids
// and timestamps) against the rules of the table. now bounds the expiry.
func (s *Statement) Normalize(now time.Time) error {
	var err error
	if s.VulnID, err = NormalizeVulnID(s.VulnID); err != nil {
		return err
	}
	if !s.Status.IsValid() {
		return invalid("status must be not_affected, affected, fixed or under_investigation")
	}
	s.Justification = strings.TrimSpace(s.Justification)
	if s.Justification != "" {
		if !IsJustification(s.Justification) {
			return invalid("unknown justification")
		}
		if s.Status != StatusNotAffected {
			return invalid("a justification is given only with status not_affected")
		}
	}
	if s.ImpactStatement, err = cleanText(s.ImpactStatement, MaxStatementLen, "impact_statement"); err != nil {
		return err
	}
	if s.ActionStatement, err = cleanText(s.ActionStatement, MaxStatementLen, "action_statement"); err != nil {
		return err
	}
	if s.Status == StatusNotAffected && s.Justification == "" && s.ImpactStatement == "" {
		return invalid("a not_affected statement needs a justification or an impact statement")
	}
	if s.DocumentRef, err = cleanText(s.DocumentRef, MaxDocumentRef, "document_ref"); err != nil {
		return err
	}
	if s.Origin != OriginManual && s.Origin != OriginDocument {
		return invalid("unknown origin")
	}
	if s.Versions, err = normalizeVersions(s.Versions); err != nil {
		return err
	}
	s.VersionRange = strings.TrimSpace(s.VersionRange)
	if s.VersionRange != "" {
		if len(s.Versions) > 0 {
			return invalid("give versions or a version_range, not both")
		}
		r, perr := ParseRange(s.VersionRange)
		if perr != nil {
			return perr
		}
		s.VersionRange = r.String()
	}
	if s.ExpiresAt != nil {
		e := s.ExpiresAt.UTC()
		if !e.After(now) {
			return invalid("expires_at must be in the future")
		}
		if e.Sub(now) > MaxExpiryHorizon {
			return invalid("expires_at must be within five years")
		}
		s.ExpiresAt = &e
	}
	return nil
}

func normalizeVersions(in []string) ([]string, error) {
	if len(in) > MaxVersions {
		return nil, invalid(fmt.Sprintf("at most %d versions", MaxVersions))
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if len(v) > MaxVersionLen || strings.ContainsFunc(v, unicode.IsControl) || strings.ContainsAny(v, " ,") {
			return nil, invalid("a version is at most 128 characters without spaces or commas")
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	// Sorted, so the same set always makes the same subject key.
	sort.Strings(out)
	return out, nil
}

// Active reports whether the statement applies at now (not expired).
func (s *Statement) Active(now time.Time) bool {
	return s.ExpiresAt == nil || s.ExpiresAt.After(now)
}

// Covers reports whether the statement covers finding f: same vulnerability
// (any id of the finding), same package, the finding's version is listed or
// in the range (or the statement names no versions), and the finding is on
// the statement's asset (or the statement is for every asset).
func (s *Statement) Covers(f *FindingRef) bool {
	if f.ProductID != s.ProductID {
		return false
	}
	if s.AssetID != nil && *s.AssetID != f.AssetID {
		return false
	}
	if !f.HasVuln(s.VulnID) {
		return false
	}
	switch {
	case len(s.Versions) > 0:
		for _, v := range s.Versions {
			if v == f.Version {
				return true
			}
		}
		return false
	case s.VersionRange != "":
		r, err := ParseRange(s.VersionRange)
		return err == nil && r.Contains(f.Version)
	}
	return true
}

// specificity orders statements that cover the same finding: one asset over
// every asset, then listed versions over a range over every version.
func (s *Statement) specificity() int {
	n := 0
	if s.AssetID != nil {
		n += 4
	}
	switch {
	case len(s.Versions) > 0:
		n += 2
	case s.VersionRange != "":
		n++
	}
	return n
}

// Pick returns the statement that governs f among stmts (nil when none
// covers it): the most specific one, then the most recently updated, then
// the lowest id so the choice is stable.
func Pick(stmts []*Statement, f *FindingRef, now time.Time) *Statement {
	var best *Statement
	for _, s := range stmts {
		if !s.Active(now) || !s.Covers(f) {
			continue
		}
		if best == nil || better(s, best) {
			best = s
		}
	}
	return best
}

func better(a, b *Statement) bool {
	if a.specificity() != b.specificity() {
		return a.specificity() > b.specificity()
	}
	if !a.UpdatedAt.Equal(b.UpdatedAt) {
		return a.UpdatedAt.After(b.UpdatedAt)
	}
	return a.ID.String() < b.ID.String()
}

// Filter selects statements to list.
type Filter struct {
	TenantID  shared.ID
	VulnID    string
	ProductID *shared.ID
	AssetID   *shared.ID
	Status    Status
	// Scope, when set, restricts the list to statements the member may see:
	// asset-bound statements on an in-scope asset, and tenant-wide
	// statements whose package an in-scope asset uses.
	Scope *shared.DataScope
}
