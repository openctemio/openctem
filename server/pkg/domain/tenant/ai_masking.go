package tenant

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/aimask"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AIMaskClass is one class of values the AI context masker can leave
// readable in internal data. Secrets are not a class here: they are always
// masked. Design: docs/architecture/ai-context-masking.md.
type AIMaskClass string

const (
	AIMaskHosts     AIMaskClass = "hosts"
	AIMaskIPs       AIMaskClass = "ips"
	AIMaskEmails    AIMaskClass = "emails"
	AIMaskUsers     AIMaskClass = "users"
	AIMaskURLParams AIMaskClass = "url_params"
	AIMaskOrgs      AIMaskClass = "orgs"
	AIMaskTickets   AIMaskClass = "tickets"
)

// AIMaskClasses lists every configurable class, in display order.
var AIMaskClasses = []AIMaskClass{AIMaskHosts, AIMaskIPs, AIMaskEmails, AIMaskUsers, AIMaskURLParams, AIMaskOrgs, AIMaskTickets}

// Valid reports a known class.
func (c AIMaskClass) Valid() bool {
	for _, k := range AIMaskClasses {
		if k == c {
			return true
		}
	}
	return false
}

// AIMaskingPolicy is the organization's masking policy for internal AI data.
// The stored form lists the classes turned OFF, so a class added later is on
// by default. Restricted data is always masked in full, whatever this says.
type AIMaskingPolicy struct {
	Off                 []AIMaskClass `json:"off,omitempty"`
	MaskSubdomainLabels bool          `json:"mask_subdomain_labels,omitempty"`
	Terms               []string      `json:"terms,omitempty"`
	UpdatedAt           *time.Time    `json:"updated_at,omitempty"`
	UpdatedBy           string        `json:"updated_by,omitempty"`
}

// Masked reports whether a class is masked in internal data.
func (p AIMaskingPolicy) Masked(c AIMaskClass) bool {
	for _, o := range p.Off {
		if o == c {
			return false
		}
	}
	return true
}

// Normalize validates the policy and returns it with the off list sorted
// and de-duplicated and the terms trimmed and de-duplicated (case-folded).
func (p AIMaskingPolicy) Normalize() (AIMaskingPolicy, error) {
	out := AIMaskingPolicy{MaskSubdomainLabels: p.MaskSubdomainLabels, UpdatedAt: p.UpdatedAt, UpdatedBy: p.UpdatedBy}
	seen := map[AIMaskClass]bool{}
	for _, c := range p.Off {
		if !c.Valid() {
			return AIMaskingPolicy{}, fmt.Errorf("%w: unknown masking class", shared.ErrValidation)
		}
		if !seen[c] {
			seen[c] = true
			out.Off = append(out.Off, c)
		}
	}
	sort.Slice(out.Off, func(i, j int) bool { return out.Off[i] < out.Off[j] })
	if len(p.Terms) > aimask.MaxTerms {
		return AIMaskingPolicy{}, fmt.Errorf("%w: at most %d masking terms", shared.ErrValidation, aimask.MaxTerms)
	}
	terms := map[string]bool{}
	for _, t := range p.Terms {
		t = strings.TrimSpace(t)
		n := utf8.RuneCountInString(t)
		if n < aimask.MinTermLen || len(t) > aimask.MaxTermLen || !utf8.ValidString(t) {
			return AIMaskingPolicy{}, fmt.Errorf("%w: a masking term is %d to %d characters", shared.ErrValidation, aimask.MinTermLen, aimask.MaxTermLen)
		}
		for _, r := range t {
			if unicode.IsControl(r) {
				return AIMaskingPolicy{}, fmt.Errorf("%w: a masking term has a control character", shared.ErrValidation)
			}
		}
		k := strings.ToLower(t)
		if !terms[k] {
			terms[k] = true
			out.Terms = append(out.Terms, t)
		}
	}
	return out, nil
}

// Loosens reports whether next masks less than p: a class turned off, the
// label switch turned off, or a term removed. Such a change needs a fresh
// sign-in and is audited at high severity.
func (p AIMaskingPolicy) Loosens(next AIMaskingPolicy) bool {
	for _, c := range AIMaskClasses {
		if p.Masked(c) && !next.Masked(c) {
			return true
		}
	}
	if p.MaskSubdomainLabels && !next.MaskSubdomainLabels {
		return true
	}
	keep := map[string]bool{}
	for _, t := range next.Terms {
		keep[strings.ToLower(t)] = true
	}
	for _, t := range p.Terms {
		if !keep[strings.ToLower(t)] {
			return true
		}
	}
	return false
}

// MaskerPolicy is the masker's policy for internal data.
func (p AIMaskingPolicy) MaskerPolicy() aimask.Policy {
	return aimask.Policy{
		Hosts: p.Masked(AIMaskHosts), IPs: p.Masked(AIMaskIPs), Emails: p.Masked(AIMaskEmails),
		Users: p.Masked(AIMaskUsers), URLParams: p.Masked(AIMaskURLParams), Orgs: p.Masked(AIMaskOrgs),
		Tickets: p.Masked(AIMaskTickets), MaskSubdomainLabels: p.MaskSubdomainLabels,
		Terms: append([]string(nil), p.Terms...),
	}
}

// AIMaskingRepository stores the masking policy (tenant_ai_settings.masking).
type AIMaskingRepository interface {
	// GetMasking returns the organization's policy; an organization with no
	// row or an empty policy gets the default (every class masked).
	GetMasking(ctx context.Context, tenantID shared.ID) (AIMaskingPolicy, error)
	// SaveMasking writes the policy, creating the settings row if needed.
	SaveMasking(ctx context.Context, tenantID shared.ID, p AIMaskingPolicy) error
}
