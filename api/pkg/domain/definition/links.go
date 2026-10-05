package definition

import (
	"fmt"
	"math"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Identifier is one identifier of a definition (RFC-044 §5.2): its primary
// (namespace, external id) or an alias. Every identifier resolves to exactly
// one definition in its scope.
type Identifier struct {
	Namespace    string
	ExternalID   string
	Scope        Scope
	DefinitionID shared.ID
	IsPrimary    bool
	AssertedBy   Source
}

// Validate checks the trust rules the schema also enforces: an identifier is
// in its definition's scope; a global alias comes only from a feed that
// publishes alias sets; a tenant identifier only from that tenant's reports
// or users.
func (i Identifier) Validate(definitionScope Scope) error {
	if i.DefinitionID.IsZero() {
		return fmt.Errorf("%w: identifier without a definition", ErrInvalid)
	}
	if i.Scope != definitionScope {
		return fmt.Errorf("%w: an identifier must be in its definition's scope", ErrInvalid)
	}
	if !i.AssertedBy.IsValid() {
		return fmt.Errorf("%w: unknown source %q", ErrInvalid, i.AssertedBy)
	}
	if i.Scope.IsGlobal() {
		if i.AssertedBy == SourceTenant || (!i.IsPrimary && !i.AssertedBy.AssertsAliases()) {
			return fmt.Errorf("%w: only OSV, GHSA or the CVE List assert a global alias, not %q", ErrInvalid, i.AssertedBy)
		}
	} else if !i.AssertedBy.IsTenantSource() {
		return fmt.Errorf("%w: a tenant identifier comes from a report or a user, not %q", ErrInvalid, i.AssertedBy)
	}
	if _, err := NormalizeID(i.Namespace, i.ExternalID); err != nil {
		return err
	}
	return nil
}

// Relation is an edge between two different definitions (RFC-044 §5.3).
type Relation struct {
	ID         shared.ID
	Scope      Scope
	FromID     shared.ID
	FromScope  Scope
	ToID       shared.ID
	ToScope    Scope
	Type       RelationType
	AssertedBy Source
}

// Validate checks the relation's scope and trust rules: a global edge joins
// two global definitions and comes from a trusted feed; a tenant edge joins
// that tenant's definitions and global ones and comes from the tenant.
func (r Relation) Validate() error {
	if r.FromID.IsZero() || r.ToID.IsZero() {
		return fmt.Errorf("%w: relation without both ends", ErrInvalid)
	}
	if r.FromID.Equals(r.ToID) {
		return fmt.Errorf("%w: a definition cannot relate to itself", ErrInvalid)
	}
	if !r.Type.IsValid() {
		return fmt.Errorf("%w: unknown relation %q", ErrInvalid, r.Type)
	}
	if !r.AssertedBy.IsValid() {
		return fmt.Errorf("%w: unknown source %q", ErrInvalid, r.AssertedBy)
	}
	for _, end := range []Scope{r.FromScope, r.ToScope} {
		if !end.IsGlobal() && end != r.Scope {
			return fmt.Errorf("%w: a relation may only reach global definitions or its own tenant's", ErrInvalid)
		}
	}
	if r.Scope.IsGlobal() {
		if r.AssertedBy == SourceKEV || !r.AssertedBy.IsTrustedFeed() {
			return fmt.Errorf("%w: a global relation comes from a feed or the rule catalog, not %q", ErrInvalid, r.AssertedBy)
		}
	} else if !r.AssertedBy.IsTenantSource() {
		return fmt.Errorf("%w: a tenant relation comes from a report or a user, not %q", ErrInvalid, r.AssertedBy)
	}
	return nil
}

// TaxonomyLink classifies a definition (CWE-79, OWASP A03, a CIS control).
// Taxonomies are links, never definitions (RFC-044 §5.4).
type TaxonomyLink struct {
	DefinitionID shared.ID
	Scope        Scope
	Namespace    string
	ExternalID   string
	AssertedBy   Source
}

// Validate checks the link's trust rules: a global definition's mapping comes
// from a feed or the rule catalog (a reporter's CWE stays on its finding); a
// tenant definition's from the tenant.
func (l TaxonomyLink) Validate(definitionScope Scope) error {
	if l.DefinitionID.IsZero() {
		return fmt.Errorf("%w: taxonomy link without a definition", ErrInvalid)
	}
	if l.Scope != definitionScope {
		return fmt.Errorf("%w: a taxonomy link must be in its definition's scope", ErrInvalid)
	}
	if !namespacePattern.MatchString(l.Namespace) || strings.TrimSpace(l.ExternalID) == "" || len(l.ExternalID) > 200 {
		return fmt.Errorf("%w: invalid taxonomy entry %s:%s", ErrInvalid, l.Namespace, l.ExternalID)
	}
	if l.Scope.IsGlobal() {
		if !l.AssertedBy.IsTrustedFeed() {
			return fmt.Errorf("%w: a global taxonomy link comes from a feed or the rule catalog, not %q", ErrInvalid, l.AssertedBy)
		}
	} else if !l.AssertedBy.IsTenantSource() {
		return fmt.Errorf("%w: a tenant taxonomy link comes from a report or a user, not %q", ErrInvalid, l.AssertedBy)
	}
	return nil
}

// FindingLink links a finding to one of its definitions (RFC-044 §5.7).
type FindingLink struct {
	FindingID       shared.ID
	TenantID        shared.ID
	DefinitionID    shared.ID
	DefinitionScope Scope
	Role            Role
	Ord             int
	AssertedBy      LinkSource
}

// ValidateFindingLinks checks the complete link set of one finding of
// tenant: exactly one primary at ord 0, unique ords and definitions, known
// roles and sources, and every definition global or the tenant's own. An
// empty set is valid (a finding with no definition yet).
func ValidateFindingLinks(tenant, finding shared.ID, links []FindingLink) error {
	if tenant.IsZero() || finding.IsZero() {
		return fmt.Errorf("%w: finding links need a tenant and a finding", ErrInvalid)
	}
	if len(links) == 0 {
		return nil
	}
	if len(links) > math.MaxInt16 {
		return fmt.Errorf("%w: too many definitions on one finding", ErrInvalid)
	}
	ords := make(map[int]bool, len(links))
	defs := make(map[shared.ID]bool, len(links))
	primaries := 0
	for _, l := range links {
		if !l.TenantID.Equals(tenant) || !l.FindingID.Equals(finding) {
			return fmt.Errorf("%w: a link of another finding or tenant", ErrInvalid)
		}
		if l.DefinitionID.IsZero() {
			return fmt.Errorf("%w: link without a definition", ErrInvalid)
		}
		if !l.DefinitionScope.VisibleTo(tenant) {
			// Not ErrInvalid: the caller named a definition it cannot see.
			return ErrNotFound
		}
		if !l.Role.IsValid() || !l.AssertedBy.IsValid() {
			return fmt.Errorf("%w: unknown role %q or source %q", ErrInvalid, l.Role, l.AssertedBy)
		}
		if l.Ord < 0 || l.Ord > math.MaxInt16 || (l.Ord == 0) != (l.Role == RolePrimary) {
			return fmt.Errorf("%w: the primary is ord 0 and only the primary", ErrInvalid)
		}
		if ords[l.Ord] || defs[l.DefinitionID] {
			return fmt.Errorf("%w: duplicate ord or definition on one finding", ErrInvalid)
		}
		ords[l.Ord], defs[l.DefinitionID] = true, true
		if l.Role == RolePrimary {
			primaries++
		}
	}
	if primaries != 1 {
		return fmt.Errorf("%w: a finding with definitions has exactly one primary", ErrInvalid)
	}
	return nil
}

// PrimaryOf returns the primary definition of links, if any.
func PrimaryOf(links []FindingLink) (shared.ID, bool) {
	for _, l := range links {
		if l.Role == RolePrimary {
			return l.DefinitionID, true
		}
	}
	return shared.ID{}, false
}
