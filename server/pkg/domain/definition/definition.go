package definition

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxTitleLen matches vulnerabilities.title VARCHAR(500).
const maxTitleLen = 500

// Definition is one entry of the catalog: what an issue is, in general.
type Definition struct {
	id          shared.ID
	scope       Scope
	kind        Kind
	namespace   string
	externalID  string
	title       string
	description string
	remediation string
	severity    string
	lifecycle   Lifecycle
	mergedInto  *shared.ID
	origin      Source
	nicknames   []string
	createdAt   time.Time
	updatedAt   time.Time
}

// NewTenantDefinition builds a definition visible to one tenant only: a
// custom rule or template, a pentest issue, or a rule id a sensor reported
// that no curated pack knows (RFC-044 §5.5). origin is SourceReport (created
// by ingest from the tenant's own reports) or SourceTenant (created by a
// user). The CVE namespace is global only.
func NewTenantDefinition(tenantID shared.ID, kind Kind, namespace, externalID, title string, origin Source) (*Definition, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: a tenant definition needs a tenant", ErrInvalid)
	}
	if !origin.IsTenantSource() {
		return nil, fmt.Errorf("%w: a tenant definition comes from a report or a user, not %q", ErrInvalid, origin)
	}
	if namespace == NamespaceCVE {
		return nil, fmt.Errorf("%w: CVE definitions are global", ErrInvalid)
	}
	return newDefinition(TenantScope(tenantID), kind, namespace, externalID, title, origin)
}

// NewGlobalStub builds the identity-only global definition ingest may create
// for an advisory id nobody has reported yet (RFC-044 §5.5). It carries no
// reporter text: its title is the id itself, and the reporter's own title,
// description and scores stay on that tenant's finding. Shared content comes
// later from the trusted feeds.
func NewGlobalStub(namespace, externalID string) (*Definition, error) {
	ns, ok := Lookup(namespace)
	if !ok {
		return nil, fmt.Errorf("%w: unknown namespace %q", ErrInvalid, namespace)
	}
	if !ns.GlobalCapable || !ns.Advisory {
		return nil, fmt.Errorf("%w: a report may create a global stub only for an advisory id, not %s", ErrInvalid, namespace)
	}
	id, err := ns.Normalize(externalID)
	if err != nil {
		return nil, err
	}
	return newDefinition(Global(), ns.DefaultKind, ns.Name, id, id, SourceReport)
}

func newDefinition(scope Scope, kind Kind, namespace, externalID, title string, origin Source) (*Definition, error) {
	ns, ok := Lookup(namespace)
	if !ok {
		return nil, fmt.Errorf("%w: unknown namespace %q", ErrInvalid, namespace)
	}
	if scope.IsGlobal() && !ns.GlobalCapable {
		return nil, fmt.Errorf("%w: namespace %s holds tenant definitions only", ErrInvalid, namespace)
	}
	if kind == "" {
		kind = ns.DefaultKind
	}
	if !kind.IsValid() {
		return nil, fmt.Errorf("%w: unknown kind %q", ErrInvalid, kind)
	}
	id, err := ns.Normalize(externalID)
	if err != nil {
		return nil, err
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = id
	}
	if utf8.RuneCountInString(title) > maxTitleLen {
		title = string([]rune(title)[:maxTitleLen])
	}
	now := time.Now().UTC()
	return &Definition{
		id:         shared.NewID(),
		scope:      scope,
		kind:       kind,
		namespace:  ns.Name,
		externalID: id,
		title:      title,
		severity:   "unknown",
		lifecycle:  LifecyclePublished,
		origin:     origin,
		createdAt:  now,
		updatedAt:  now,
	}, nil
}

// ReconstituteParams are the stored fields of a definition.
type ReconstituteParams struct {
	ID          shared.ID
	Scope       Scope
	Kind        Kind
	Namespace   string
	ExternalID  string
	Title       string
	Description string
	Remediation string
	Severity    string
	Lifecycle   Lifecycle
	MergedInto  *shared.ID
	Origin      Source
	Nicknames   []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Reconstitute rebuilds a stored definition without validation.
func Reconstitute(p ReconstituteParams) *Definition {
	return &Definition{
		id:          p.ID,
		scope:       p.Scope,
		kind:        p.Kind,
		namespace:   p.Namespace,
		externalID:  p.ExternalID,
		title:       p.Title,
		description: p.Description,
		remediation: p.Remediation,
		severity:    p.Severity,
		lifecycle:   p.Lifecycle,
		mergedInto:  p.MergedInto,
		origin:      p.Origin,
		nicknames:   p.Nicknames,
		createdAt:   p.CreatedAt,
		updatedAt:   p.UpdatedAt,
	}
}

func (d *Definition) ID() shared.ID          { return d.id }
func (d *Definition) Scope() Scope           { return d.scope }
func (d *Definition) Kind() Kind             { return d.kind }
func (d *Definition) Namespace() string      { return d.namespace }
func (d *Definition) ExternalID() string     { return d.externalID }
func (d *Definition) Title() string          { return d.title }
func (d *Definition) Description() string    { return d.description }
func (d *Definition) Remediation() string    { return d.remediation }
func (d *Definition) Severity() string       { return d.severity }
func (d *Definition) Lifecycle() Lifecycle   { return d.lifecycle }
func (d *Definition) MergedInto() *shared.ID { return d.mergedInto }
func (d *Definition) Origin() Source         { return d.origin }
func (d *Definition) Nicknames() []string    { return d.nicknames }
func (d *Definition) CreatedAt() time.Time   { return d.createdAt }
func (d *Definition) UpdatedAt() time.Time   { return d.updatedAt }

// CVEID is the compat cve_id column: the external id of a CVE definition,
// else "".
func (d *Definition) CVEID() string {
	if d.namespace == NamespaceCVE {
		return d.externalID
	}
	return ""
}

// SetText sets the shared text of a tenant definition. A global definition's
// text comes only from trusted feeds and is never set through this.
func (d *Definition) SetText(title, description, remediation string) error {
	if d.scope.IsGlobal() {
		return ErrNotWritable
	}
	title = strings.TrimSpace(title)
	if title == "" {
		return fmt.Errorf("%w: empty title", ErrInvalid)
	}
	if utf8.RuneCountInString(title) > maxTitleLen {
		return fmt.Errorf("%w: title longer than %d characters", ErrInvalid, maxTitleLen)
	}
	d.title = title
	d.description = description
	d.remediation = remediation
	d.updatedAt = time.Now().UTC()
	return nil
}

// SetSeverity sets the default severity of a tenant definition.
func (d *Definition) SetSeverity(severity string) error {
	if d.scope.IsGlobal() {
		return ErrNotWritable
	}
	switch severity {
	case "critical", "high", "medium", "low", "info", "none", "unknown":
	default:
		return fmt.Errorf("%w: unknown severity %q", ErrInvalid, severity)
	}
	d.severity = severity
	d.updatedAt = time.Now().UTC()
	return nil
}

// VisibleTo reports whether tenant may read d.
func (d *Definition) VisibleTo(tenant shared.ID) bool { return d.scope.VisibleTo(tenant) }

// ReferenceURL returns the public page of d's primary id, or "".
func (d *Definition) ReferenceURL() string {
	ns, ok := Lookup(d.namespace)
	if !ok {
		return ""
	}
	return ns.ReferenceURL(d.externalID)
}
