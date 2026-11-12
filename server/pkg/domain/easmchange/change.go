// Package easmchange types the changes of the external attack surface and
// schedules the weekly "what changed" digest.
// Design: docs/rfcs/RFC-080-attack-surface-changes-and-digest.md.
//
// A change is not stored a second time: it is read from the records the
// platform already keeps (asset state history, the RFC-069 change timeline
// and exposure events) and given one of the kinds below.
package easmchange

import (
	"errors"
	"fmt"
	"time"
)

// Kind is the type of an attack-surface change.
type Kind string

const (
	// KindHostAdded: a domain, subdomain or address appeared (or came back).
	KindHostAdded Kind = "host_added"
	// KindHostRemoved: a host is no longer seen by any scan.
	KindHostRemoved Kind = "host_removed"
	// KindPortOpened: an internet-facing port or service appeared.
	KindPortOpened Kind = "port_opened"
	// KindPortClosed: a port or service is no longer seen.
	KindPortClosed Kind = "port_closed"
	// KindCertChanged: a new certificate appeared on the surface (issued,
	// rotated or served by a new host).
	KindCertChanged Kind = "cert_changed"
	// KindCertExpiring: a certificate is about to expire or has expired.
	KindCertExpiring Kind = "cert_expiring"
	// KindDNSChanged: the addresses a name resolves to changed.
	KindDNSChanged Kind = "dns_changed"
	// KindDNSDangling: a dangling CNAME or NS record, or a confirmed takeover.
	KindDNSDangling Kind = "dns_dangling"
	// KindTechChanged: the technologies detected on an asset changed.
	KindTechChanged Kind = "tech_changed"
	// KindExposureNew: any other new exposure on the surface (TLS issue,
	// weak email posture, misconfiguration, leaked credential, ...).
	KindExposureNew Kind = "exposure_new"
	// KindWebSensitiveNew: a sensitive path (a catalog entry of severity high
	// or critical, or an admin panel) appeared on a web origin.
	KindWebSensitiveNew Kind = "web_sensitive_new"
	// KindWebAuthLost: a sensitive or API endpoint that asked for
	// authentication no longer does.
	KindWebAuthLost Kind = "web_auth_lost"
	// KindWebParamAddedSensitive: a parameter appeared on a sensitive
	// endpoint, or a credential-class parameter appeared on any endpoint.
	KindWebParamAddedSensitive Kind = "web_param_added_sensitive"
)

// AllKinds lists every kind in the order the digest presents them: the
// riskiest first.
func AllKinds() []Kind {
	return []Kind{
		KindDNSDangling, KindExposureNew, KindWebSensitiveNew, KindWebAuthLost, KindPortOpened, KindHostAdded,
		KindWebParamAddedSensitive, KindCertExpiring, KindCertChanged, KindDNSChanged, KindTechChanged,
		KindPortClosed, KindHostRemoved,
	}
}

// IsValid reports whether k is a known kind.
func (k Kind) IsValid() bool {
	for _, v := range AllKinds() {
		if v == k {
			return true
		}
	}
	return false
}

// ParseKinds validates a list of kinds from a request.
func ParseKinds(values []string) ([]Kind, error) {
	out := make([]Kind, 0, len(values))
	for _, v := range values {
		k := Kind(v)
		if !k.IsValid() {
			return nil, fmt.Errorf("%w: unknown change kind %q", ErrInvalidQuery, v)
		}
		out = append(out, k)
	}
	return out, nil
}

// ErrInvalidQuery marks a query the caller must fix.
var ErrInvalidQuery = errors.New("invalid change query")

// MaxWindow is the longest window one query may cover.
const MaxWindow = 31 * 24 * time.Hour

// DefaultWindow is the window when the caller gives none: the last week.
const DefaultWindow = 7 * 24 * time.Hour

// MaxPageSize caps one page of changes.
const MaxPageSize = 200

// Change is one typed change of the attack surface.
type Change struct {
	// ID is the id of the record the change was read from; with Kind it is
	// unique (one timeline row may open and close ports).
	ID        string    `json:"id"`
	Kind      Kind      `json:"kind"`
	At        time.Time `json:"at"`
	AssetID   *string   `json:"asset_id,omitempty"`
	AssetName string    `json:"asset_name,omitempty"`
	AssetType string    `json:"asset_type,omitempty"`
	// Detail is the attribute (timeline), the state change (history) or the
	// exposure type the change came from.
	Detail   string   `json:"detail,omitempty"`
	Old      string   `json:"old,omitempty"`
	New      string   `json:"new,omitempty"`
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
	Severity string   `json:"severity,omitempty"`
	// ExposureID links an exposure-sourced change to its exposure.
	ExposureID *string `json:"exposure_id,omitempty"`
}

// Query selects changes in [From, To).
type Query struct {
	From, To time.Time
	Kinds    []Kind
	Limit    int
	// Cursor continues a previous page (opaque, from Page.NextCursor).
	Cursor string
}

// Normalize fills the defaults and checks the window.
func (q *Query) Normalize(now time.Time) error {
	if q.To.IsZero() {
		q.To = now
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-DefaultWindow)
	}
	if !q.From.Before(q.To) {
		return fmt.Errorf("%w: from must be before to", ErrInvalidQuery)
	}
	if q.To.Sub(q.From) > MaxWindow {
		return fmt.Errorf("%w: the window is at most 31 days", ErrInvalidQuery)
	}
	if q.Limit <= 0 || q.Limit > MaxPageSize {
		q.Limit = 50
	}
	return nil
}

// Page is one page of changes plus the count of every kind in the window
// (the counts ignore the kind filter and the cursor).
type Page struct {
	From       time.Time    `json:"from"`
	To         time.Time    `json:"to"`
	Counts     map[Kind]int `json:"counts"`
	Total      int          `json:"total"`
	Items      []Change     `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

// DigestHourUTC is the hour of the day the weekly digest goes out.
const DigestHourUTC = 8

// DefaultDigestWeekday is the weekday of the digest when the organization
// chose none.
const DefaultDigestWeekday = time.Monday

// DigestSlot returns the start of the latest digest slot at or before now
// (weekday at 08:00 UTC) and the week it covers: [slot-7d, slot).
func DigestSlot(now time.Time, weekday time.Weekday) (slot, from time.Time) {
	now = now.UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), DigestHourUTC, 0, 0, 0, time.UTC)
	back := (int(now.Weekday()) - int(weekday) + 7) % 7
	slot = day.AddDate(0, 0, -back)
	if slot.After(now) {
		slot = slot.AddDate(0, 0, -7)
	}
	return slot, slot.AddDate(0, 0, -7)
}

// Weekday maps the stored setting (0 = default, 1..7 = Monday..Sunday, ISO
// 8601) to a time.Weekday.
func Weekday(setting int) time.Weekday {
	if setting < 1 || setting > 7 {
		return DefaultDigestWeekday
	}
	return time.Weekday(setting % 7)
}
