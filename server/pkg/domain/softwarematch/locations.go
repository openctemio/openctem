package softwarematch

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// Locations of a version-match finding (docs/architecture/vulnerability-matching.md,
// "Locations").
//
// One web server often answers on several origins of one host (http:80,
// https:443, http:8080), and each origin is its own service asset. The
// matcher keeps one finding per (host, product, version, CVE) on the oldest
// of those service assets, and one location per service it sees the
// software on, each with its own evidence, sightings and state. A location's
// key is the network identity (asset, CVE, port, transport) the matcher
// would key a finding of its own on, so a location belongs to one finding.
//
// Services are grouped only when every user sees them alike (the same scope
// rows and the same private-program links), so a finding is never moved
// away from a person who could see one of its services, and nobody sees a
// service they could not see before.

// LocationState is what the matcher knows about the software at one
// location.
type LocationState string

const (
	// LocationAffected: the vulnerable version is observed there.
	LocationAffected LocationState = "affected"
	// LocationFixed: another, evaluated version displaced it there.
	LocationFixed LocationState = "fixed"
	// LocationNotAffected: the advisory no longer covers the version seen
	// there.
	LocationNotAffected LocationState = "not_affected"
)

// Location state reasons.
const (
	ReasonObserved        = "observed"
	ReasonMatchedAgain    = "matched_again"
	ReasonVersionChanged  = string(CloseVersionChanged)
	ReasonAdvisoryUpdated = string(CloseAdvisoryUpdated)
	ReasonMerged          = "merged"
)

// maxEvidenceLen bounds the evidence text of a location (the column's check).
const maxEvidenceLen = 512

// Location is one stored location of a matcher finding.
type Location struct {
	ID           shared.ID
	FindingID    shared.ID
	AssetID      shared.ID
	Key          string
	Port         int
	Transport    string
	ProductID    *shared.ID
	VersionID    *shared.ID
	Version      string
	LinkLocation string
	Evidence     string
	State        LocationState
	StateReason  string
	StateAt      time.Time
	FirstSeen    time.Time
	LastSeen     time.Time
	// AssetName is the location's service asset name (reads only).
	AssetName string
}

// LinkKey is the software link the location was matched on; ok is false
// when the location does not name one.
func (l Location) LinkKey() (LinkKey, bool) {
	if l.ProductID == nil || l.VersionID == nil {
		return LinkKey{}, false
	}
	return LinkKey{AssetID: l.AssetID, ProductID: *l.ProductID, VersionID: *l.VersionID, Location: l.LinkLocation}, true
}

// LocationWrite is one write of a location. A sighting (Seen) records the
// location as affected with the current evidence and moves its last
// sighting; a state move (Seen false) sets State only when the stored state
// is still From.
type LocationWrite struct {
	FindingID    shared.ID
	AssetID      shared.ID
	Key          string
	Port         int
	Transport    string
	ProductID    shared.ID
	VersionID    shared.ID
	Version      string
	LinkLocation string
	Evidence     string
	Seen         bool
	State        LocationState
	From         LocationState
	Reason       string
	// Label names the service on the timeline (LocationLabel).
	Label string
	// Quiet: write no timeline entry or audit row when the row is created.
	// The anchor location of a finding is the finding itself, already on its
	// timeline.
	Quiet bool
}

// LocationStore is the matcher's location storage (optional on Store).
type LocationStore interface {
	// TenantLocations returns the tenant's locations.
	TenantLocations(ctx context.Context, tenantID shared.ID) ([]Location, error)
	// WriteLocations applies writes to the tenant's locations. A write for a
	// key another finding holds, or for a finding that is gone or a
	// duplicate, does nothing. Every created row (unless Quiet) and every
	// state move goes on the finding's timeline and into the audit log.
	WriteLocations(ctx context.Context, tenantID shared.ID, writes []LocationWrite) (int, error)
	// ScopeSignatures returns, per asset of the tenant among ids, a value
	// that is equal for two assets exactly when every user sees them alike
	// (the same scope rows, the same program-only flag and private program
	// links).
	ScopeSignatures(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]string, error)
}

// Locatable reports whether a match's finding has locations: a network
// identity (not a package) on a service asset whose name names a host.
func Locatable(m Match) bool {
	if m.Package {
		return false
	}
	// A service is stored as type service (its sub type says http, open
	// port, ...); the legacy http_service and open_port names are input-only.
	if asset.AssetType(m.AssetType) != asset.AssetTypeService {
		return false
	}
	return ServiceHost(m.AssetName) != ""
}

// ServiceHost is the host a service asset name points at, "" when it names
// none (a network range, an empty name).
func ServiceHost(name string) string {
	h := asset.HostOf(name)
	if h == "" || strings.Contains(h, "/") {
		return ""
	}
	return h
}

// HostKey is the group of one locatable match: one finding per host,
// product, version and CVE.
func HostKey(m Match) string {
	return ServiceHost(m.AssetName) + "|" + m.ProductID.String() + "|" + m.VersionID.String() + "|" +
		strings.ToUpper(strings.TrimSpace(m.Result.CVEID))
}

// LocationEvidence bounds and masks the evidence text of a location.
func LocationEvidence(s string) string {
	s = strings.TrimSpace(safetext.MaskEmails(s))
	if len(s) > maxEvidenceLen {
		cut := maxEvidenceLen
		for cut > 0 && !utf8Start(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// LocationLabel names a service by scheme (or transport) and port, without
// its host: "https:443", "http:8080", "tcp:22". It is what the finding page
// and the timeline show.
func LocationLabel(assetName string, port int, transport string) string {
	name := strings.TrimSpace(assetName)
	scheme := ""
	if strings.Contains(name, "://") {
		if u, err := url.Parse(name); err == nil {
			scheme = strings.ToLower(u.Scheme)
			if port == 0 {
				if p, err := strconv.Atoi(u.Port()); err == nil {
					port = p
				}
			}
			if port == 0 {
				switch scheme {
				case "http":
					port = 80
				case "https":
					port = 443
				}
			}
		}
	}
	if scheme == "" {
		if _, p, proto, ok := asset.SplitServiceName(name); ok {
			scheme = proto
			if port == 0 {
				port = p
			}
		}
	}
	if scheme == "" {
		scheme = strings.ToLower(strings.TrimSpace(transport))
	}
	if scheme == "" {
		scheme = "tcp"
	}
	if port <= 0 {
		return scheme
	}
	return scheme + ":" + strconv.Itoa(port)
}
