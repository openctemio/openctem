// Package proxypool defines an organization's proxy pools for sensor scan
// traffic: the pools, their endpoints, the health the platform scores from
// sensor reports, and which sensors use which pool. Design:
// docs/rfcs/RFC-034-sensor-network-egress.md; architecture:
// docs/architecture/sensor-proxies.md.
//
// Credentials are never part of a value this package returns to a caller
// outside the service: an Endpoint carries only whether it has credentials.
package proxypool

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Limits.
const (
	MaxPoolsPerTenant    = 20
	MaxEndpointsPerPool  = 64
	MaxNameLength        = 100
	MaxDescriptionLength = 1000
	MaxLabelLength       = 64
	MaxCredentialLength  = 255
	// MaxListBytes bounds a pasted endpoint list.
	MaxListBytes = 64 << 10
)

// Strategies: how a sensor picks an endpoint for a connection.
const (
	// StrategySticky keeps every target host of a job on one endpoint,
	// chosen by weight; removing an endpoint moves only its hosts.
	StrategySticky = "sticky"
	// StrategyPriority uses endpoints in list order, failing over down it.
	StrategyPriority = "priority"
)

// Schemes an endpoint may use.
const (
	SchemeHTTP    = "http"
	SchemeHTTPS   = "https"
	SchemeSOCKS5  = "socks5"
	SchemeSOCKS5H = "socks5h"
)

// Assignment modes of a sensor ("inherit" is the absence of a row).
const (
	ModeInherit = "inherit"
	ModeDirect  = "direct"
	ModePool    = "pool"
)

// AppliesTo values of a job's egress: a pool the organization set as its
// default carries only public target addresses (internal targets never
// pick up an external proxy by accident); a pool set on the sensor carries
// all of them (a segment proxy).
const (
	AppliesPublic = "public"
	AppliesAll    = "all"
)

// MaskedCredentials is how a stored credential appears in an endpoint list.
// A pasted line that keeps it keeps the stored credentials.
const MaskedCredentials = "••••"

// Errors. Each wraps a shared sentinel so handlers map them to HTTP codes.
var (
	ErrPoolNotFound         = fmt.Errorf("%w: proxy pool not found", shared.ErrNotFound)
	ErrEndpointNotFound     = fmt.Errorf("%w: proxy endpoint not found", shared.ErrNotFound)
	ErrSensorNotFound       = fmt.Errorf("%w: sensor not found", shared.ErrNotFound)
	ErrPoolNameTaken        = shared.NewDomainError("PROXY_POOL_NAME_TAKEN", "a proxy pool with this name already exists", shared.ErrAlreadyExists)
	ErrDefaultTaken         = shared.NewDomainError("PROXY_POOL_DEFAULT_EXISTS", "the organization already has a default proxy pool", shared.ErrAlreadyExists)
	ErrPoolInUse            = shared.NewDomainError("PROXY_POOL_IN_USE", "sensors use this proxy pool; set their network path to another pool, Direct or Inherit first", shared.ErrConflict)
	ErrTooManyPools         = shared.NewDomainError("TOO_MANY_PROXY_POOLS", fmt.Sprintf("an organization may define at most %d proxy pools", MaxPoolsPerTenant), shared.ErrValidation)
	ErrEnabledNeedsEndpoint = shared.NewDomainError("PROXY_POOL_NEEDS_ENDPOINT", "add at least one proxy before enabling the pool: scans fail closed when an enabled pool has none", shared.ErrValidation)
	ErrNoEncryption         = shared.NewDomainError("PROXY_CREDENTIALS_UNAVAILABLE", "proxy credentials cannot be stored: the server has no encryption key", shared.ErrValidation)
)

func invalid(format string, args ...any) error {
	return shared.NewDomainError("INVALID_PROXY_POOL", fmt.Sprintf(format, args...), shared.ErrValidation)
}

// Pool is an organization's proxy pool.
type Pool struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Description string
	Enabled     bool
	IsDefault   bool
	Strategy    string
	Revision    int
	Endpoints   []*Endpoint // priority order; filled by the repository
	// AssignedSensors is how many sensors name the pool; filled by the
	// repository.
	AssignedSensors int
	CreatedBy       *shared.ID
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// NewPool validates and creates a pool with no endpoints.
func NewPool(tenantID shared.ID, name, description, strategy string, enabled, isDefault bool, createdBy *shared.ID) (*Pool, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	now := time.Now().UTC()
	p := &Pool{ID: shared.NewID(), TenantID: tenantID, Enabled: enabled, IsDefault: isDefault, Revision: 1,
		CreatedBy: createdBy, CreatedAt: now, UpdatedAt: now}
	if strategy == "" {
		strategy = StrategySticky
	}
	if err := p.Update(&name, &description, &strategy, nil, nil); err != nil {
		return nil, err
	}
	return p, nil
}

// Update changes the given fields (nil: unchanged). A strategy change bumps
// the revision.
func (p *Pool) Update(name, description, strategy *string, enabled, isDefault *bool) error {
	if name != nil {
		n := strings.TrimSpace(*name)
		if n == "" || utf8.RuneCountInString(n) > MaxNameLength || hasControl(n) {
			return invalid("name must be 1 to %d characters", MaxNameLength)
		}
		p.Name = n
	}
	if description != nil {
		d := strings.TrimSpace(*description)
		if utf8.RuneCountInString(d) > MaxDescriptionLength {
			return invalid("description must be at most %d characters", MaxDescriptionLength)
		}
		p.Description = d
	}
	if strategy != nil {
		if *strategy != StrategySticky && *strategy != StrategyPriority {
			return invalid("strategy must be %q or %q", StrategySticky, StrategyPriority)
		}
		if p.Strategy != "" && p.Strategy != *strategy {
			p.Revision++
		}
		p.Strategy = *strategy
	}
	if enabled != nil {
		p.Enabled = *enabled
	}
	if isDefault != nil {
		p.IsDefault = *isDefault
	}
	p.UpdatedAt = time.Now().UTC()
	return nil
}

// Endpoint is one proxy of a pool.
type Endpoint struct {
	ID       shared.ID
	TenantID shared.ID
	PoolID   shared.ID
	Scheme   string
	Host     string
	Port     int
	Label    string
	Priority int
	Enabled  bool
	// CredentialsEncrypted is the stored ciphertext ("" without
	// credentials). It never leaves the service.
	CredentialsEncrypted string
	CredentialsUpdatedAt *time.Time
	Health               Health
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// HasCredentials reports whether the endpoint has stored credentials.
func (e *Endpoint) HasCredentials() bool { return e.CredentialsEncrypted != "" }

// Address is scheme://host:port (no credentials): the only form an endpoint
// is ever shown or logged in.
func (e *Endpoint) Address() string { return addressOf(e.Scheme, e.Host, e.Port) }

func addressOf(scheme, host string, port int) string {
	h := host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, h, port)
}

func endpointKey(scheme, host string, port int) string {
	if scheme == SchemeSOCKS5H {
		scheme = SchemeSOCKS5
	}
	return addressOf(scheme, host, port)
}

// Assignment is a sensor's network path when it is not the organization
// default.
type Assignment struct {
	SensorID shared.ID
	Mode     string // ModeDirect or ModePool
	PoolID   *shared.ID
}

// extraDenied are cloud metadata and host-agent addresses outside the ranges
// scanzone already denies (an IPv6 IMDS address in ULA space, a metadata
// service in CGNAT space, a cloud host agent on a public address). The
// sensor refuses the same addresses at dial.
var extraDenied = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("168.63.129.16"),
}

// deniedNames can never be a proxy endpoint: they name the sensor host
// itself or a cloud metadata service.
var deniedNames = []string{"localhost", "metadata", "metadata.google.internal", "instance-data", "instance-data.ec2.internal"}

// CheckHost validates an endpoint host: an IP address outside the deny list
// (loopback, link-local, metadata, multicast, unspecified, broadcast,
// reserved) or a DNS host name. Private addresses are allowed: a proxy into
// a segment is usually private. The sensor checks every address a name
// resolves to again before it dials.
func CheckHost(host string) error {
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return fmt.Errorf("an address with a zone is not allowed")
		}
		if AddrDenied(a) {
			return fmt.Errorf("%s is not allowed as a proxy (loopback, link-local, metadata, multicast or reserved address)", a)
		}
		return nil
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if len(h) > 253 {
		return fmt.Errorf("host name is too long")
	}
	for _, d := range deniedNames {
		if h == d {
			return fmt.Errorf("%s is not allowed as a proxy", h)
		}
	}
	if strings.HasSuffix(h, ".localhost") {
		return fmt.Errorf("%s is not allowed as a proxy", h)
	}
	for _, label := range strings.Split(h, ".") {
		if !validLabel(label) {
			return fmt.Errorf("%q is not a valid host name", host)
		}
	}
	return nil
}

// AddrDenied reports whether a can never be a proxy endpoint.
func AddrDenied(a netip.Addr) bool {
	a = a.Unmap()
	if scanzone.IsDenied(a) || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, d := range extraDenied {
		if a == d {
			return true
		}
	}
	return false
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, r := range l {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
