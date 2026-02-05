package asset

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// AssetService Entity (Extension)
// =============================================================================

// AssetService represents a network service running on an asset (host/server).
// Services are stored in the `asset_services` table and linked to assets via asset_id.
// This follows the same extension pattern as RepositoryExtension (asset_repositories table).
// Provides a clean 1:N relationship (Host -> Services) without bloating the assets table.
type AssetService struct {
	id       shared.ID
	tenantID shared.ID
	assetID  shared.ID // Parent asset (host, server, IP address)

	// Service Identity
	name        string
	protocol    Protocol
	port        int
	serviceType ServiceType

	// Service Details (from banner grabbing/fingerprinting)
	product string // Software name: nginx, Apache, OpenSSH, MySQL
	version string // Software version: 1.18.0, 8.0.23
	banner  string // Raw service banner
	cpe     string // Common Platform Enumeration identifier

	// Exposure
	isPublic   bool     // Directly accessible from internet
	exposure   Exposure // public, restricted, private
	tlsEnabled bool
	tlsVersion string // TLS 1.2, TLS 1.3

	// Discovery
	discoverySource string     // nmap, shodan, censys, httpx, agent
	discoveredAt    *time.Time // When first discovered
	lastSeenAt      *time.Time // When last seen active

	// Risk Context
	findingCount int // Number of vulnerabilities on this service
	riskScore    int // Calculated risk score (0-100)

	// State
	state          ServiceState
	stateChangedAt *time.Time

	// Timestamps
	createdAt time.Time
	updatedAt time.Time
}

// =============================================================================
// Constructors
// =============================================================================

// NewAssetService creates a new AssetService entity.
func NewAssetService(tenantID, assetID shared.ID, port int, protocol Protocol, serviceType ServiceType) (*AssetService, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("%w: port must be between 1 and 65535", shared.ErrValidation)
	}
	if !protocol.IsValid() {
		return nil, fmt.Errorf("%w: invalid protocol", shared.ErrValidation)
	}
	if !serviceType.IsValid() {
		return nil, fmt.Errorf("%w: invalid service type", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &AssetService{
		id:          shared.NewID(),
		tenantID:    tenantID,
		assetID:     assetID,
		port:        port,
		protocol:    protocol,
		serviceType: serviceType,
		exposure:    ExposurePrivate,
		state:       ServiceStateActive,
		createdAt:   now,
		updatedAt:   now,
	}, nil
}

// ReconstituteAssetService recreates an AssetService from persistence.
func ReconstituteAssetService(
	id, tenantID, assetID shared.ID,
	name string,
	protocol Protocol,
	port int,
	serviceType ServiceType,
	product, version, banner, cpe string,
	isPublic bool,
	exposure Exposure,
	tlsEnabled bool,
	tlsVersion string,
	discoverySource string,
	discoveredAt, lastSeenAt *time.Time,
	findingCount, riskScore int,
	state ServiceState,
	stateChangedAt *time.Time,
	createdAt, updatedAt time.Time,
) *AssetService {
	return &AssetService{
		id:              id,
		tenantID:        tenantID,
		assetID:         assetID,
		name:            name,
		protocol:        protocol,
		port:            port,
		serviceType:     serviceType,
		product:         product,
		version:         version,
		banner:          banner,
		cpe:             cpe,
		isPublic:        isPublic,
		exposure:        exposure,
		tlsEnabled:      tlsEnabled,
		tlsVersion:      tlsVersion,
		discoverySource: discoverySource,
		discoveredAt:    discoveredAt,
		lastSeenAt:      lastSeenAt,
		findingCount:    findingCount,
		riskScore:       riskScore,
		state:           state,
		stateChangedAt:  stateChangedAt,
		createdAt:       createdAt,
		updatedAt:       updatedAt,
	}
}

// =============================================================================
// Getters
// =============================================================================

func (s *AssetService) ID() shared.ID              { return s.id }
func (s *AssetService) TenantID() shared.ID        { return s.tenantID }
func (s *AssetService) AssetID() shared.ID         { return s.assetID }
func (s *AssetService) Name() string               { return s.name }
func (s *AssetService) Protocol() Protocol         { return s.protocol }
func (s *AssetService) Port() int                  { return s.port }
func (s *AssetService) ServiceType() ServiceType   { return s.serviceType }
func (s *AssetService) Product() string            { return s.product }
func (s *AssetService) Version() string            { return s.version }
func (s *AssetService) Banner() string             { return s.banner }
func (s *AssetService) CPE() string                { return s.cpe }
func (s *AssetService) IsPublic() bool             { return s.isPublic }
func (s *AssetService) Exposure() Exposure         { return s.exposure }
func (s *AssetService) TLSEnabled() bool           { return s.tlsEnabled }
func (s *AssetService) TLSVersion() string         { return s.tlsVersion }
func (s *AssetService) DiscoverySource() string    { return s.discoverySource }
func (s *AssetService) DiscoveredAt() *time.Time   { return s.discoveredAt }
func (s *AssetService) LastSeenAt() *time.Time     { return s.lastSeenAt }
func (s *AssetService) FindingCount() int          { return s.findingCount }
func (s *AssetService) RiskScore() int             { return s.riskScore }
func (s *AssetService) State() ServiceState        { return s.state }
func (s *AssetService) StateChangedAt() *time.Time { return s.stateChangedAt }
func (s *AssetService) CreatedAt() time.Time       { return s.createdAt }
func (s *AssetService) UpdatedAt() time.Time       { return s.updatedAt }

// =============================================================================
// Setters / Mutators
// =============================================================================

func (s *AssetService) SetName(name string) {
	s.name = name
	s.updatedAt = time.Now().UTC()
}

func (s *AssetService) SetProduct(product string) {
	s.product = product
	s.updatedAt = time.Now().UTC()
}

func (s *AssetService) SetVersion(version string) {
	s.version = version
	s.updatedAt = time.Now().UTC()
}

func (s *AssetService) SetBanner(banner string) {
	// Truncate to max allowed length (from migration 000111)
	if len(banner) > 4096 {
		banner = banner[:4096]
	}
	s.banner = banner
	s.updatedAt = time.Now().UTC()
}

func (s *AssetService) SetCPE(cpe string) {
	// Truncate to max allowed length (from migration 000111)
	if len(cpe) > 500 {
		cpe = cpe[:500]
	}
	s.cpe = cpe
	s.updatedAt = time.Now().UTC()
}

func (s *AssetService) SetPublic(isPublic bool) {
	s.isPublic = isPublic
	if isPublic {
		s.exposure = ExposurePublic
	}
	s.updatedAt = time.Now().UTC()
}

func (s *AssetService) SetExposure(exposure Exposure) error {
	if !exposure.IsValid() {
		return fmt.Errorf("%w: invalid exposure", shared.ErrValidation)
	}
	s.exposure = exposure
	s.isPublic = (exposure == ExposurePublic)
	s.updatedAt = time.Now().UTC()
	return nil
}

func (s *AssetService) SetTLS(enabled bool, version string) {
	s.tlsEnabled = enabled
	s.tlsVersion = version
	s.updatedAt = time.Now().UTC()
}

func (s *AssetService) SetDiscoveryInfo(source string, discoveredAt *time.Time) {
	s.discoverySource = source
	s.discoveredAt = discoveredAt
	s.updatedAt = time.Now().UTC()
}

func (s *AssetService) MarkSeen() {
	now := time.Now().UTC()
	s.lastSeenAt = &now
	s.updatedAt = now
}

func (s *AssetService) UpdateFindingCount(count int) {
	if count < 0 {
		count = 0
	}
	s.findingCount = count
	s.updatedAt = time.Now().UTC()
}

func (s *AssetService) UpdateRiskScore(score int) error {
	if score < 0 || score > 100 {
		return fmt.Errorf("%w: risk score must be between 0 and 100", shared.ErrValidation)
	}
	s.riskScore = score
	s.updatedAt = time.Now().UTC()
	return nil
}

func (s *AssetService) SetState(state ServiceState) error {
	if !state.IsValid() {
		return fmt.Errorf("%w: invalid service state", shared.ErrValidation)
	}
	if s.state != state {
		s.state = state
		now := time.Now().UTC()
		s.stateChangedAt = &now
		s.updatedAt = now
	}
	return nil
}

// =============================================================================
// Business Logic
// =============================================================================

// IsActive returns true if the service is currently active.
func (s *AssetService) IsActive() bool {
	return s.state == ServiceStateActive
}

// IsHighRisk returns true if the service is considered high risk.
// High risk: public + (database OR remote access OR no TLS on HTTPS)
func (s *AssetService) IsHighRisk() bool {
	if !s.isPublic {
		return false
	}

	// Database services exposed to internet
	if s.serviceType.IsDatabase() {
		return true
	}

	// Remote access services exposed to internet
	if s.serviceType.IsRemoteAccess() {
		return true
	}

	// HTTPS without TLS
	if s.serviceType == ServiceTypeHTTPS && !s.tlsEnabled {
		return true
	}

	// High finding count
	if s.findingCount >= 5 {
		return true
	}

	return false
}

// CalculateRiskScore calculates and updates the risk score.
func (s *AssetService) CalculateRiskScore() {
	score := 0

	// Base score from exposure
	switch s.exposure {
	case ExposurePublic:
		score += 40
	case ExposureRestricted:
		score += 20
	case ExposurePrivate:
		score += 10
	}

	// Service type risk
	if s.serviceType.IsDatabase() {
		score += 20
	} else if s.serviceType.IsRemoteAccess() {
		score += 15
	}

	// Finding impact
	score += min(s.findingCount*5, 30)

	// TLS penalty for web services
	if (s.serviceType == ServiceTypeHTTP || s.serviceType == ServiceTypeHTTPS) && !s.tlsEnabled {
		score += 10
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	s.riskScore = score
	s.updatedAt = time.Now().UTC()
}

// Identifier returns a unique identifier string for this service.
// Format: "{asset_id}:{port}/{protocol}"
func (s *AssetService) Identifier() string {
	return fmt.Sprintf("%s:%d/%s", s.assetID.String(), s.port, s.protocol)
}

// =============================================================================
// Value Objects
// =============================================================================

// Protocol represents the network protocol.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

func (p Protocol) IsValid() bool {
	return p == ProtocolTCP || p == ProtocolUDP
}

func (p Protocol) String() string {
	return string(p)
}

// ServiceType represents the type of network service.
type ServiceType string

const (
	// Web Services
	ServiceTypeHTTP  ServiceType = "http"
	ServiceTypeHTTPS ServiceType = "https"
	ServiceTypeGRPC  ServiceType = "grpc"

	// Remote Access
	ServiceTypeSSH    ServiceType = "ssh"
	ServiceTypeRDP    ServiceType = "rdp"
	ServiceTypeTelnet ServiceType = "telnet"
	ServiceTypeVNC    ServiceType = "vnc"

	// File Transfer
	ServiceTypeFTP  ServiceType = "ftp"
	ServiceTypeSFTP ServiceType = "sftp"

	// Email
	ServiceTypeSMTP  ServiceType = "smtp"
	ServiceTypeSMTPS ServiceType = "smtps"
	ServiceTypeIMAP  ServiceType = "imap"
	ServiceTypeIMAPS ServiceType = "imaps"
	ServiceTypePOP3  ServiceType = "pop3"
	ServiceTypePOP3S ServiceType = "pop3s"

	// Databases
	ServiceTypeMySQL         ServiceType = "mysql"
	ServiceTypePostgreSQL    ServiceType = "postgresql"
	ServiceTypeMongoDB       ServiceType = "mongodb"
	ServiceTypeRedis         ServiceType = "redis"
	ServiceTypeMSSQL         ServiceType = "mssql"
	ServiceTypeOracle        ServiceType = "oracle"
	ServiceTypeCassandra     ServiceType = "cassandra"
	ServiceTypeElasticsearch ServiceType = "elasticsearch"
	ServiceTypeMemcached     ServiceType = "memcached"

	// Message Queues
	ServiceTypeKafka    ServiceType = "kafka"
	ServiceTypeRabbitMQ ServiceType = "rabbitmq"

	// Infrastructure
	ServiceTypeDNS        ServiceType = "dns"
	ServiceTypeLDAP       ServiceType = "ldap"
	ServiceTypeKerberos   ServiceType = "kerberos"
	ServiceTypeSMB        ServiceType = "smb"
	ServiceTypeNTP        ServiceType = "ntp"
	ServiceTypeSNMP       ServiceType = "snmp"
	ServiceTypeKubernetes ServiceType = "kubernetes"
	ServiceTypeDocker     ServiceType = "docker"

	// Media
	ServiceTypeRTSP ServiceType = "rtsp"
	ServiceTypeSIP  ServiceType = "sip"

	// Other
	ServiceTypeOther ServiceType = "other"
)

// AllServiceTypes returns all valid service types.
func AllServiceTypes() []ServiceType {
	return []ServiceType{
		ServiceTypeHTTP, ServiceTypeHTTPS, ServiceTypeGRPC,
		ServiceTypeSSH, ServiceTypeRDP, ServiceTypeTelnet, ServiceTypeVNC,
		ServiceTypeFTP, ServiceTypeSFTP,
		ServiceTypeSMTP, ServiceTypeSMTPS, ServiceTypeIMAP, ServiceTypeIMAPS, ServiceTypePOP3, ServiceTypePOP3S,
		ServiceTypeMySQL, ServiceTypePostgreSQL, ServiceTypeMongoDB, ServiceTypeRedis, ServiceTypeMSSQL,
		ServiceTypeOracle, ServiceTypeCassandra, ServiceTypeElasticsearch, ServiceTypeMemcached,
		ServiceTypeKafka, ServiceTypeRabbitMQ,
		ServiceTypeDNS, ServiceTypeLDAP, ServiceTypeKerberos, ServiceTypeSMB, ServiceTypeNTP, ServiceTypeSNMP,
		ServiceTypeKubernetes, ServiceTypeDocker,
		ServiceTypeRTSP, ServiceTypeSIP,
		ServiceTypeOther,
	}
}

func (t ServiceType) IsValid() bool {
	for _, valid := range AllServiceTypes() {
		if t == valid {
			return true
		}
	}
	return false
}

func (t ServiceType) String() string {
	return string(t)
}

// IsDatabase returns true if this is a database service.
func (t ServiceType) IsDatabase() bool {
	switch t {
	case ServiceTypeMySQL, ServiceTypePostgreSQL, ServiceTypeMongoDB, ServiceTypeRedis,
		ServiceTypeMSSQL, ServiceTypeOracle, ServiceTypeCassandra, ServiceTypeElasticsearch,
		ServiceTypeMemcached:
		return true
	}
	return false
}

// IsRemoteAccess returns true if this is a remote access service.
func (t ServiceType) IsRemoteAccess() bool {
	switch t {
	case ServiceTypeSSH, ServiceTypeRDP, ServiceTypeTelnet, ServiceTypeVNC:
		return true
	}
	return false
}

// IsWeb returns true if this is a web service.
func (t ServiceType) IsWeb() bool {
	return t == ServiceTypeHTTP || t == ServiceTypeHTTPS || t == ServiceTypeGRPC
}

// DefaultPort returns the default port for this service type.
func (t ServiceType) DefaultPort() int {
	ports := map[ServiceType]int{
		ServiceTypeHTTP:          80,
		ServiceTypeHTTPS:         443,
		ServiceTypeSSH:           22,
		ServiceTypeFTP:           21,
		ServiceTypeSFTP:          22,
		ServiceTypeSMTP:          25,
		ServiceTypeSMTPS:         465,
		ServiceTypeIMAP:          143,
		ServiceTypeIMAPS:         993,
		ServiceTypePOP3:          110,
		ServiceTypePOP3S:         995,
		ServiceTypeMySQL:         3306,
		ServiceTypePostgreSQL:    5432,
		ServiceTypeMongoDB:       27017,
		ServiceTypeRedis:         6379,
		ServiceTypeMSSQL:         1433,
		ServiceTypeOracle:        1521,
		ServiceTypeElasticsearch: 9200,
		ServiceTypeMemcached:     11211,
		ServiceTypeKafka:         9092,
		ServiceTypeRabbitMQ:      5672,
		ServiceTypeDNS:           53,
		ServiceTypeLDAP:          389,
		ServiceTypeKerberos:      88,
		ServiceTypeSMB:           445,
		ServiceTypeRDP:           3389,
		ServiceTypeTelnet:        23,
		ServiceTypeVNC:           5900,
		ServiceTypeGRPC:          50051,
		ServiceTypeNTP:           123,
		ServiceTypeSNMP:          161,
		ServiceTypeKubernetes:    6443,
		ServiceTypeDocker:        2375,
		ServiceTypeRTSP:          554,
		ServiceTypeSIP:           5060,
	}
	if port, ok := ports[t]; ok {
		return port
	}
	return 0
}

// ServiceState represents the state of a service.
type ServiceState string

const (
	ServiceStateActive   ServiceState = "active"   // Service is responding
	ServiceStateInactive ServiceState = "inactive" // Service not responding
	ServiceStateFiltered ServiceState = "filtered" // Firewall blocked
)

func (s ServiceState) IsValid() bool {
	return s == ServiceStateActive || s == ServiceStateInactive || s == ServiceStateFiltered
}

func (s ServiceState) String() string {
	return string(s)
}

// =============================================================================
// List Options
// =============================================================================

// ListAssetServicesOptions contains options for listing asset services.
type ListAssetServicesOptions struct {
	AssetID     *shared.ID
	ServiceType *ServiceType
	State       *ServiceState
	IsPublic    *bool
	Port        *int
	Product     *string

	// Pagination
	Limit  int
	Offset int

	// Sorting
	SortBy    string // port, service_type, risk_score, last_seen_at, created_at
	SortOrder string // asc, desc
}

// DefaultListAssetServicesOptions returns default options.
func DefaultListAssetServicesOptions() ListAssetServicesOptions {
	return ListAssetServicesOptions{
		Limit:     50,
		Offset:    0,
		SortBy:    "port",
		SortOrder: "asc",
	}
}
