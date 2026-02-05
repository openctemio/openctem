// Package validator provides struct validation utilities with custom validators.
package validator

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Protocol constants for network validation.
const (
	protocolTCP = "tcp"
	protocolUDP = "udp"
)

// PropertiesValidator validates asset properties based on asset type.
type PropertiesValidator struct {
	maxPropertiesCount int
	maxKeyLength       int
	maxStringLength    int
}

// NewPropertiesValidator creates a new properties validator with default limits.
func NewPropertiesValidator() *PropertiesValidator {
	return &PropertiesValidator{
		maxPropertiesCount: 100,
		maxKeyLength:       100,
		maxStringLength:    10000,
	}
}

// PropertyError represents a property validation error.
type PropertyError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// PropertyErrors is a collection of property validation errors.
type PropertyErrors []PropertyError

// Error implements the error interface.
func (e PropertyErrors) Error() string {
	if len(e) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, err := range e {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(fmt.Sprintf("%s: %s", err.Path, err.Message))
	}
	return sb.String()
}

// ValidateProperties validates properties based on asset type.
func (v *PropertiesValidator) ValidateProperties(assetType string, properties map[string]any) PropertyErrors {
	var errs PropertyErrors

	// Check property count
	if len(properties) > v.maxPropertiesCount {
		errs = append(errs, PropertyError{
			Path:    "properties",
			Message: fmt.Sprintf("exceeds maximum of %d properties", v.maxPropertiesCount),
		})
	}

	// Validate property keys
	for key := range properties {
		if len(key) > v.maxKeyLength {
			errs = append(errs, PropertyError{
				Path:    fmt.Sprintf("properties.%s", key),
				Message: fmt.Sprintf("key exceeds maximum length of %d", v.maxKeyLength),
			})
		}
		if !isValidPropertyKey(key) {
			errs = append(errs, PropertyError{
				Path:    fmt.Sprintf("properties.%s", key),
				Message: "invalid key format (must be alphanumeric with underscores)",
			})
		}
	}

	// Type-specific validation
	typeErrs := v.validateByAssetType(assetType, properties)
	errs = append(errs, typeErrs...)

	if len(errs) == 0 {
		return nil
	}
	return errs
}

// validateByAssetType dispatches validation based on asset type.
func (v *PropertiesValidator) validateByAssetType(assetType string, props map[string]any) PropertyErrors {
	switch assetType {
	case "domain":
		return v.validateDomainProperties(props)
	case "subdomain":
		return v.validateSubdomainProperties(props)
	case "ip_address":
		return v.validateIPAddressProperties(props)
	case "certificate":
		return v.validateCertificateProperties(props)
	case "website", "web_application":
		return v.validateWebsiteProperties(props)
	case "api":
		return v.validateAPIProperties(props)
	case "service", "http_service":
		return v.validateServiceProperties(props)
	case "cloud_account", "compute", "storage", "serverless", "s3_bucket":
		return v.validateCloudProperties(props)
	case "kubernetes_cluster":
		return v.validateKubernetesClusterProperties(props)
	case "kubernetes_namespace":
		return v.validateKubernetesNamespaceProperties(props)
	case "vpc", "subnet", "load_balancer", "firewall":
		return v.validateNetworkProperties(props)
	case "iam_user", "iam_role", "service_account":
		return v.validateIAMProperties(props)
	case "open_port":
		return v.validateOpenPortProperties(props)
	default:
		// No specific validation for unknown types
		return nil
	}
}

// =============================================================================
// Domain Validation
// =============================================================================

func (v *PropertiesValidator) validateDomainProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	// Validate domain-specific nested object
	if domain, ok := props["domain"].(map[string]any); ok {
		if registrar, ok := domain["registrar"].(string); ok {
			if len(registrar) > 255 {
				errs = append(errs, PropertyError{
					Path:    "properties.domain.registrar",
					Message: "exceeds maximum length of 255",
				})
			}
		}

		if registeredAt, ok := domain["registered_at"].(string); ok {
			if _, err := time.Parse(time.RFC3339, registeredAt); err != nil {
				errs = append(errs, PropertyError{
					Path:    "properties.domain.registered_at",
					Message: "must be a valid RFC3339 timestamp",
				})
			}
		}

		if expiresAt, ok := domain["expires_at"].(string); ok {
			if _, err := time.Parse(time.RFC3339, expiresAt); err != nil {
				errs = append(errs, PropertyError{
					Path:    "properties.domain.expires_at",
					Message: "must be a valid RFC3339 timestamp",
				})
			}
		}

		if dnsRecords, ok := domain["dns_records"].([]any); ok {
			errs = append(errs, v.validateDNSRecords(dnsRecords)...)
		}
	}

	return errs
}

func (v *PropertiesValidator) validateDNSRecords(records []any) PropertyErrors {
	var errs PropertyErrors
	validTypes := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true,
		"TXT": true, "NS": true, "SOA": true, "SRV": true, "PTR": true,
	}

	for i, rec := range records {
		record, ok := rec.(map[string]any)
		if !ok {
			errs = append(errs, PropertyError{
				Path:    fmt.Sprintf("properties.domain.dns_records[%d]", i),
				Message: "must be an object",
			})
			continue
		}

		recType, _ := record["type"].(string)
		if recType == "" || !validTypes[strings.ToUpper(recType)] {
			errs = append(errs, PropertyError{
				Path:    fmt.Sprintf("properties.domain.dns_records[%d].type", i),
				Message: "must be a valid DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR)",
			})
		}

		if ttl, ok := record["ttl"].(float64); ok {
			if ttl < 0 || ttl > 2147483647 {
				errs = append(errs, PropertyError{
					Path:    fmt.Sprintf("properties.domain.dns_records[%d].ttl", i),
					Message: "must be a non-negative integer",
				})
			}
		}
	}

	return errs
}

// =============================================================================
// Subdomain Validation
// =============================================================================

func (v *PropertiesValidator) validateSubdomainProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if parentDomain, ok := props["parent_domain"].(string); ok {
		if !isValidDomain(parentDomain) {
			errs = append(errs, PropertyError{
				Path:    "properties.parent_domain",
				Message: "must be a valid domain name",
			})
		}
	}

	if resolvedIPs, ok := props["resolved_ips"].([]any); ok {
		for i, ip := range resolvedIPs {
			ipStr, _ := ip.(string)
			if net.ParseIP(ipStr) == nil {
				errs = append(errs, PropertyError{
					Path:    fmt.Sprintf("properties.resolved_ips[%d]", i),
					Message: "must be a valid IP address",
				})
			}
		}
	}

	if source, ok := props["discovery_source"].(string); ok {
		validSources := map[string]bool{
			"dns_enum": true, "cert_transparency": true, "brute_force": true,
			"web_crawl": true, "passive": true, "active": true,
		}
		if !validSources[source] {
			errs = append(errs, PropertyError{
				Path:    "properties.discovery_source",
				Message: "must be one of: dns_enum, cert_transparency, brute_force, web_crawl, passive, active",
			})
		}
	}

	return errs
}

// =============================================================================
// IP Address Validation
// =============================================================================

func (v *PropertiesValidator) validateIPAddressProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if ipProps, ok := props["ip_address"].(map[string]any); ok {
		if version, ok := ipProps["version"].(float64); ok {
			if version != 4 && version != 6 {
				errs = append(errs, PropertyError{
					Path:    "properties.ip_address.version",
					Message: "must be 4 or 6",
				})
			}
		}

		if asn, ok := ipProps["asn"].(float64); ok {
			if asn < 0 || asn > 4294967295 {
				errs = append(errs, PropertyError{
					Path:    "properties.ip_address.asn",
					Message: "must be a valid ASN (0-4294967295)",
				})
			}
		}

		if country, ok := ipProps["country"].(string); ok {
			if len(country) != 2 {
				errs = append(errs, PropertyError{
					Path:    "properties.ip_address.country",
					Message: "must be a 2-letter ISO 3166-1 alpha-2 country code",
				})
			}
		}

		if ports, ok := ipProps["ports"].([]any); ok {
			errs = append(errs, v.validatePorts(ports, "properties.ip_address.ports")...)
		}

		if geo, ok := ipProps["geolocation"].(map[string]any); ok {
			errs = append(errs, v.validateGeolocation(geo)...)
		}
	}

	return errs
}

func (v *PropertiesValidator) validatePorts(ports []any, basePath string) PropertyErrors {
	var errs PropertyErrors

	for i, p := range ports {
		port, ok := p.(map[string]any)
		if !ok {
			errs = append(errs, PropertyError{
				Path:    fmt.Sprintf("%s[%d]", basePath, i),
				Message: "must be an object",
			})
			continue
		}

		if portNum, ok := port["port"].(float64); ok {
			if portNum < 1 || portNum > 65535 {
				errs = append(errs, PropertyError{
					Path:    fmt.Sprintf("%s[%d].port", basePath, i),
					Message: "must be between 1 and 65535",
				})
			}
		}

		if protocol, ok := port["protocol"].(string); ok {
			if protocol != protocolTCP && protocol != protocolUDP {
				errs = append(errs, PropertyError{
					Path:    fmt.Sprintf("%s[%d].protocol", basePath, i),
					Message: "must be tcp or udp",
				})
			}
		}

		if state, ok := port["state"].(string); ok {
			validStates := map[string]bool{"open": true, "filtered": true, "closed": true}
			if !validStates[state] {
				errs = append(errs, PropertyError{
					Path:    fmt.Sprintf("%s[%d].state", basePath, i),
					Message: "must be open, filtered, or closed",
				})
			}
		}
	}

	return errs
}

func (v *PropertiesValidator) validateGeolocation(geo map[string]any) PropertyErrors {
	var errs PropertyErrors

	if lat, ok := geo["latitude"].(float64); ok {
		if lat < -90 || lat > 90 {
			errs = append(errs, PropertyError{
				Path:    "properties.ip_address.geolocation.latitude",
				Message: "must be between -90 and 90",
			})
		}
	}

	if lon, ok := geo["longitude"].(float64); ok {
		if lon < -180 || lon > 180 {
			errs = append(errs, PropertyError{
				Path:    "properties.ip_address.geolocation.longitude",
				Message: "must be between -180 and 180",
			})
		}
	}

	return errs
}

// =============================================================================
// Certificate Validation
// =============================================================================

func (v *PropertiesValidator) validateCertificateProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if cert, ok := props["certificate"].(map[string]any); ok {
		if notBefore, ok := cert["not_before"].(string); ok {
			if _, err := time.Parse(time.RFC3339, notBefore); err != nil {
				errs = append(errs, PropertyError{
					Path:    "properties.certificate.not_before",
					Message: "must be a valid RFC3339 timestamp",
				})
			}
		}

		if notAfter, ok := cert["not_after"].(string); ok {
			if _, err := time.Parse(time.RFC3339, notAfter); err != nil {
				errs = append(errs, PropertyError{
					Path:    "properties.certificate.not_after",
					Message: "must be a valid RFC3339 timestamp",
				})
			}
		}

		if keySize, ok := cert["key_size"].(float64); ok {
			validSizes := map[float64]bool{1024: true, 2048: true, 3072: true, 4096: true, 256: true, 384: true, 521: true}
			if !validSizes[keySize] {
				errs = append(errs, PropertyError{
					Path:    "properties.certificate.key_size",
					Message: "must be a valid key size (1024, 2048, 3072, 4096 for RSA; 256, 384, 521 for ECDSA)",
				})
			}
		}
	}

	return errs
}

// =============================================================================
// Website Validation
// =============================================================================

func (v *PropertiesValidator) validateWebsiteProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if urlStr, ok := props["url"].(string); ok {
		if _, err := url.ParseRequestURI(urlStr); err != nil {
			errs = append(errs, PropertyError{
				Path:    "properties.url",
				Message: "must be a valid URL",
			})
		}
	}

	if responseCode, ok := props["response_code"].(float64); ok {
		if responseCode < 100 || responseCode > 599 {
			errs = append(errs, PropertyError{
				Path:    "properties.response_code",
				Message: "must be a valid HTTP status code (100-599)",
			})
		}
	}

	if tlsVersion, ok := props["tls_version"].(string); ok {
		validVersions := map[string]bool{
			"TLS 1.0": true, "TLS 1.1": true, "TLS 1.2": true, "TLS 1.3": true,
			"tls1.0": true, "tls1.1": true, "tls1.2": true, "tls1.3": true,
		}
		if !validVersions[tlsVersion] {
			errs = append(errs, PropertyError{
				Path:    "properties.tls_version",
				Message: "must be a valid TLS version",
			})
		}
	}

	return errs
}

// =============================================================================
// API Validation
// =============================================================================

func (v *PropertiesValidator) validateAPIProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if baseURL, ok := props["base_url"].(string); ok {
		if _, err := url.ParseRequestURI(baseURL); err != nil {
			errs = append(errs, PropertyError{
				Path:    "properties.base_url",
				Message: "must be a valid URL",
			})
		}
	}

	if apiType, ok := props["api_type"].(string); ok {
		validTypes := map[string]bool{
			"rest": true, "graphql": true, "grpc": true, "soap": true, "websocket": true,
		}
		if !validTypes[apiType] {
			errs = append(errs, PropertyError{
				Path:    "properties.api_type",
				Message: "must be one of: rest, graphql, grpc, soap, websocket",
			})
		}
	}

	if auth, ok := props["authentication"].(string); ok {
		validAuth := map[string]bool{
			"none": true, "api_key": true, "oauth2": true, "jwt": true, "basic": true,
		}
		if !validAuth[auth] {
			errs = append(errs, PropertyError{
				Path:    "properties.authentication",
				Message: "must be one of: none, api_key, oauth2, jwt, basic",
			})
		}
	}

	return errs
}

// =============================================================================
// Service Validation
// =============================================================================

func (v *PropertiesValidator) validateServiceProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if svc, ok := props["service"].(map[string]any); ok {
		if port, ok := svc["port"].(float64); ok {
			if port < 1 || port > 65535 {
				errs = append(errs, PropertyError{
					Path:    "properties.service.port",
					Message: "must be between 1 and 65535",
				})
			}
		}

		if transport, ok := svc["transport"].(string); ok {
			if transport != protocolTCP && transport != protocolUDP {
				errs = append(errs, PropertyError{
					Path:    "properties.service.transport",
					Message: "must be tcp or udp",
				})
			}
		}

		if state, ok := svc["state"].(string); ok {
			validStates := map[string]bool{"open": true, "filtered": true, "closed": true, "active": true, "inactive": true}
			if !validStates[state] {
				errs = append(errs, PropertyError{
					Path:    "properties.service.state",
					Message: "must be open, filtered, closed, active, or inactive",
				})
			}
		}
	}

	return errs
}

// =============================================================================
// Cloud Validation
// =============================================================================

func (v *PropertiesValidator) validateCloudProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if provider, ok := props["provider"].(string); ok {
		validProviders := map[string]bool{
			"aws": true, "gcp": true, "azure": true, "digitalocean": true,
		}
		if !validProviders[provider] {
			errs = append(errs, PropertyError{
				Path:    "properties.provider",
				Message: "must be one of: aws, gcp, azure, digitalocean",
			})
		}
	}

	if publicAccess, ok := props["public_access"].(string); ok {
		validAccess := map[string]bool{"public": true, "private": true, "restricted": true}
		if !validAccess[publicAccess] {
			errs = append(errs, PropertyError{
				Path:    "properties.public_access",
				Message: "must be public, private, or restricted",
			})
		}
	}

	return errs
}

// =============================================================================
// Kubernetes Validation
// =============================================================================

func (v *PropertiesValidator) validateKubernetesClusterProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if provider, ok := props["provider"].(string); ok {
		validProviders := map[string]bool{
			"eks": true, "gke": true, "aks": true, "self-managed": true,
		}
		if !validProviders[provider] {
			errs = append(errs, PropertyError{
				Path:    "properties.provider",
				Message: "must be one of: eks, gke, aks, self-managed",
			})
		}
	}

	if nodeCount, ok := props["node_count"].(float64); ok {
		if nodeCount < 0 {
			errs = append(errs, PropertyError{
				Path:    "properties.node_count",
				Message: "must be non-negative",
			})
		}
	}

	return errs
}

func (v *PropertiesValidator) validateKubernetesNamespaceProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if ns, ok := props["namespace"].(string); ok {
		if !isValidKubernetesName(ns) {
			errs = append(errs, PropertyError{
				Path:    "properties.namespace",
				Message: "must be a valid Kubernetes namespace name",
			})
		}
	}

	if podCount, ok := props["pod_count"].(float64); ok {
		if podCount < 0 {
			errs = append(errs, PropertyError{
				Path:    "properties.pod_count",
				Message: "must be non-negative",
			})
		}
	}

	return errs
}

// =============================================================================
// Network Validation
// =============================================================================

func (v *PropertiesValidator) validateNetworkProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if cidr, ok := props["cidr_block"].(string); ok {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errs = append(errs, PropertyError{
				Path:    "properties.cidr_block",
				Message: "must be a valid CIDR block",
			})
		}
	}

	if cidr, ok := props["cidr"].(string); ok {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errs = append(errs, PropertyError{
				Path:    "properties.cidr",
				Message: "must be a valid CIDR block",
			})
		}
	}

	return errs
}

// =============================================================================
// IAM Validation
// =============================================================================

func (v *PropertiesValidator) validateIAMProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if provider, ok := props["provider"].(string); ok {
		validProviders := map[string]bool{
			"aws": true, "gcp": true, "azure": true, "kubernetes": true,
		}
		if !validProviders[provider] {
			errs = append(errs, PropertyError{
				Path:    "properties.provider",
				Message: "must be one of: aws, gcp, azure, kubernetes",
			})
		}
	}

	if createdAt, ok := props["created_at"].(string); ok {
		if _, err := time.Parse(time.RFC3339, createdAt); err != nil {
			errs = append(errs, PropertyError{
				Path:    "properties.created_at",
				Message: "must be a valid RFC3339 timestamp",
			})
		}
	}

	return errs
}

// =============================================================================
// Open Port Validation
// =============================================================================

func (v *PropertiesValidator) validateOpenPortProperties(props map[string]any) PropertyErrors {
	var errs PropertyErrors

	if port, ok := props["port"].(float64); ok {
		if port < 1 || port > 65535 {
			errs = append(errs, PropertyError{
				Path:    "properties.port",
				Message: "must be between 1 and 65535",
			})
		}
	}

	if protocol, ok := props["protocol"].(string); ok {
		if protocol != protocolTCP && protocol != protocolUDP {
			errs = append(errs, PropertyError{
				Path:    "properties.protocol",
				Message: "must be tcp or udp",
			})
		}
	}

	if state, ok := props["state"].(string); ok {
		validStates := map[string]bool{"open": true, "filtered": true}
		if !validStates[state] {
			errs = append(errs, PropertyError{
				Path:    "properties.state",
				Message: "must be open or filtered",
			})
		}
	}

	return errs
}

// =============================================================================
// Helper Functions
// =============================================================================

var propertyKeyRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
var k8sNameRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func isValidPropertyKey(key string) bool {
	return propertyKeyRegex.MatchString(key)
}

func isValidDomain(domain string) bool {
	return domainRegex.MatchString(domain)
}

func isValidKubernetesName(name string) bool {
	if len(name) > 253 {
		return false
	}
	return k8sNameRegex.MatchString(name)
}

// ValidateJSON validates that the input is valid JSON and returns properties map.
func ValidateJSON(data []byte) (map[string]any, error) {
	var props map[string]any
	if err := json.Unmarshal(data, &props); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return props, nil
}
