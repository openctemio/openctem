// Package component provides the component domain model for software dependencies.
package component

import (
	"fmt"
	"strings"
)

// Ecosystem represents the package ecosystem.
type Ecosystem string

const (
	EcosystemNPM       Ecosystem = "npm"
	EcosystemMaven     Ecosystem = "maven"
	EcosystemPyPI      Ecosystem = "pypi"
	EcosystemGo        Ecosystem = "go"
	EcosystemCargo     Ecosystem = "cargo"
	EcosystemNuGet     Ecosystem = "nuget"
	EcosystemRubyGems  Ecosystem = "rubygems"
	EcosystemComposer  Ecosystem = "composer"
	EcosystemHex       Ecosystem = "hex"
	EcosystemCocoaPods Ecosystem = "cocoapods"
	EcosystemSwiftPM   Ecosystem = "swiftpm"
	EcosystemPub       Ecosystem = "pub"
	EcosystemCran      Ecosystem = "cran"
	EcosystemOther     Ecosystem = "other"
)

// AllEcosystems returns all valid ecosystems.
func AllEcosystems() []Ecosystem {
	return []Ecosystem{
		EcosystemNPM,
		EcosystemMaven,
		EcosystemPyPI,
		EcosystemGo,
		EcosystemCargo,
		EcosystemNuGet,
		EcosystemRubyGems,
		EcosystemComposer,
		EcosystemHex,
		EcosystemCocoaPods,
		EcosystemSwiftPM,
		EcosystemPub,
		EcosystemCran,
		EcosystemOther,
	}
}

// IsValid checks if the ecosystem is valid.
func (e Ecosystem) IsValid() bool {
	switch e {
	case EcosystemNPM, EcosystemMaven, EcosystemPyPI, EcosystemGo,
		EcosystemCargo, EcosystemNuGet, EcosystemRubyGems, EcosystemComposer,
		EcosystemHex, EcosystemCocoaPods, EcosystemSwiftPM, EcosystemPub,
		EcosystemCran, EcosystemOther:
		return true
	default:
		return false
	}
}

// String returns the string representation.
func (e Ecosystem) String() string {
	return string(e)
}

// ParseEcosystem parses a string into an Ecosystem.
func ParseEcosystem(s string) (Ecosystem, error) {
	e := Ecosystem(strings.ToLower(strings.TrimSpace(s)))
	if !e.IsValid() {
		return EcosystemOther, nil // Default to other for unknown ecosystems
	}
	return e, nil
}

// ManifestFile returns the typical manifest file for this ecosystem.
func (e Ecosystem) ManifestFile() string {
	switch e {
	case EcosystemNPM:
		return "package.json"
	case EcosystemMaven:
		return "pom.xml"
	case EcosystemPyPI:
		return "requirements.txt"
	case EcosystemGo:
		return "go.mod"
	case EcosystemCargo:
		return "Cargo.toml"
	case EcosystemNuGet:
		return "packages.config"
	case EcosystemRubyGems:
		return "Gemfile"
	case EcosystemComposer:
		return "composer.json"
	case EcosystemHex:
		return "mix.exs"
	case EcosystemCocoaPods:
		return "Podfile"
	case EcosystemSwiftPM:
		return "Package.swift"
	case EcosystemPub:
		return "pubspec.yaml"
	case EcosystemCran:
		return "DESCRIPTION"
	default:
		return ""
	}
}

// Status represents the component status.
type Status string

const (
	StatusActive     Status = "active"
	StatusDeprecated Status = "deprecated"
	StatusEndOfLife  Status = "end_of_life"
	StatusUnknown    Status = "unknown"
)

// AllStatuses returns all valid statuses.
func AllStatuses() []Status {
	return []Status{
		StatusActive,
		StatusDeprecated,
		StatusEndOfLife,
		StatusUnknown,
	}
}

// IsValid checks if the status is valid.
func (s Status) IsValid() bool {
	switch s {
	case StatusActive, StatusDeprecated, StatusEndOfLife, StatusUnknown:
		return true
	default:
		return false
	}
}

// String returns the string representation.
func (s Status) String() string {
	return string(s)
}

// ParseStatus parses a string into a Status.
func ParseStatus(str string) (Status, error) {
	s := Status(strings.ToLower(strings.TrimSpace(str)))
	if !s.IsValid() {
		return "", fmt.Errorf("invalid status: %s", str)
	}
	return s, nil
}

// DependencyType represents whether a dependency is direct or transitive.
type DependencyType string

const (
	DependencyTypeDirect     DependencyType = "direct"
	DependencyTypeTransitive DependencyType = "transitive"
	DependencyTypeDev        DependencyType = "dev"
	DependencyTypeOptional   DependencyType = "optional"
)

// IsValid checks if the dependency type is valid.
func (d DependencyType) IsValid() bool {
	switch d {
	case DependencyTypeDirect, DependencyTypeTransitive, DependencyTypeDev, DependencyTypeOptional:
		return true
	default:
		return false
	}
}

// String returns the string representation.
func (d DependencyType) String() string {
	return string(d)
}

// ParseDependencyType parses a string into a DependencyType.
// Handles mapping from various scanner formats (e.g., Trivy uses "indirect", "transit").
func ParseDependencyType(s string) (DependencyType, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))

	// Map scanner-specific values to our standard types
	switch normalized {
	case "direct", "root":
		return DependencyTypeDirect, nil
	case "transitive", "indirect", "transit":
		return DependencyTypeTransitive, nil
	case "dev", "development":
		return DependencyTypeDev, nil
	case "optional", "peer":
		return DependencyTypeOptional, nil
	default:
		// Unknown types default to direct (safest assumption)
		return DependencyTypeDirect, nil
	}
}

// BuildPURL builds a Package URL (PURL) for a component.
// Format: pkg:ecosystem/namespace/name@version
func BuildPURL(ecosystem Ecosystem, namespace, name, version string) string {
	var purl strings.Builder
	purl.WriteString("pkg:")
	purl.WriteString(string(ecosystem))
	purl.WriteString("/")
	if namespace != "" {
		purl.WriteString(namespace)
		purl.WriteString("/")
	}
	purl.WriteString(name)
	if version != "" {
		purl.WriteString("@")
		purl.WriteString(version)
	}
	return purl.String()
}
