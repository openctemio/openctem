// Package credential provides domain types for credential leak management.
package credential

import (
	"fmt"
	"slices"
	"strings"
)

// CredentialType represents the type of leaked credential.
type CredentialType string

const (
	CredentialTypePassword      CredentialType = "password"
	CredentialTypePasswordHash  CredentialType = "password_hash"
	CredentialTypeAPIKey        CredentialType = "api_key"
	CredentialTypeAccessToken   CredentialType = "access_token"
	CredentialTypeRefreshToken  CredentialType = "refresh_token"
	CredentialTypePrivateKey    CredentialType = "private_key"
	CredentialTypeSSHKey        CredentialType = "ssh_key"
	CredentialTypeCertificate   CredentialType = "certificate"
	CredentialTypeAWSKey        CredentialType = "aws_key"
	CredentialTypeGCPKey        CredentialType = "gcp_key"
	CredentialTypeAzureKey      CredentialType = "azure_key"
	CredentialTypeDatabaseCred  CredentialType = "database_cred"
	CredentialTypeJWTSecret     CredentialType = "jwt_secret"
	CredentialTypeEncryptionKey CredentialType = "encryption_key"
	CredentialTypeWebhookSecret CredentialType = "webhook_secret"
	CredentialTypeSMTPCred      CredentialType = "smtp_cred"
	CredentialTypeOther         CredentialType = "other"
)

// AllCredentialTypes returns all valid credential types.
func AllCredentialTypes() []CredentialType {
	return []CredentialType{
		CredentialTypePassword,
		CredentialTypePasswordHash,
		CredentialTypeAPIKey,
		CredentialTypeAccessToken,
		CredentialTypeRefreshToken,
		CredentialTypePrivateKey,
		CredentialTypeSSHKey,
		CredentialTypeCertificate,
		CredentialTypeAWSKey,
		CredentialTypeGCPKey,
		CredentialTypeAzureKey,
		CredentialTypeDatabaseCred,
		CredentialTypeJWTSecret,
		CredentialTypeEncryptionKey,
		CredentialTypeWebhookSecret,
		CredentialTypeSMTPCred,
		CredentialTypeOther,
	}
}

// IsValid checks if the credential type is valid.
func (t CredentialType) IsValid() bool {
	return slices.Contains(AllCredentialTypes(), t)
}

// String returns the string representation.
func (t CredentialType) String() string {
	return string(t)
}

// ParseCredentialType parses a string into a CredentialType.
func ParseCredentialType(s string) (CredentialType, error) {
	t := CredentialType(strings.ToLower(strings.TrimSpace(s)))
	if !t.IsValid() {
		return "", fmt.Errorf("invalid credential type: %s", s)
	}
	return t, nil
}

// DefaultSeverity returns the default severity for this credential type.
func (t CredentialType) DefaultSeverity() string {
	switch t {
	case CredentialTypeAWSKey, CredentialTypeGCPKey, CredentialTypeAzureKey,
		CredentialTypePrivateKey, CredentialTypeSSHKey, CredentialTypeDatabaseCred:
		return "critical"
	case CredentialTypeAPIKey, CredentialTypeJWTSecret, CredentialTypeAccessToken,
		CredentialTypeEncryptionKey, CredentialTypeCertificate:
		return "high"
	case CredentialTypePassword, CredentialTypePasswordHash, CredentialTypeRefreshToken:
		return "high"
	case CredentialTypeWebhookSecret, CredentialTypeSMTPCred:
		return "medium"
	default:
		return "medium"
	}
}

// SourceType represents the source where credential was found.
type SourceType string

const (
	// Breach sources
	SourceTypeDataBreach       SourceType = "data_breach"
	SourceTypeDarkWeb          SourceType = "dark_web"
	SourceTypePasteSite        SourceType = "paste_site"
	SourceTypeUndergroundForum SourceType = "underground_forum"

	// Code sources
	SourceTypeCodeRepository SourceType = "code_repository"
	SourceTypeCommitHistory  SourceType = "commit_history"
	SourceTypeConfigFile     SourceType = "config_file"
	SourceTypeLogFile        SourceType = "log_file"
	SourceTypeCICD           SourceType = "ci_cd"
	SourceTypeDockerImage    SourceType = "docker_image"

	// Other sources
	SourceTypePhishing     SourceType = "phishing"
	SourceTypeMalware      SourceType = "malware"
	SourceTypePublicBucket SourceType = "public_bucket"
	SourceTypeAPIResponse  SourceType = "api_response"
	SourceTypeInternal     SourceType = "internal_report"
	SourceTypeOther        SourceType = "other"
)

// AllSourceTypes returns all valid source types.
func AllSourceTypes() []SourceType {
	return []SourceType{
		SourceTypeDataBreach,
		SourceTypeDarkWeb,
		SourceTypePasteSite,
		SourceTypeUndergroundForum,
		SourceTypeCodeRepository,
		SourceTypeCommitHistory,
		SourceTypeConfigFile,
		SourceTypeLogFile,
		SourceTypeCICD,
		SourceTypeDockerImage,
		SourceTypePhishing,
		SourceTypeMalware,
		SourceTypePublicBucket,
		SourceTypeAPIResponse,
		SourceTypeInternal,
		SourceTypeOther,
	}
}

// IsValid checks if the source type is valid.
func (s SourceType) IsValid() bool {
	return slices.Contains(AllSourceTypes(), s)
}

// String returns the string representation.
func (s SourceType) String() string {
	return string(s)
}

// ParseSourceType parses a string into a SourceType.
func ParseSourceType(str string) (SourceType, error) {
	s := SourceType(strings.ToLower(strings.TrimSpace(str)))
	if !s.IsValid() {
		return "", fmt.Errorf("invalid source type: %s", str)
	}
	return s, nil
}

// IsBreachSource returns true if this is a breach-related source.
func (s SourceType) IsBreachSource() bool {
	return s == SourceTypeDataBreach || s == SourceTypeDarkWeb ||
		s == SourceTypePasteSite || s == SourceTypeUndergroundForum
}

// IsCodeSource returns true if this is a code-related source.
func (s SourceType) IsCodeSource() bool {
	return s == SourceTypeCodeRepository || s == SourceTypeCommitHistory ||
		s == SourceTypeConfigFile || s == SourceTypeLogFile ||
		s == SourceTypeCICD || s == SourceTypeDockerImage
}

// Classification represents the exposure classification.
type Classification string

const (
	ClassificationInternal Classification = "internal"
	ClassificationExternal Classification = "external"
	ClassificationPartner  Classification = "partner"
	ClassificationVendor   Classification = "vendor"
	ClassificationUnknown  Classification = "unknown"
)

// AllClassifications returns all valid classifications.
func AllClassifications() []Classification {
	return []Classification{
		ClassificationInternal,
		ClassificationExternal,
		ClassificationPartner,
		ClassificationVendor,
		ClassificationUnknown,
	}
}

// IsValid checks if the classification is valid.
func (c Classification) IsValid() bool {
	return slices.Contains(AllClassifications(), c)
}

// String returns the string representation.
func (c Classification) String() string {
	return string(c)
}

// ParseClassification parses a string into a Classification.
func ParseClassification(str string) (Classification, error) {
	c := Classification(strings.ToLower(strings.TrimSpace(str)))
	if !c.IsValid() {
		return ClassificationUnknown, nil // Default to unknown instead of error
	}
	return c, nil
}

// DedupStrategy defines how to handle duplicate credentials.
type DedupStrategy string

const (
	DedupStrategySkip           DedupStrategy = "skip"
	DedupStrategyUpdateLastSeen DedupStrategy = "update_last_seen"
	DedupStrategyUpdateAll      DedupStrategy = "update_all"
	DedupStrategyCreateNew      DedupStrategy = "create_new"
)

// AllDedupStrategies returns all valid deduplication strategies.
func AllDedupStrategies() []DedupStrategy {
	return []DedupStrategy{
		DedupStrategySkip,
		DedupStrategyUpdateLastSeen,
		DedupStrategyUpdateAll,
		DedupStrategyCreateNew,
	}
}

// IsValid checks if the dedup strategy is valid.
func (d DedupStrategy) IsValid() bool {
	return slices.Contains(AllDedupStrategies(), d)
}

// String returns the string representation.
func (d DedupStrategy) String() string {
	return string(d)
}

// ParseDedupStrategy parses a string into a DedupStrategy.
func ParseDedupStrategy(str string) DedupStrategy {
	d := DedupStrategy(strings.ToLower(strings.TrimSpace(str)))
	if !d.IsValid() {
		return DedupStrategyUpdateLastSeen // Default
	}
	return d
}
