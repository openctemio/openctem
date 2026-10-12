package integration

import (
	"fmt"
	"net/url"
	"strings"

	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrIntegrationDisabled is returned when a read or test would use the stored
// credentials of an integration its owner switched off.
var ErrIntegrationDisabled = fmt.Errorf("%w: integration is disabled; enable it first", shared.ErrValidation)

// ErrCredentialsRequiredForNewHost is returned when base_url moves to another
// host without new credentials: the stored token was issued for the old host
// and must not be sent to a host someone else chose.
var ErrCredentialsRequiredForNewHost = fmt.Errorf("%w: changing base_url to another host requires re-entering the credentials", shared.ErrValidation)

// callerMetadataKeys are the integration metadata keys a caller may set
// directly: non-secret provider settings (Splunk HEC endpoint, index and
// sourcetype; a Slack/Teams channel label). Everything else in metadata is
// written by the server (chat ids, SMTP host, sync state) and is never
// overwritten from a request.
var callerMetadataKeys = map[string]bool{
	"hec_url":      true,
	"index":        true,
	"sourcetype":   true,
	"channel_name": true,
}

const maxCallerMetadataValueLen = 2048

// sanitizeCallerMetadata checks request metadata against the allowlist: only
// known non-secret keys, string values, bounded length. A secret never goes
// to metadata (it is stored in plaintext there); credentials go in the
// encrypted credentials field.
func sanitizeCallerMetadata(in map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if !callerMetadataKeys[k] {
			return nil, fmt.Errorf("%w: metadata key %q is not allowed", shared.ErrValidation, k)
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%w: metadata %q must be a string", shared.ErrValidation, k)
		}
		if len(s) > maxCallerMetadataValueLen {
			return nil, fmt.Errorf("%w: metadata %q is too long", shared.ErrValidation, k)
		}
		out[k] = s
	}
	return out, nil
}

// hostOf returns the scheme://host[:port] of a URL, lower-cased; "" when the
// URL is empty or unparsable.
func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(raw)
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// requireCredentialsForHostChange refuses a base_url change to a different
// host when stored credentials would follow it.
func requireCredentialsForHostChange(intg *integrationdom.Integration, newBaseURL, newCredentials *string) error {
	if newBaseURL == nil || intg.CredentialsEncrypted() == "" {
		return nil
	}
	if hostOf(*newBaseURL) == hostOf(intg.BaseURL()) {
		return nil
	}
	if newCredentials != nil && *newCredentials != "" {
		return nil
	}
	return ErrCredentialsRequiredForNewHost
}
