package cirun

// Pasted signing keys: a trust configuration can verify job tokens with the
// provider's public keys an administrator pasted, so the platform never
// fetches them (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md, "Pasted
// signing keys"). When the provider rotates its keys, tokens name a kid the
// pasted set does not have: the job is told to have the keys pasted again,
// and the administrators are told (audit and alert, at most once an hour per
// configuration, since the kid comes from a token nobody has verified).

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/weblink"
)

// RefuseUnknownKey refuses a token signed with a key that is not among the
// configuration's pasted keys (CI_TOKEN_UNKNOWN_KEY).
const RefuseUnknownKey = "unknown_key"

// UnknownKeyMessage tells the job (and the administrator previewing a token)
// what to do. It names no configuration and no key.
const UnknownKeyMessage = "Its signing key is not among the keys pasted in the trust configuration; an administrator " +
	"must paste the current keys (<GitLab URL>/oauth/discovery/keys, <GitHub issuer>/.well-known/jwks)."

const (
	unknownKeyNoticeEvery   = time.Hour
	maxUnknownKeyNoticeKeys = 2000
	// maxNoticeKIDLen bounds the unverified kid written to the audit log.
	maxNoticeKIDLen = 128
	// alertActionKey names the alert's action in its metadata.
	alertActionKey = "action"
)

// pastedKeyUnknownError: the token named a key none of the configurations
// with pasted keys has, and no configuration verified it.
type pastedKeyUnknownError struct {
	configs []cirun.TrustConfig
}

func (e *pastedKeyUnknownError) Error() string {
	return "token signing key is not among the pasted keys"
}

// noticeThrottle answers true once per key per interval, with a bounded
// memory (it stays quiet rather than grow).
type noticeThrottle struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (n *noticeThrottle) first(key string, now time.Time, every time.Duration, limit int) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen == nil {
		n.seen = map[string]time.Time{}
	}
	if at, ok := n.seen[key]; ok && now.Sub(at) < every {
		return false
	}
	if len(n.seen) >= limit {
		for k, at := range n.seen {
			if now.Sub(at) >= every {
				delete(n.seen, k)
			}
		}
		if len(n.seen) >= limit {
			return false
		}
	}
	n.seen[key] = now
	return true
}

// notePastedKeyUnknown writes an audit entry and alerts the administrators
// that a configuration's pasted keys do not include the key a token named.
// At most once an hour per configuration: an anonymous caller can send such
// a token, so it cannot fill the audit log or the administrators' inboxes.
func (s *Service) notePastedKeyUnknown(ctx context.Context, tenantID shared.ID, configs []cirun.TrustConfig, kid string) {
	kid = cirun.SanitizeLabel(kid, maxNoticeKIDLen)
	s.log.Info("ci exchange refused: token signing key not among the pasted keys", "tenant_id", tenantID.String(),
		"kid", logger.SanitizeValue(kid))
	for i := range configs {
		c := &configs[i]
		if !s.keyNotices.first(tenantID.String()+"|"+c.ID.String(), s.now(), unknownKeyNoticeEvery, maxUnknownKeyNoticeKeys) {
			continue
		}
		known := c.SigningKeyIDs()
		name := cirun.SanitizeLabel(c.Name, 80)
		s.logAudit(ctx, tenantID, Actor{},
			auditapp.NewDeniedEvent(auditdom.ActionCIRunTokenRefused, auditdom.ResourceTypeCITrustConfig, c.ID.String(),
				RefuseUnknownKey).
				WithMessage(fmt.Sprintf("A CI token for %q named a signing key that is not among its pasted keys; "+
					"paste the provider's current keys", name)).
				WithResourceName(c.Name).
				// reasons and provider: the shape the recent refusals list reads.
				WithMetadata("reasons", []string{RefuseUnknownKey}).
				WithMetadata("provider", string(c.Provider)).
				WithMetadata("reason", RefuseUnknownKey).
				WithMetadata("token_kid", kid).
				WithMetadata("pasted_kids", known))
		alert := AdminAlert{
			EventType: string(integration.EventTypeCITokenRefusals), Severity: notificationdom.SeverityHigh,
			Title: "CI signing keys out of date: " + name,
			Body: fmt.Sprintf("A CI job's token for the trust configuration %q is signed with the key %q, which is not among "+
				"the keys pasted in it (%s). The CI provider has probably rotated its keys, and every upload of these "+
				"pipelines is refused until the provider's current keys are pasted in the trust configuration.",
				name, kid, strings.Join(known, ", ")),
			URL: trustSettingsPath, Aggregate: "ci_trust_config", AggregateID: &c.ID,
			Metadata: map[string]any{alertActionKey: "signing_key_unknown", "token_kid": kid, "pasted_kids": known},
			Email:    true,
		}
		if base := strings.TrimRight(s.cfg.WebBaseURL, "/"); base != "" {
			alert.EmailLink = weblink.Console(base, trustSettingsPath, tenantID.String())
		}
		s.alertAdmins(ctx, tenantID, alert)
	}
}
