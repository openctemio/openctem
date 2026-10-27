package webendpoint

import (
	"crypto/sha256"
	"encoding/hex"
)

// Web change alerts (docs/architecture/web-content-pipeline.md). The change
// kinds themselves are read from web_endpoint_events by the typed change
// feed (easmchange); an alert is the immediate delivery of the two kinds
// that cannot wait for the digest.

const severityCritical = "critical"

// Alert kinds (the easmchange kind names).
const (
	AlertSensitiveNew = "web_sensitive_new"
	AlertAuthLost     = "web_auth_lost"
)

// AlertCandidate is one endpoint change that may be announced at once.
type AlertCandidate struct {
	EndpointID   string
	Kind         string
	Severity     string
	CatalogKey   string
	Method       string
	PathTemplate string
	TemplateHash string
}

// Fingerprint identifies the alert across sightings: one per tenant, origin,
// kind and template. A flapping endpoint keeps the same fingerprint, so it
// alerts once per fingerprint lifetime.
func (c AlertCandidate) Fingerprint(tenantID, originAssetID string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + originAssetID + "\x00" + c.Kind + "\x00" + c.TemplateHash))
	return hex.EncodeToString(sum[:16])
}

// AlertCandidates picks, among the observations of one origin that were just
// recorded, the changes announced immediately:
//   - web_sensitive_new: an endpoint of a critical catalog entry appeared or
//     came back;
//   - web_auth_lost: an endpoint that asked for authentication (required or
//     a login redirect) answers without it, and it is on the catalog or is
//     an API/GraphQL endpoint.
//
// An out-of-scope observation (under a scope exclusion) is never a
// candidate. ids maps template hashes to endpoint ids; existing is the state
// before this sighting.
func AlertCandidates(kept []Observation, existing map[string]PriorState, ids map[string]string) []AlertCandidate {
	var out []AlertCandidate
	for _, o := range kept {
		id, ok := ids[o.TemplateHash]
		if !ok || o.OutOfScope {
			continue
		}
		prior, had := existing[o.TemplateHash]
		c := AlertCandidate{EndpointID: id, CatalogKey: o.CatalogKey, Method: o.Method, PathTemplate: o.PathTemplate, TemplateHash: o.TemplateHash}
		if o.CatalogKey != "" && (!had || prior.State == string(StateGone)) {
			if e := DefaultCatalog.ByKey(o.CatalogKey); e != nil && e.Severity == severityCritical {
				c.Kind, c.Severity = AlertSensitiveNew, severityCritical
				out = append(out, c)
			}
		}
		if had && o.AuthState == "none" && (prior.Auth == "required" || prior.Auth == "redirect_login") &&
			(o.CatalogKey != "" || o.Kind == "api" || o.Kind == "graphql") {
			c.Kind, c.Severity = AlertAuthLost, "high"
			out = append(out, c)
		}
	}
	return out
}

// PriorState is what an endpoint looked like before a sighting.
type PriorState struct {
	Status int
	Auth   string
	State  string
}
