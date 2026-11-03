package limits

import "sort"

// Grant keys are the other half of the one entitlement key registry: things
// that are off unless granted (RFC-145 §5). A self-managed installation is
// granted them by its signed license (pkg/licensekey); a hosted service by
// its control plane. A grant only ever adds: no Community feature, limit or
// security control depends on one, and sign-in, SSO, MFA and audit are never
// grant keys (docs/development/editions.md).

// GrantKey names something a license can grant.
type GrantKey string

// GrantKind says how far a grant reaches.
type GrantKind string

const (
	// GrantKindInstance: one grant for the whole installation (every
	// organization gets it).
	GrantKindInstance GrantKind = "instance"
	// GrantKindTenant: granted per organization (a hosted control plane);
	// a license grants it to every organization of the installation.
	GrantKindTenant GrantKind = "tenant"
)

// Registered grant keys.
const (
	// GrantAssetCollector: the first-party asset collector component.
	GrantAssetCollector GrantKey = "asset_collector"
	// GrantAIWorker: the first-party AI worker component.
	GrantAIWorker GrantKey = "ai_worker"
)

// GrantInfo describes one grant key.
type GrantInfo struct {
	Kind GrantKind
	// Description says what the grant turns on.
	Description string
	// OnExpiry says what stops once the grant ends; data is always kept.
	OnExpiry string
}

// Grants is the registry of grant keys. A license naming a key that is not
// here is refused (pkg/licensekey), and tests/unit/license_guard_test.go
// keeps every key described and listed in docs/architecture/limits.md.
var Grants = map[GrantKey]GrantInfo{
	GrantAssetCollector: {
		Kind:        GrantKindInstance,
		Description: "pairing and ingest of the first-party asset collector component",
		OnExpiry:    "the collector stops sending new data; collected assets stay",
	},
	GrantAIWorker: {
		Kind:        GrantKindInstance,
		Description: "dispatch of AI agent runs to the first-party AI worker component",
		OnExpiry:    "no new runs are dispatched to it; earlier results stay",
	},
}

// GrantKeys lists the registered grant keys in order.
func GrantKeys() []GrantKey {
	out := make([]GrantKey, 0, len(Grants))
	for k := range Grants {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsGrantKey reports whether k is a registered grant key.
func IsGrantKey(k GrantKey) bool {
	_, ok := Grants[k]
	return ok
}
