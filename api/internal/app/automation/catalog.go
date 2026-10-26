package automation

import (
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// CatalogKind is the kind of a catalog entry.
type CatalogKind string

// Catalog kinds.
const (
	CatalogKindTrigger      CatalogKind = "trigger"
	CatalogKindAction       CatalogKind = "action"
	CatalogKindNotification CatalogKind = "notification"
)

// CatalogEntry is one trigger, action or notification type a builder may
// offer, with the permission the editor and the run's principal need for it
// ("" for none beyond the automation permission).
type CatalogEntry struct {
	Kind       CatalogKind
	Type       string
	Permission permission.Permission
	// RiskClass is what the type asks of the go-live gate ("" for triggers).
	RiskClass automationdom.RiskClass
}

// Catalog lists every type the engine runs (automationdom.TriggerTypes,
// ActionTypes, NotificationTypes) in builder order. It is the only list the
// console builds its palette from.
func Catalog() []CatalogEntry {
	triggers := automationdom.TriggerTypes()
	actions := automationdom.ActionTypes()
	notifications := automationdom.NotificationTypes()
	out := make([]CatalogEntry, 0, len(triggers)+len(actions)+len(notifications))
	for _, t := range triggers {
		out = append(out, CatalogEntry{Kind: CatalogKindTrigger, Type: string(t)})
	}
	for _, a := range actions {
		perm, _ := NodePermission(automationdom.NodeConfig{ActionType: a})
		out = append(out, CatalogEntry{Kind: CatalogKindAction, Type: string(a), Permission: perm, RiskClass: automationdom.ActionRisk(a)})
	}
	for _, n := range notifications {
		perm, _ := NodePermission(automationdom.NodeConfig{NotificationType: n})
		out = append(out, CatalogEntry{Kind: CatalogKindNotification, Type: string(n), Permission: perm, RiskClass: automationdom.NotificationRisk(n)})
	}
	return out
}
