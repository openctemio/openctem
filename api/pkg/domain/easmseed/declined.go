package easmseed

import "time"

// Declined is a network the organization answered "not ours" about on the
// Decisions card (research/425): the addresses its in-scope names resolve
// to inside it are no longer offered. It narrows suggestions only and
// authorizes nothing. Kind is KindASN (Value "AS<n>") or KindOrgName.
type Declined struct {
	ID        string    `json:"id"`
	Kind      Kind      `json:"kind"`
	Value     string    `json:"value"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
