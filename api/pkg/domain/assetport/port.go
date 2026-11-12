// Package assetport is the open ports each asset answers on, for the
// port and service filters of the asset list and its Open ports column
// (docs/architecture/asset-ports.md). The rows are derived from the
// open_port service assets a port scan stores and the edges that lead to
// them; the asset-ports worker keeps them current.
package assetport

// QueueResult is one batch of the asset ports queue.
type QueueResult struct {
	// Claimed is the queued assets taken.
	Claimed int
	// Refreshed is the assets whose rows were rewritten (the claimed ones
	// and the assets that depend on them).
	Refreshed int
}

// RefreshChunk is how many assets one rewrite statement covers (a widely
// shared address can have many names resolving to it).
const RefreshChunk = 2000
