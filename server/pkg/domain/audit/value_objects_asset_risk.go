package audit

// Edits that lower an asset's exposure, criticality or crown-jewel flag
// (api/docs/architecture/asset-risk-governance.md). The resource is the asset;
// a request's id is in the metadata.
const (
	// ActionAssetRiskLowered: risk inputs were lowered and the change applied
	// (it dropped no open P0/P1 finding, or one person decided it alone under
	// the organization's level).
	ActionAssetRiskLowered Action = "asset_risk.lowered"
	// ActionAssetRiskRequested: a lowering that would drop an open P0/P1 finding
	// waits for approval.
	ActionAssetRiskRequested Action = "asset_risk.requested"
	// ActionAssetRiskSigned: one approval of a request that needs more than one
	// approver (the request stays pending).
	ActionAssetRiskSigned Action = "asset_risk.signed"
	// ActionAssetRiskApproved: the last approval needed applied the change.
	ActionAssetRiskApproved Action = "asset_risk.approved"
	// ActionAssetRiskRequestClosed: a request rejected by an approver or
	// withdrawn by its requester.
	ActionAssetRiskRequestClosed Action = "asset_risk.request_closed"
)

var _ = registerActions("asset", map[Action]Severity{
	ActionAssetRiskLowered:       SeverityHigh,
	ActionAssetRiskRequested:     SeverityMedium,
	ActionAssetRiskSigned:        SeverityMedium,
	ActionAssetRiskApproved:      SeverityHigh,
	ActionAssetRiskRequestClosed: SeverityMedium,
})
