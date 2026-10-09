package audit

// OAuth for MCP clients (docs/rfcs/RFC-062-mcp-authorization.md).

const (
	// ActionMCPClientAuthorized records a person approving an MCP client on
	// the consent page (client, organization, granted scopes).
	ActionMCPClientAuthorized Action = "mcp_grant.authorized"
	// ActionMCPClientDenied records a person refusing an MCP client.
	ActionMCPClientDenied Action = "mcp_grant.denied"
	// ActionMCPTokenIssued records an authorization code redeemed for the
	// first tokens of a grant.
	ActionMCPTokenIssued Action = "mcp_grant.token_issued"
	// ActionMCPCodeReused records an authorization code presented a second
	// time; the grant the first redemption created is revoked.
	ActionMCPCodeReused Action = "mcp_grant.code_reused"
	// ActionMCPRefreshReused records a rotated refresh token presented
	// again: someone else holds a copy, and the grant is revoked.
	ActionMCPRefreshReused Action = "mcp_grant.refresh_reused"
	// ActionMCPGrantRevoked records a grant revoked by the client
	// (revocation endpoint), the person or an administrator.
	ActionMCPGrantRevoked Action = "mcp_grant.revoked"
	// ActionMCPSettingsUpdated records a change of the organization's MCP
	// policy (RFC-062 §8).
	ActionMCPSettingsUpdated Action = "mcp_settings.updated"
)

// Resource types of the MCP OAuth actions.
const (
	ResourceTypeMCPGrant ResourceType = "mcp_grant"
)

var _ = registerActions("mcp", map[Action]Severity{
	ActionMCPClientAuthorized: SeverityMedium,
	ActionMCPClientDenied:     SeverityLow,
	ActionMCPTokenIssued:      SeverityLow,
	ActionMCPCodeReused:       SeverityHigh,
	ActionMCPRefreshReused:    SeverityHigh,
	ActionMCPGrantRevoked:     SeverityMedium,
	ActionMCPSettingsUpdated:  SeverityHigh,
})

func init() {
	configResourceTypes[ResourceTypeMCPGrant] = struct{}{}
}
