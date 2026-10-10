package audit

// VEX statements of the organization (api/docs/architecture/software-components.md).
// A statement closes findings, so every change, expiry and closure is
// recorded.

const (
	ActionVEXStatementCreated  Action = "vex_statement.created"
	ActionVEXStatementUpdated  Action = "vex_statement.updated"
	ActionVEXStatementDeleted  Action = "vex_statement.deleted"
	ActionVEXStatementExpired  Action = "vex_statement.expired"
	ActionVEXStatementImported Action = "vex_statement.imported"
	// ActionVEXStatementApplied records statements applied to findings an
	// ingest reported after the statement was made.
	ActionVEXStatementApplied Action = "vex_statement.applied"
)

// ResourceTypeVEXStatement is a VEX statement.
const ResourceTypeVEXStatement ResourceType = "vex_statement"

var _ = registerActions("vex_statement", map[Action]Severity{
	ActionVEXStatementCreated:  SeverityHigh,
	ActionVEXStatementUpdated:  SeverityHigh,
	ActionVEXStatementDeleted:  SeverityHigh,
	ActionVEXStatementExpired:  SeverityMedium,
	ActionVEXStatementImported: SeverityHigh,
	ActionVEXStatementApplied:  SeverityMedium,
})

func init() {
	configResourceTypes[ResourceTypeVEXStatement] = struct{}{}
}
