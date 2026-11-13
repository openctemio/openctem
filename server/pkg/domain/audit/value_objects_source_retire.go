package audit

// Actions of retiring an import source
// (docs/architecture/source-retirement.md).
const (
	// ActionSourceRetired records an administrator stopping the use of an
	// import source: its data is refused and the findings only it reported
	// are archived as source retired.
	ActionSourceRetired Action = "import_source.retired"
	// ActionSourceRestored records the source used again and its archived
	// findings restored.
	ActionSourceRestored Action = "import_source.restored"
)

// ResourceTypeImportSource is a retired import source.
const ResourceTypeImportSource ResourceType = "import_source"

var _ = registerActions("import_source", map[Action]Severity{
	ActionSourceRetired:  SeverityHigh,
	ActionSourceRestored: SeverityHigh,
})
