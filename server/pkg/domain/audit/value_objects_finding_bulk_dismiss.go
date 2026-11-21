package audit

// Bulk dismiss of findings (docs/architecture/findings-bulk-by-filter.md,
// "Bulk dismiss"): one event per bulk, beside the per-finding rows of the
// decisions it made (finding_approval.single_person_decided) and the group it
// asked for. The resource is the bulk dismissal; its counts, filter hash and
// group are in the metadata.
const (
	// ResourceTypeFindingBulkDismissal is one bulk dismissal
	// (finding_bulk_dismissals).
	ResourceTypeFindingBulkDismissal ResourceType = "finding_bulk_dismissal"

	// ActionFindingsBulkDismissed: a person dismissed findings in bulk. The
	// event is raised to high severity when more than 100 were decided alone.
	ActionFindingsBulkDismissed Action = "finding.bulk_dismissed"
	// ActionFindingsBulkDismissUndone: the person undid their bulk dismissal
	// (findings decided alone reopened, its pending group canceled).
	ActionFindingsBulkDismissUndone Action = "finding.bulk_dismiss_undone"
)

var _ = registerActions("finding", map[Action]Severity{
	ActionFindingsBulkDismissed:     SeverityMedium,
	ActionFindingsBulkDismissUndone: SeverityMedium,
})

func init() {
	configResourceTypes[ResourceTypeFindingBulkDismissal] = struct{}{}
}
