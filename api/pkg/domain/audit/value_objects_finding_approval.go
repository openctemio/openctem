package audit

// Finding status approvals: a false positive or an accepted risk needs a
// second person (api/docs/architecture/finding-status-lifecycle.md). The
// resource is the request (finding_approval); its finding is in the metadata.
const (
	// ResourceTypeFindingApproval is a finding status request
	// (finding_status_approvals).
	ResourceTypeFindingApproval ResourceType = "finding_approval"

	ActionFindingApprovalRequested Action = "finding_approval.requested"
	ActionFindingApprovalApproved  Action = "finding_approval.approved"
	ActionFindingApprovalRejected  Action = "finding_approval.rejected"
	ActionFindingApprovalCanceled  Action = "finding_approval.canceled"
	// ActionFindingApprovalReminded: someone reminded the approvers.
	ActionFindingApprovalReminded Action = "finding_approval.reminded"
	// ActionFindingApprovalExpired: nobody decided the request by its
	// decide-by time (written by the expiration job).
	ActionFindingApprovalExpired Action = "finding_approval.expired"
	// ActionFindingApprovalSelfRefused: a requester tried to approve their
	// own request and was refused (a signal for abuse or a misunderstanding).
	ActionFindingApprovalSelfRefused Action = "finding_approval.self_approval_refused"
	// ActionFindingApprovalSelfApproved: the sole member of the organization
	// approved their own request (fresh authenticator code and a reason).
	ActionFindingApprovalSelfApproved Action = "finding_approval.self_approved"
	// ActionFindingApprovalSettingsChanged: the organization's finding
	// approval settings changed (step-up; old and new values).
	ActionFindingApprovalSettingsChanged Action = "finding_approval.settings_changed"
	// ActionFindingApprovalSinglePerson: one person decided a false
	// positive alone because the organization's level allowed it.
	ActionFindingApprovalSinglePerson Action = "finding_approval.single_person_decided"
	// ActionFindingApprovalSigned: one approval of a request that needs
	// more than one approver (the request stays pending).
	ActionFindingApprovalSigned Action = "finding_approval.signed"
	// ActionFindingApprovalRefused: the approval policy refused an approver
	// (asset owner, assignee, not in the security pool, signed already, or
	// not enough eligible approvers).
	ActionFindingApprovalRefused Action = "finding_approval.approval_refused"
	// Group exceptions (RFC-111 §7): one approval of a group exception
	// (pending or applied), its rejection and its cancellation.
	ActionFindingApprovalBatchApproved Action = "finding_approval.batch_approved"
	ActionFindingApprovalBatchSigned   Action = "finding_approval.batch_signed"
	ActionFindingApprovalBatchRejected Action = "finding_approval.batch_rejected"
	ActionFindingApprovalBatchCanceled Action = "finding_approval.batch_canceled"
)

var _ = registerActions("finding_approval", map[Action]Severity{
	ActionFindingApprovalRequested:       SeverityMedium,
	ActionFindingApprovalApproved:        SeverityMedium,
	ActionFindingApprovalRejected:        SeverityMedium,
	ActionFindingApprovalCanceled:        SeverityLow,
	ActionFindingApprovalReminded:        SeverityLow,
	ActionFindingApprovalExpired:         SeverityLow,
	ActionFindingApprovalSelfRefused:     SeverityMedium,
	ActionFindingApprovalSelfApproved:    SeverityHigh,
	ActionFindingApprovalSettingsChanged: SeverityHigh,
	ActionFindingApprovalSinglePerson:    SeverityMedium,
	ActionFindingApprovalSigned:          SeverityMedium,
	ActionFindingApprovalRefused:         SeverityMedium,
	ActionFindingApprovalBatchApproved:   SeverityMedium,
	ActionFindingApprovalBatchSigned:     SeverityMedium,
	ActionFindingApprovalBatchRejected:   SeverityMedium,
	ActionFindingApprovalBatchCanceled:   SeverityLow,
})
