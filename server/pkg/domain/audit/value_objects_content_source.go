package audit

// Rule sources (docs/architecture/content-sources.md).

const (
	ActionContentSourceCreated           Action = "content_source.created"
	ActionContentSourceUpdated           Action = "content_source.updated"
	ActionContentSourceDeleted           Action = "content_source.deleted"
	ActionContentSourceCredentialSet     Action = "content_source.credential_set"
	ActionContentSourceCredentialCleared Action = "content_source.credential_cleared"
	ActionContentSourceWebhookSet        Action = "content_source.webhook_set"
	ActionContentSourcePolicyChanged     Action = "content_source.policy_changed"
	ActionContentSourceSyncRequested     Action = "content_source.sync_requested"
	ActionContentSourceSynced            Action = "content_source.synced"
	ActionContentSourceSyncFailed        Action = "content_source.sync_failed"
	ActionContentSourcePromoted          Action = "content_source.promoted"
	ActionContentSourceRejected          Action = "content_source.rejected"
	ActionContentSourceRolledBack        Action = "content_source.rolled_back"
)

// ResourceTypeContentSource is a rule source.
const ResourceTypeContentSource ResourceType = "content_source"

var _ = registerActions("content_source", map[Action]Severity{
	ActionContentSourceCreated:           SeverityMedium,
	ActionContentSourceUpdated:           SeverityMedium,
	ActionContentSourceDeleted:           SeverityHigh,
	ActionContentSourceCredentialSet:     SeverityHigh,
	ActionContentSourceCredentialCleared: SeverityMedium,
	ActionContentSourceWebhookSet:        SeverityMedium,
	ActionContentSourcePolicyChanged:     SeverityHigh,
	ActionContentSourceSyncRequested:     SeverityLow,
	ActionContentSourceSynced:            SeverityLow,
	ActionContentSourceSyncFailed:        SeverityMedium,
	ActionContentSourcePromoted:          SeverityHigh,
	ActionContentSourceRejected:          SeverityMedium,
	ActionContentSourceRolledBack:        SeverityHigh,
})

func init() {
	configResourceTypes[ResourceTypeContentSource] = struct{}{}
}
