package audit

// Evidence files (attachments): adding and removing one is recorded with the
// file's SHA-256, so the evidence of a finding has a chain of custody.

const (
	ActionAttachmentUploaded Action = "attachment.uploaded"
	ActionAttachmentDeleted  Action = "attachment.deleted"
)

// ResourceTypeAttachment is an uploaded evidence file.
const ResourceTypeAttachment ResourceType = "attachment"

var _ = registerActions("attachment", map[Action]Severity{
	ActionAttachmentUploaded: SeverityLow,
	ActionAttachmentDeleted:  SeverityMedium,
})

func init() {
	configResourceTypes[ResourceTypeAttachment] = struct{}{}
}
