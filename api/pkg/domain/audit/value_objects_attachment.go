package audit

// Evidence files (attachments): adding and removing one is recorded with the
// file's SHA-256, so the evidence of a finding has a chain of custody.

const (
	ActionAttachmentUploaded Action = "attachment.uploaded"
	ActionAttachmentDeleted  Action = "attachment.deleted"
	// ActionAttachmentPurged: the retention sweep removed a file whose
	// finding or campaign was deleted, or that was never linked to one.
	ActionAttachmentPurged Action = "attachment.purged"
	// ActionAttachmentMalwareDetected: the malware scanner flagged a file.
	ActionAttachmentMalwareDetected Action = "attachment.malware_detected"
	// ActionAttachmentInfectedDownloaded: a member downloaded a flagged file
	// after confirming.
	ActionAttachmentInfectedDownloaded Action = "attachment.infected_downloaded"
)

// ResourceTypeAttachment is an uploaded evidence file.
const ResourceTypeAttachment ResourceType = "attachment"

var _ = registerActions("attachment", map[Action]Severity{
	ActionAttachmentUploaded:           SeverityLow,
	ActionAttachmentDeleted:            SeverityMedium,
	ActionAttachmentPurged:             SeverityMedium,
	ActionAttachmentMalwareDetected:    SeverityHigh,
	ActionAttachmentInfectedDownloaded: SeverityHigh,
})

func init() {
	configResourceTypes[ResourceTypeAttachment] = struct{}{}
}
