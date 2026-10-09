package audit

// Content packs (docs/rfcs/RFC-061-content-packs.md).

const (
	ActionContentPackCreated Action = "content_pack.created"
	ActionContentPackRevoked Action = "content_pack.revoked"
)

// ResourceTypeContentPack is a content pack.
const ResourceTypeContentPack ResourceType = "content_pack"

var _ = registerActions("content_pack", map[Action]Severity{
	ActionContentPackCreated: SeverityMedium,
	ActionContentPackRevoked: SeverityHigh,
})

func init() {
	configResourceTypes[ResourceTypeContentPack] = struct{}{}
}
