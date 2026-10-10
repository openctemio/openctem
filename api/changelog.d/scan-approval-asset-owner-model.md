### Added: asset owners as scan approvers (design and model)

- RFC-073 §10 designs asset owners as approvers: each owner approves the part of a scan's targets they own, a fallback group approves the rest. The model (`approver_source`, `fallback_group_id`, owner parts) is in place; saving a rule with `asset_owners` is refused until the request and gate paths enforce it.
