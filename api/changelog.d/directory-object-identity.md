### Added: a renamed directory computer stays the same asset

- New strong, single-valued identifier kind `directory_object_id`: the Active Directory objectGUID of a computer, read from the `ad_object_guid` property the directory collector sends (also `object_guid`, `directory_object_id`). A computer renamed or moved in the directory matches its existing asset instead of becoming a second one; two different objectGUIDs on one name veto a match like other single-valued kinds.
- Migration 002083 widens the `asset_identifiers` kind and strong CHECK constraints. The vCenter instance UUID was already the `cloud_id` identifier.
- Matching stays inside the tenant: the same objectGUID in another organization is a different asset.
