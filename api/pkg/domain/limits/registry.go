package limits

// The one registry of entitlement keys: every limit key and every named
// feature has a description here, and nothing else may be used as a key
// (tests/unit/entitlement_keys_test.go fails on an unregistered or
// undescribed key, and on a key built from a string literal). Module
// features take their description from the module registry. A paid feature
// registers its key here and is checked through the entitlement service.

// KeyDescriptions describes every limit key (what it counts or bounds).
var KeyDescriptions = map[Key]string{
	Seats:                        "members who are not offboarded",
	Assets:                       "assets not deleted and not archived",
	Sensors:                      "the organization's own sensors that are not revoked",
	APIKeys:                      "active API keys",
	CITrusts:                     "CI trust configurations",
	InvitesPerDay:                "invitations created in the last 24 hours",
	PlatformScansPerDay:          "scans started on shared sensors since 00:00 UTC",
	PlatformScansConcurrent:      "shared-sensor jobs queued or running at once",
	Findings:                     "the organization's findings (new fingerprints)",
	LifecycleSubStatuses:         "finding sub-statuses that are not archived",
	LifecycleSchemes:             "finding lifecycle schemes that are not archived",
	StorageMB:                    "MiB of uploaded files the organization holds",
	OrgsPerUser:                  "organizations one person may own when creating one themselves",
	DashboardRefreshFloorMinutes: "floor: the shortest dashboard refresh cadence in minutes",
	ContentSources:               "the organization's own rule sources the platform fetches",
	ContentStorageMB:             "MiB of rule source snapshots the platform holds",
	ContentSyncFloorMinutes:      "floor: the shortest sync interval of a rule source in minutes",
	ContentSnapshotMaxMB:         "per-item cap: the largest rule source snapshot in MiB",
}

// NamedFeatureDescriptions describes every named feature below module level.
var NamedFeatureDescriptions = map[string]string{
	FeatureActiveScanning:      "sending active or intrusive probes (scan tiers above passive) from any sensor",
	FeatureSSOConnections:      "configuring per-organization SAML and OIDC connections",
	FeatureSSOEnforcement:      "requiring SSO sign-in for members",
	FeatureSCIM:                "SCIM provisioning (tokens and the SCIM API)",
	FeatureSSOGroupLinks:       "identity-provider group to role links",
	FeatureLDAP:                "LDAP sign-in (reserved, not built)",
	FeatureContentWebhook:      "push-triggered sync of a rule source",
	FeatureContentReviewPolicy: "the review promotion policy of a rule source",
	FeatureContentPrivateGit:   "rule sources on hosts in an allowed private network",
}
