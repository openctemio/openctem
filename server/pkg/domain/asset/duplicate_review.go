package asset

// Reasons a duplicate-asset review is raised. A review never merges by
// itself: an operator approves or rejects it (/api/v1/assets/dedup/reviews).
const (
	DuplicateReasonSharedIP           = "shared_ip"           // ingest: an IP matched several assets
	DuplicateReasonIdentifierConflict = "identifier_conflict" // ingest: identifiers point at different assets
	DuplicateReasonSharedIdentifier   = "shared_identifier"   // backfill: two assets carry one strong identifier
	DuplicateReasonRenamedHost        = "renamed_host"        // backfill: one scanner saw one IP under two names
)

// DuplicateReview proposes merging MergeIDs into KeepID.
type DuplicateReview struct {
	Reason            string
	Evidence          map[string]any
	NormalizedName    string
	AssetType         string
	KeepID            string
	KeepName          string
	KeepFindingCount  int
	MergeIDs          []string
	MergeNames        []string
	MergeFindingCount int
}
