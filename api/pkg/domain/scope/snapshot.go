package scope

// Scope snapshot of a scan run (RFC-065 §9): the authority a run relied on
// when it started, in a canonical form, with its SHA-256. It is the evidence
// a researcher shows a program or an abuse desk: which entries covered the
// run's targets (with their source and program), the program exclusions of
// those programs, and each program's attestation.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

// SnapshotEntry is one entry that covered a target of the run.
type SnapshotEntry struct {
	ID         string     `json:"id"`
	TargetType string     `json:"target_type"`
	Pattern    string     `json:"pattern"`
	Source     string     `json:"authorization_source"`
	ProgramID  string     `json:"program_id,omitempty"`
	MaxTier    string     `json:"max_tier"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
}

// SnapshotProgram is the attestation in force for a program whose entries
// covered a target of the run.
type SnapshotProgram struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	ProgramURL  string     `json:"program_url"`
	TermsSHA256 string     `json:"terms_sha256"`
	AcceptedBy  string     `json:"accepted_by,omitempty"`
	AcceptedAt  *time.Time `json:"accepted_at,omitempty"`
	// Exclusions are the program's out-of-scope patterns ("type:pattern").
	Exclusions []string `json:"exclusions"`
}

// Snapshot is the scope a run relied on.
type Snapshot struct {
	Version  int               `json:"version"`
	Targets  int               `json:"targets"`
	Entries  []SnapshotEntry   `json:"entries"`
	Programs []SnapshotProgram `json:"programs"`
	// Uncovered counts targets no entry covered (internal, zone-gated or
	// refused later by the dispatch gate).
	Uncovered int `json:"uncovered"`
}

// SnapshotVersion is the format version of a snapshot body.
const SnapshotVersion = 1

// Canonical sorts the snapshot and returns its JSON and SHA-256 (hex).
// Identical scope gives an identical body and hash.
func (s *Snapshot) Canonical() ([]byte, string, error) {
	s.Version = SnapshotVersion
	if s.Entries == nil {
		s.Entries = []SnapshotEntry{}
	}
	if s.Programs == nil {
		s.Programs = []SnapshotProgram{}
	}
	sort.Slice(s.Entries, func(i, j int) bool { return s.Entries[i].ID < s.Entries[j].ID })
	sort.Slice(s.Programs, func(i, j int) bool { return s.Programs[i].ID < s.Programs[j].ID })
	for i := range s.Programs {
		if s.Programs[i].Exclusions == nil {
			s.Programs[i].Exclusions = []string{}
		}
		sort.Strings(s.Programs[i].Exclusions)
	}
	for i := range s.Entries {
		s.Entries[i].ExpiresAt = utc(s.Entries[i].ExpiresAt)
		s.Entries[i].ApprovedAt = utc(s.Entries[i].ApprovedAt)
	}
	for i := range s.Programs {
		s.Programs[i].AcceptedAt = utc(s.Programs[i].AcceptedAt)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC().Truncate(time.Microsecond)
	return &v
}
