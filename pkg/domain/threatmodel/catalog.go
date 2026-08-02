package threatmodel

// The catalog types are read-only projections of the global seed tables
// (attack_technique_mitigations, technique_applicability). They are tenant-
// agnostic and versioned by dataset_version (e.g. "attack-16.1"). See migration
// 000190 for the seed data and its MITRE ATT&CK attribution.

// DefaultDatasetVersion is the ATT&CK dataset version the seeded catalog uses.
// Models record which version their threats were computed against.
const DefaultDatasetVersion = "attack-16.1"

// TechniqueMitigation is one technique → MITRE M-series mitigation mapping.
type TechniqueMitigation struct {
	TechniqueID       string
	TechniqueName     string
	Tactic            string
	MitigationID      string
	MitigationName    string
	MitigationSummary string
	DatasetVersion    string
}

// TechniqueApplicability describes at which asset-type / edge / attacker
// capability a technique applies. MinNetwork/MinCredential express the minimum
// attacker capability that unlocks the technique; EdgeType may be empty to mean
// "any incoming edge".
type TechniqueApplicability struct {
	TechniqueID         string
	AssetType           string
	EdgeType            string // "" = any edge (stored NULL)
	MinNetwork          string // external|internal ("" = none required)
	MinCredential       string // none|user|admin ("" = none required)
	RequiresPersistence bool
	DatasetVersion      string
}
