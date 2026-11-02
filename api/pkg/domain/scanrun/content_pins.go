package scanrun

import "encoding/json"

// ContentPins is what a task's job read (docs/architecture/wordlists.md,
// "What a run used"): the packs it pinned by digest and the lists generated
// for it. The platform writes it when it signs the job for a sensor, from
// what it signed; nothing of it comes from a sensor.
type ContentPins struct {
	Packs  []PinnedPack  `json:"packs,omitempty"`
	Inputs []PinnedInput `json:"inputs,omitempty"`
	// Rules are the detection rule sets the platform matched the task's
	// report with (docs/architecture/rule-packs.md), written at ingest.
	Rules []PinnedRules `json:"rules,omitempty"`
}

// PinnedRules is one detection rule set a report was matched with: a
// platform pack (name, version, digest) or the organization's own rules
// (the sha256 of their ids and versions).
type PinnedRules struct {
	Kind    string `json:"kind"`
	Scope   string `json:"scope"`
	Pack    string `json:"pack,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest"`
	Rules   int    `json:"rules"`
}

// PinnedPack is a pack a job pinned.
type PinnedPack struct {
	Slot    string `json:"slot"`
	Scope   string `json:"scope"`
	Pack    string `json:"pack"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest"`
}

// Sources of a generated list.
const (
	// InputSourceLearned: labels learned from the organization's own names,
	// and their permutations.
	InputSourceLearned = "learned"
	// InputSourceOrganization: the organization's enabled wordlists.
	InputSourceOrganization = "organization"
)

// PinnedInput is a list generated for a job and carried inline.
type PinnedInput struct {
	Slot    string `json:"slot"`
	Purpose string `json:"purpose"`
	Source  string `json:"source,omitempty"`
	SHA256  string `json:"sha256"`
	Lines   int    `json:"lines"`
	// Lists are the organization lists the input was built from, with the
	// version each had.
	Lists []PinnedList `json:"lists,omitempty"`
}

// PinnedList is one organization list in an input.
type PinnedList struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
}

// Bounds of a stored record.
const (
	maxPinnedPacks  = 8
	maxPinnedInputs = 8
	maxPinnedLists  = 20
	// MaxPinnedRules bounds the rule sets one record names.
	MaxPinnedRules = 16
)

// ParseContentPins decodes a stored record; nil when there is none or it
// does not decode. Counts are bounded.
func ParseContentPins(raw []byte) *ContentPins {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var p ContentPins
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil
	}
	p.Packs = p.Packs[:min(len(p.Packs), maxPinnedPacks)]
	p.Inputs = p.Inputs[:min(len(p.Inputs), maxPinnedInputs)]
	p.Rules = p.Rules[:min(len(p.Rules), MaxPinnedRules)]
	for i := range p.Inputs {
		p.Inputs[i].Lists = p.Inputs[i].Lists[:min(len(p.Inputs[i].Lists), maxPinnedLists)]
	}
	if len(p.Packs) == 0 && len(p.Inputs) == 0 && len(p.Rules) == 0 {
		return nil
	}
	return &p
}
