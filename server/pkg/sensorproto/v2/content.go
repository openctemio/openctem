package v2

// Content a job pins (RFC-061 §3.7). The platform puts these members in the
// copy of a scan or retest command it hands the claiming sensor, and the job
// signature covers them through payload_sha256. The signed statement lists the
// packs (jobsign.Statement.Content); a sensor mounts only packs that
// statement lists and checks each against the content keys it pinned at
// pairing.

import "encoding/json"

// Payload members of a job's content.
const (
	PayloadKeyContent = "content"
	PayloadKeyInputs  = "inputs"
)

// Bounds of a job's content, as the sensor enforces them.
const (
	// MaxJobContent and MaxJobInputs bound the members of a payload.
	MaxJobContent = 8
	MaxJobInputs  = 8
	// MaxJobContentFiles bounds the files one pack item names.
	MaxJobContentFiles = 64
	// MaxJobInputGzipBytes is the largest compressed inline list and
	// MaxJobInputsGzipTotal the most all of a job's inline lists may take.
	MaxJobInputGzipBytes  = 256 << 10
	MaxJobInputsGzipTotal = 512 << 10
	// MaxJobInputExpandedBytes is the most one inline list may expand to.
	MaxJobInputExpandedBytes = 8 << 20
)

// Content scopes: which pinned key signs the pack.
const (
	ContentScopePlatform = "platform"
	ContentScopeTenant   = "tenant"
)

// JobContent is one pack a job names (payload "content").
type JobContent struct {
	// Slot is the tool's content slot ("labels").
	Slot string `json:"slot"`
	// Kind is the pack's content kind ("wordlist").
	Kind string `json:"kind,omitempty"`
	// Scope is "platform" or "tenant".
	Scope string `json:"scope"`
	// Pack is the pack's name.
	Pack string `json:"pack"`
	// Digest is the pack's "sha256:<hex>" content address.
	Digest string `json:"digest"`
	// Size is the canonical archive's size in bytes.
	Size int64 `json:"size,omitempty"`
	// Files are the files of the pack the slot uses.
	Files []string `json:"files,omitempty"`
	// MaxLines caps the composed wordlist.
	MaxLines int `json:"max_lines,omitempty"`
	// Signature is the pack's DSSE envelope.
	Signature json.RawMessage `json:"signature"`
	// Version is the pack's version, for the platform's record of what the
	// job read. It never travels to the sensor.
	Version string `json:"-"`
}

// JobInput is a list the platform generated for one job (payload "inputs"):
// the organization's own data, written only to the task directory and erased
// with it, never put in a content cache.
type JobInput struct {
	Slot    string `json:"slot"`
	Purpose string `json:"purpose"`
	// SHA256 is the lower-case hex SHA-256 of the list as it reads
	// decompressed.
	SHA256 string `json:"sha256"`
	Lines  int    `json:"lines,omitempty"`
	// Data is the gzip-compressed list (standard base64 in JSON).
	Data []byte `json:"data_b64"`
	// Source and Lists are for the platform's record of what the job read
	// (where the list came from, and the organization lists with their
	// versions). They never travel to the sensor.
	Source string         `json:"-"`
	Lists  []InputListRef `json:"-"`
}

// InputListRef is an organization list a generated list was built from.
type InputListRef struct {
	ID      string
	Name    string
	Version int
	SHA256  string
}
