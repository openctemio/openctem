package vulnbundle

// The exploitation signals (CISA KEV and FIRST EPSS) travel next to each
// release as a signed side manifest: intel.manifest.dsse.json names one
// entries file per stream with SHA-256, size and record count, the data date
// of the stream (as_of), when the collector last read the source
// (fetched_at) and the bundle sequence the manifest was built with. The
// corpus format is untouched, so a platform that does not know the manifest
// ignores it. Design: research on threat intel feeds, "intel sidecar".
//
// A platform applies a stream it knows and skips (and reports) a stream name
// it does not know: the manifest is signed, so skipping is safe.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/feedsign"
)

// Intel side manifest format (must match the collector).
const (
	IntelManifestPayloadType = "application/vnd.openctem.vulnfeed.intel+json"
	IntelSchema              = "openctem.vulnfeed.intel/v1"
	IntelManifestFile        = "intel.manifest.dsse.json"
	// Stream names this platform knows.
	IntelStreamKEV  = "kev"
	IntelStreamEPSS = "epss"
	// Caps (the collector enforces the same).
	MaxIntelKEVRecords   = 20_000
	MaxIntelEPSSRecords  = 1_500_000
	MaxIntelKEVBytes     = 8 << 20
	MaxIntelEPSSBytes    = 64 << 20
	maxIntelStreams      = 16
	maxIntelStringLength = 4096
)

var (
	intelStreamRe = regexp.MustCompile(`^[a-z0-9]{1,24}$`)
	intelCVERe    = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
)

// IntelStream describes one signed stream.
type IntelStream struct {
	Name        string    `json:"name"`
	AsOf        time.Time `json:"as_of"`
	FetchedAt   time.Time `json:"fetched_at"`
	Version     string    `json:"version"`
	Attribution string    `json:"attribution"`
	File        File      `json:"file"`
}

// IntelManifest is the signed description of the side files.
type IntelManifest struct {
	Schema    string        `json:"schema"`
	Sequence  uint64        `json:"sequence"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	Streams   []IntelStream `json:"streams"`
}

// Stream returns the named stream, or nil.
func (m *IntelManifest) Stream(name string) *IntelStream {
	for i := range m.Streams {
		if m.Streams[i].Name == name {
			return &m.Streams[i]
		}
	}
	return nil
}

// IntelFileName is the entries file name of a stream.
func IntelFileName(stream string) string { return "intel-" + stream + ".jsonl.gz" }

// VerifyIntelManifest checks the side manifest against the verified key
// set: the signature, the schema, that it was built for the release
// sequence the importer applied (an old manifest cannot be replayed with a
// new bundle), its validity window, and that every stream is well formed
// (a safe name, its own entries file, a data date that is not in the
// future, a fetch time inside the validity window).
func VerifyIntelManifest(ks *KeySet, raw []byte, sequence uint64, now time.Time) (*IntelManifest, error) {
	var m IntelManifest
	if err := feedsign.VerifyWith(ks, raw, IntelManifestPayloadType, MaxManifestBytes, &m); err != nil {
		return nil, fmt.Errorf("intel manifest: %w", err)
	}
	switch {
	case m.Schema != IntelSchema:
		return nil, fmt.Errorf("intel manifest: schema %q", m.Schema)
	case m.Sequence != sequence:
		return nil, fmt.Errorf("intel manifest: built for sequence %d, the applied release is %d", m.Sequence, sequence)
	case m.ExpiresAt.Sub(m.CreatedAt) > MaxBundleValidity || !now.Before(m.ExpiresAt) || m.CreatedAt.After(now.Add(time.Hour)):
		return nil, errors.New("intel manifest: expired or outside its validity window")
	case len(m.Streams) == 0 || len(m.Streams) > maxIntelStreams:
		return nil, errors.New("intel manifest: no streams or too many")
	}
	seen := map[string]bool{}
	for _, s := range m.Streams {
		switch {
		case !intelStreamRe.MatchString(s.Name) || seen[s.Name] || s.File.Name != IntelFileName(s.Name):
			return nil, fmt.Errorf("intel manifest: stream %q is malformed or repeated", s.Name)
		case s.AsOf.IsZero() || s.AsOf.After(now.Add(48*time.Hour)):
			return nil, fmt.Errorf("intel manifest: stream %q has no data date or one in the future", s.Name)
		case s.FetchedAt.IsZero() || s.FetchedAt.After(m.CreatedAt.Add(time.Hour)) || s.FetchedAt.Before(m.CreatedAt.Add(-MaxBundleValidity)):
			return nil, fmt.Errorf("intel manifest: stream %q has a fetch time outside the release's window", s.Name)
		case s.File.Size < 0 || s.File.Records < 0:
			return nil, fmt.Errorf("intel manifest: stream %q has a negative size", s.Name)
		}
		seen[s.Name] = true
	}
	return &m, nil
}

type intelKEVLine struct {
	CVE         string   `json:"cve"`
	Vendor      string   `json:"vendor"`
	Product     string   `json:"product"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	DateAdded   string   `json:"date_added"`
	DueDate     string   `json:"due_date,omitempty"`
	Ransomware  string   `json:"ransomware"`
	Notes       string   `json:"notes,omitempty"`
	CWEs        []string `json:"cwes"`
}

type intelEPSSLine struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

func openIntelStream(gz []byte, s *IntelStream, maxBytes int64, maxRecords int) (*gzip.Reader, error) {
	if s.File.Size > maxBytes || s.File.Records < 0 || s.File.Records > maxRecords {
		return nil, fmt.Errorf("intel %s: over the caps", s.Name)
	}
	sum := sha256.Sum256(gz)
	if int64(len(gz)) != s.File.Size || hex.EncodeToString(sum[:]) != s.File.SHA256 {
		return nil, fmt.Errorf("intel %s: size or SHA-256 does not match the manifest", s.Name)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("intel %s: %w", s.Name, err)
	}
	return zr, nil
}

func validIntelCVE(id string) bool {
	return len(id) <= 32 && intelCVERe.MatchString(id)
}

// ParseIntelKEV checks the KEV entries file against the verified manifest
// (size and SHA-256) and decodes it: every line strictly, ids ascending and
// unique, the count as the manifest states.
func ParseIntelKEV(gz []byte, s *IntelStream) ([]*threatintel.KEVEntry, error) {
	zr, err := openIntelStream(gz, s, MaxIntelKEVBytes, MaxIntelKEVRecords)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := make([]*threatintel.KEVEntry, 0, s.File.Records)
	last := ""
	err = scanLines(&limited{r: zr, left: 8 * MaxIntelKEVBytes}, func(line []byte) error {
		var e intelKEVLine
		if err := feedsign.DecodeStrict(line, &e); err != nil {
			return err
		}
		if len(out) >= s.File.Records {
			return errors.New("more entries than the manifest states")
		}
		if !validIntelCVE(e.CVE) || e.CVE <= last {
			return fmt.Errorf("entry %q is malformed, repeated or out of order", e.CVE)
		}
		last = e.CVE
		added, err := time.Parse("2006-01-02", e.DateAdded)
		if err != nil {
			return fmt.Errorf("entry %s: date_added: %w", e.CVE, err)
		}
		var due time.Time
		if e.DueDate != "" {
			if due, err = time.Parse("2006-01-02", e.DueDate); err != nil {
				return fmt.Errorf("entry %s: due_date: %w", e.CVE, err)
			}
		}
		for _, f := range []string{e.Vendor, e.Product, e.Name, e.Description, e.Ransomware, e.Notes} {
			if len(f) > maxIntelStringLength {
				return fmt.Errorf("entry %s: a field is over %d bytes", e.CVE, maxIntelStringLength)
			}
		}
		cwes := make([]string, 0, len(e.CWEs))
		for _, c := range e.CWEs {
			if c != "" && c != "NVD-CWE-noinfo" && len(c) <= 32 {
				cwes = append(cwes, c)
			}
		}
		out = append(out, threatintel.NewKEVEntry(e.CVE, e.Vendor, e.Product, e.Name, e.Description,
			added, due, e.Ransomware, e.Notes, cwes))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("intel kev: %w", err)
	}
	if len(out) != s.File.Records {
		return nil, fmt.Errorf("intel kev: %d entries, the manifest states %d", len(out), s.File.Records)
	}
	return out, nil
}

// ParseIntelEPSS checks the EPSS entries file against the verified manifest
// and decodes it into scores dated at the stream's data date. The published
// percentile is a fraction; the platform stores it on a 0-100 scale.
func ParseIntelEPSS(gz []byte, s *IntelStream) ([]*threatintel.EPSSScore, error) {
	zr, err := openIntelStream(gz, s, MaxIntelEPSSBytes, MaxIntelEPSSRecords)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := make([]*threatintel.EPSSScore, 0, s.File.Records)
	last := ""
	date := s.AsOf.UTC().Truncate(24 * time.Hour)
	err = scanLines(&limited{r: zr, left: 8 * MaxIntelEPSSBytes}, func(line []byte) error {
		var e intelEPSSLine
		if err := feedsign.DecodeStrict(line, &e); err != nil {
			return err
		}
		if len(out) >= s.File.Records {
			return errors.New("more entries than the manifest states")
		}
		if !validIntelCVE(e.CVE) || e.CVE <= last {
			return fmt.Errorf("entry %q is malformed, repeated or out of order", e.CVE)
		}
		if !(e.Score >= 0 && e.Score <= 1 && e.Percentile >= 0 && e.Percentile <= 1) {
			return fmt.Errorf("entry %s: a score is outside 0-1", e.CVE)
		}
		last = e.CVE
		out = append(out, threatintel.NewEPSSScore(e.CVE, e.Score, e.Percentile*100, clipModel(s.Version), date))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("intel epss: %w", err)
	}
	if len(out) != s.File.Records {
		return nil, fmt.Errorf("intel epss: %d entries, the manifest states %d", len(out), s.File.Records)
	}
	return out, nil
}

// clipModel fits the model version into the column (varchar 20).
func clipModel(v string) string {
	if len(v) > 20 {
		return v[:20]
	}
	return v
}
