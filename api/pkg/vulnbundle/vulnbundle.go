// Package vulnbundle verifies and reads the signed vulnerability bundles
// the collector publishes (openctemio/vulnfeed).
//
// Design: docs/rfcs/RFC-066-inventory-vulnerability-matching.md §5.5. The
// envelope, pre-authentication encoding and key ids are those of signed
// jobs (pkg/jobsign); the key set has its own kind and a 180-day validity.
// Everything in a bundle is untrusted until verified: the key set against
// the pinned root, the pointer and manifests against the key set, every
// file against its manifest, every record with the platform's own parsers.
package vulnbundle

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
	"github.com/openctemio/openctem/api/pkg/feedsign"
)

// Format constants (must match the collector).
const (
	KeySetPayloadType   = "application/vnd.openctem.vulnfeed.keyset+json"
	KeySetKind          = "openctem.vulnfeed.keyset/v1"
	ManifestPayloadType = "application/vnd.openctem.vulnfeed.manifest+json"
	LatestPayloadType   = "application/vnd.openctem.vulnfeed.latest+json"
	ManifestSchema      = "openctem.vulnfeed/v1"
	LatestSchema        = "openctem.vulnfeed.latest/v1"
	KindSnapshot        = "snapshot"
	KindDelta           = "delta"
	LatestFile          = "latest.dsse.json"
	KeySetFile          = "keyset.dsse.json"
)

// Caps.
const (
	MaxKeySetValidity    = feedsign.MaxKeySetValidity
	MaxBundleValidity    = 7 * 24 * time.Hour
	MaxKeySetBytes       = 64 << 10
	MaxManifestBytes     = 1 << 20
	MaxFileBytes         = 512 << 20
	MaxDecompressedBytes = 2 << 30
	MaxRecordBytes       = 1 << 20
)

var recordFiles = []string{"products", "vulns", "ranges"}

// FileName is the name of a record file.
func FileName(kind, records string) string { return kind + "-" + records + ".jsonl.gz" }

// ManifestName is the manifest file of a kind.
func ManifestName(kind string) string { return kind + ".manifest.dsse.json" }

// Tag is the release tag of a sequence.
func Tag(sequence uint64) string { return fmt.Sprintf("v1-%d", sequence) }

// KeySet lists the online keys an offline root allows (the shared signed
// feed key set, pkg/feedsign).
type KeySet = feedsign.KeySet

// Source is one upstream source of a bundle.
type Source struct {
	Name        string    `json:"name"`
	AsOf        time.Time `json:"as_of"`
	Terms       string    `json:"terms"`
	Attribution string    `json:"attribution"`
}

// File is one record file of a manifest.
type File struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Records int    `json:"records"`
}

// Manifest describes a snapshot or a delta.
type Manifest struct {
	Schema       string    `json:"schema"`
	Sequence     uint64    `json:"sequence"`
	Kind         string    `json:"kind"`
	BaseSequence uint64    `json:"base_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Sources      []Source  `json:"sources"`
	Files        []File    `json:"files"`
	Stats        struct {
		Vulns         int `json:"vulns"`
		Ranges        int `json:"ranges"`
		Products      int `json:"products"`
		RangesAdded   int `json:"ranges_added"`
		RangesRemoved int `json:"ranges_removed"`
	} `json:"stats"`
	Collector struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	} `json:"collector"`
}

// Latest points at the newest bundle.
type Latest struct {
	Schema       string    `json:"schema"`
	Sequence     uint64    `json:"sequence"`
	Tag          string    `json:"tag"`
	Snapshot     string    `json:"snapshot"`
	Delta        string    `json:"delta,omitempty"`
	BaseSequence uint64    `json:"base_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// VerifyKeySet checks a key set envelope: signed by its root, the root is
// the pinned one, valid at now, version not below minVersion
// (feedsign.VerifyKeySet with this feed's payload type and kind).
func VerifyKeySet(envelope []byte, pinnedRoot string, minVersion uint64, now time.Time) (*KeySet, error) {
	return feedsign.VerifyKeySet(envelope, feedsign.KeySetType{PayloadType: KeySetPayloadType, Kind: KeySetKind},
		pinnedRoot, minVersion, now)
}

// verifyWith checks an envelope against the key set and decodes it.
func verifyWith(ks *KeySet, raw []byte, payloadType string, v any) error {
	return feedsign.VerifyWith(ks, raw, payloadType, MaxManifestBytes, v)
}

// Verified is a bundle whose envelopes and files checked out.
type Verified struct {
	Dir      string
	KeySet   *KeySet
	Latest   Latest
	Snapshot Manifest
	Delta    *Manifest
}

// Options are the platform's state at verification.
type Options struct {
	PinnedRoot   string
	MinKeySetVer uint64
	AppliedSeq   uint64
	Now          time.Time
}

// ErrNotNewer: the bundle is not newer than what is applied (nothing to do,
// or a rollback).
var ErrNotNewer = errors.New("bundle is not newer than the applied sequence")

// VerifyPointer verifies the key set and the latest pointer in dir: the
// first step, before the (large) record files are fetched.
func VerifyPointer(dir string, opt Options) (*Verified, error) {
	ksRaw, err := readCapped(filepath.Join(dir, KeySetFile), MaxKeySetBytes)
	if err != nil {
		return nil, err
	}
	ks, err := VerifyKeySet(ksRaw, opt.PinnedRoot, opt.MinKeySetVer, opt.Now)
	if err != nil {
		return nil, err
	}
	v := &Verified{Dir: dir, KeySet: ks}
	raw, err := readCapped(filepath.Join(dir, LatestFile), MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	if err := verifyWith(ks, raw, LatestPayloadType, &v.Latest); err != nil {
		return nil, fmt.Errorf("latest: %w", err)
	}
	l := v.Latest
	switch {
	case l.Schema != LatestSchema:
		return nil, fmt.Errorf("latest: schema %q", l.Schema)
	case l.Sequence <= opt.AppliedSeq:
		return nil, fmt.Errorf("%w: %d <= %d", ErrNotNewer, l.Sequence, opt.AppliedSeq)
	case !l.ExpiresAt.After(opt.Now) || l.ExpiresAt.Sub(l.CreatedAt) > MaxBundleValidity:
		return nil, fmt.Errorf("latest: expired or valid too long (expires %s)", l.ExpiresAt.Format(time.RFC3339))
	case l.Tag != Tag(l.Sequence) || l.Snapshot != ManifestName(KindSnapshot) || (l.Delta != "" && l.Delta != ManifestName(KindDelta)):
		return nil, errors.New("latest: tag or file names")
	}
	return v, nil
}

// LoadManifest verifies one manifest of a pointer-verified bundle (its
// files are not checked yet).
func (v *Verified) LoadManifest(kind string) (*Manifest, error) {
	var m Manifest
	if err := v.manifestOnly(v.Dir, kind, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// VerifyDir verifies a whole bundle directory (downloaded or uploaded).
func VerifyDir(dir string, opt Options) (*Verified, error) {
	v, err := VerifyPointer(dir, opt)
	if err != nil {
		return nil, err
	}
	if err := v.manifest(dir, KindSnapshot, &v.Snapshot, opt.Now); err != nil {
		return nil, err
	}
	if v.Latest.Delta != "" {
		var d Manifest
		if err := v.manifest(dir, KindDelta, &d, opt.Now); err != nil {
			return nil, err
		}
		if d.BaseSequence != v.Latest.BaseSequence || d.BaseSequence >= d.Sequence {
			return nil, errors.New("delta: base sequence does not match the pointer")
		}
		v.Delta = &d
	}
	return v, nil
}

func (v *Verified) manifestOnly(dir, kind string, m *Manifest) error {
	raw, err := readCapped(filepath.Join(dir, ManifestName(kind)), MaxManifestBytes)
	if err != nil {
		return err
	}
	if err := verifyWith(v.KeySet, raw, ManifestPayloadType, m); err != nil {
		return fmt.Errorf("%s manifest: %w", kind, err)
	}
	if m.Schema != ManifestSchema || m.Kind != kind || m.Sequence != v.Latest.Sequence || len(m.Files) != len(recordFiles) {
		return fmt.Errorf("%s manifest: schema, kind, sequence or files", kind)
	}
	for i, f := range m.Files {
		if f.Name != FileName(kind, recordFiles[i]) || f.Size < 0 || f.Size > MaxFileBytes {
			return fmt.Errorf("%s manifest: file %q", kind, f.Name)
		}
	}
	return nil
}

func (v *Verified) manifest(dir, kind string, m *Manifest, now time.Time) error {
	if err := v.manifestOnly(dir, kind, m); err != nil {
		return err
	}
	if !m.ExpiresAt.After(now) || m.ExpiresAt.Sub(m.CreatedAt) > MaxBundleValidity {
		return fmt.Errorf("%s manifest: expired or valid too long", kind)
	}
	for _, f := range m.Files {
		if err := checkFile(filepath.Join(dir, f.Name), f); err != nil {
			return err
		}
	}
	return nil
}

func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is over %d bytes", filepath.Base(path), max)
	}
	return b, nil
}

func checkFile(path string, f File) error {
	if f.Size < 0 || f.Size > MaxFileBytes {
		return fmt.Errorf("%s: size over the cap", f.Name)
	}
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(fh, MaxFileBytes+1))
	if err != nil {
		return err
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("%s: size or SHA-256 does not match the manifest", f.Name)
	}
	return nil
}

// Records of one manifest, validated with the platform's parsers.
type Records struct {
	CVEs     []cvecorpus.CVE
	Products int
}

var (
	cveIDRE  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	cweRE    = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
	vectorRE = regexp.MustCompile(`^[A-Za-z0-9:/.\-_()]{1,200}$`)
)

type product struct {
	Key        string `json:"key"`
	Part       string `json:"part"`
	Vendor     string `json:"vendor"`
	Name       string `json:"name"`
	CPEVendor  string `json:"cpe_vendor"`
	CPEProduct string `json:"cpe_product"`
}

type vuln struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	Published   *time.Time `json:"published,omitempty"`
	Modified    *time.Time `json:"modified,omitempty"`
	Description string     `json:"description"`
	CVSS        *struct {
		Version string  `json:"version"`
		Score   float64 `json:"score"`
		Vector  string  `json:"vector"`
	} `json:"cvss,omitempty"`
	Severity string   `json:"severity,omitempty"`
	CWEs     []string `json:"cwes"`
}

type rng struct {
	Vuln      string `json:"vuln"`
	Product   string `json:"product"`
	Scheme    string `json:"scheme"`
	Exact     string `json:"exact,omitempty"`
	Start     string `json:"start,omitempty"`
	StartIncl bool   `json:"start_incl"`
	End       string `json:"end,omitempty"`
	EndIncl   bool   `json:"end_incl"`
	Edition   string `json:"edition"`
	Target    string `json:"target"`
	Condition string `json:"condition,omitempty"`
	Source    string `json:"source"`
}

// Read reads and validates the record files of a verified manifest. A
// bundle with a single invalid record is refused whole.
func (v *Verified) Read(m Manifest) (*Records, error) {
	products := map[string]vulnmatch.CPE{}
	byID := map[string]int{}
	out := &Records{}
	for i, f := range m.Files {
		kind := recordFiles[i]
		n := 0
		err := eachLine(filepath.Join(v.Dir, f.Name), func(line []byte) error {
			n++
			switch kind {
			case "products":
				key, c, err := ParseProduct(line)
				if err != nil {
					return err
				}
				if _, dup := products[key]; dup {
					return fmt.Errorf("product %s listed twice", key)
				}
				products[key] = c
			case "vulns":
				c, err := ParseVuln(line)
				if err != nil {
					return err
				}
				if _, dup := byID[c.ID]; dup {
					return fmt.Errorf("vuln %s listed twice", c.ID)
				}
				byID[c.ID] = len(out.CVEs)
				out.CVEs = append(out.CVEs, c)
			case "ranges":
				r, err := ParseRange(line)
				if err != nil {
					return err
				}
				vid := r.Range.Range.VulnID
				idx, ok := byID[vid]
				if !ok {
					return fmt.Errorf("range of %s, which is not in the bundle", vid)
				}
				if _, ok := products[r.ProductKey]; !ok {
					return fmt.Errorf("range of %s: product %s is not in the bundle", vid, r.ProductKey)
				}
				if _, ok := products[r.ConditionKey]; r.ConditionKey != "" && !ok {
					return fmt.Errorf("range of %s: condition %s is not in the bundle", vid, r.ConditionKey)
				}
				out.CVEs[idx].Ranges = append(out.CVEs[idx].Ranges, r.Range)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		if n != f.Records {
			return nil, fmt.Errorf("%s: %d records, the manifest says %d", f.Name, n, f.Records)
		}
	}
	out.Products = len(products)
	return out, nil
}

// ParseProduct decodes and validates one products record: its key and the
// CPE product it names.
func ParseProduct(line []byte) (string, vulnmatch.CPE, error) {
	var p product
	if err := feedsign.DecodeStrict(line, &p); err != nil {
		return "", vulnmatch.CPE{}, err
	}
	c, err := productCPE(p.Key)
	if err != nil || p.Part != c.Part || p.CPEVendor != c.Vendor || p.CPEProduct != c.Product {
		return "", vulnmatch.CPE{}, fmt.Errorf("product %q", p.Key)
	}
	return p.Key, c, nil
}

// ParseVuln decodes and validates one vulns record (without ranges).
func ParseVuln(line []byte) (cvecorpus.CVE, error) {
	var r vuln
	if err := feedsign.DecodeStrict(line, &r); err != nil {
		return cvecorpus.CVE{}, err
	}
	return toCVE(r)
}

// KeyedRange is one validated ranges record: its record id in a chunked
// bundle ("<vuln>#<digest>"), the product keys it names and the range.
type KeyedRange = cvecorpus.KeyedRange

// ParseRange decodes and validates one ranges record. Whether its
// vulnerability and products are in the same bundle is the caller's check.
func ParseRange(line []byte) (KeyedRange, error) {
	var r rng
	if err := feedsign.DecodeStrict(line, &r); err != nil {
		return KeyedRange{}, err
	}
	if !cveIDRE.MatchString(r.Vuln) {
		return KeyedRange{}, fmt.Errorf("range of vuln %q", r.Vuln)
	}
	cr, err := toRange(r)
	if err != nil {
		return KeyedRange{}, err
	}
	return KeyedRange{Key: rangeID(r), ProductKey: r.Product, ConditionKey: r.Condition, Range: cr}, nil
}

// rangeID is the record id the collector gives a range in a chunked
// bundle: the vulnerability id, "#", and the first 8 bytes of the SHA-256
// of the range's JSON encoding, hex.
func rangeID(r rng) string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return r.Vuln + "#" + hex.EncodeToString(sum[:8])
}

func productCPE(key string) (vulnmatch.CPE, error) {
	if !vulnmatch.ValidMatchKey(key) {
		return vulnmatch.CPE{}, fmt.Errorf("product key %q", key)
	}
	parts := strings.SplitN(strings.TrimPrefix(key, "cpe:"), ":", 3)
	return vulnmatch.CPE{Part: parts[0], Vendor: parts[1], Product: parts[2], Version: vulnmatch.Any,
		Update: vulnmatch.Any, SWEdition: vulnmatch.Any, TargetSW: vulnmatch.Any}, nil
}

func toCVE(r vuln) (cvecorpus.CVE, error) {
	switch {
	case !cveIDRE.MatchString(r.ID):
		return cvecorpus.CVE{}, fmt.Errorf("vuln id %q", r.ID)
	case len(r.Status) > 32 || len(r.Description) > 4000 || strings.ContainsAny(r.Description, "\x00\r\n"):
		return cvecorpus.CVE{}, fmt.Errorf("vuln %s: status or description", r.ID)
	case len(r.CWEs) > 16:
		return cvecorpus.CVE{}, fmt.Errorf("vuln %s: cwes", r.ID)
	}
	switch r.Severity {
	case "", "none", "low", "medium", "high", "critical":
	default:
		return cvecorpus.CVE{}, fmt.Errorf("vuln %s: severity %q", r.ID, r.Severity)
	}
	for _, c := range r.CWEs {
		if !cweRE.MatchString(c) {
			return cvecorpus.CVE{}, fmt.Errorf("vuln %s: cwe %q", r.ID, c)
		}
	}
	c := cvecorpus.CVE{ID: r.ID, Status: r.Status, Rejected: strings.EqualFold(r.Status, "Rejected"),
		Published: r.Published, LastModified: r.Modified, Description: r.Description, Severity: r.Severity, CWEs: r.CWEs}
	if r.CVSS != nil {
		if r.CVSS.Score < 0 || r.CVSS.Score > 10 || len(r.CVSS.Version) > 8 || (r.CVSS.Vector != "" && !vectorRE.MatchString(r.CVSS.Vector)) {
			return cvecorpus.CVE{}, fmt.Errorf("vuln %s: cvss", r.ID)
		}
		score := r.CVSS.Score
		c.CVSSScore, c.CVSSVersion, c.CVSSVector = &score, r.CVSS.Version, r.CVSS.Vector
	}
	return c, nil
}

func toRange(r rng) (cvecorpus.Range, error) {
	bad := func(what string) (cvecorpus.Range, error) {
		return cvecorpus.Range{}, fmt.Errorf("range of %s: %s", r.Vuln, what)
	}
	p, err := productCPE(r.Product)
	if err != nil {
		return bad("product " + r.Product)
	}
	if r.Scheme != string(vulnmatch.SchemeGeneric) {
		return bad("scheme " + r.Scheme)
	}
	switch r.Source {
	case "nvd", "osv", "cve5":
	default:
		return bad("source " + r.Source)
	}
	if r.Exact != "" && (r.Start != "" || r.End != "") {
		return bad("exact version together with bounds")
	}
	if (r.Start == "" && r.StartIncl) || (r.End == "" && r.EndIncl) {
		return bad("inclusive flag without its bound")
	}
	for _, v := range []string{r.Exact, r.Start, r.End} {
		if v == "" {
			continue
		}
		if _, ok := vulnmatch.ParseVersion(v); !ok || strings.TrimSpace(v) != v {
			return bad("version " + v)
		}
	}
	for _, q := range []string{r.Edition, r.Target} {
		if len(q) > 64 || strings.ToLower(q) != q {
			return bad("edition or target")
		}
	}
	out := cvecorpus.Range{Product: p, Source: r.Source, Range: vulnmatch.Range{VulnID: r.Vuln, Scheme: vulnmatch.SchemeGeneric,
		Exact: r.Exact, Start: r.Start, StartIncl: r.StartIncl, End: r.End, EndIncl: r.EndIncl, Edition: r.Edition, Target: r.Target}}
	if r.Condition != "" {
		c, err := productCPE(r.Condition)
		if err != nil {
			return bad("condition " + r.Condition)
		}
		out.Condition = &c
	}
	return out, nil
}

func eachLine(path string, fn func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(io.LimitReader(f, MaxFileBytes))
	if err != nil {
		return err
	}
	defer gz.Close()
	sc := bufio.NewScanner(&limited{r: gz, left: MaxDecompressedBytes})
	sc.Buffer(make([]byte, 64<<10), MaxRecordBytes)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}

type limited struct {
	r    io.Reader
	left int64
}

func (l *limited) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errors.New("decompressed data over the cap")
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}
