// Package contentpin plans the content a scan job pins at dispatch (RFC-061
// §3.7, docs/architecture/content-packs.md): the platform wordlist pack the
// job's depth selects, named by digest, and the lists generated for the job
// from the organization's own data, carried inline.
//
// Threat model. The planner reads only the organization's own rows
// (NameSource is tenant-scoped) and the platform's stable packs. It never
// names a pack of another organization, and for a shared sensor never an
// organization's pack at all. Generated lists are bounded at every step
// (rows read, lines, compressed bytes) and carry names the organization
// already owns and that are its targets anyway; they are never stored. The
// command service still checks every digest the plan names before the signer
// is asked (command.ContentChecker), so a bug here cannot pin a foreign pack.
package contentpin

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/command"
	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// PayloadKeyWordlists is the payload member a scan names the wordlists it
// needs in: [{"slot": "labels", "purpose": "dns-labels"}]. The platform
// resolves each to a pack and, for DNS labels, a generated list. The member
// stays in the payload the sensor gets; it is a request, and everything the
// sensor trusts is in "content", "inputs" and the signed statement.
const PayloadKeyWordlists = "wordlists"

// Purposes a request may name (the sensor's wordlist purposes).
const (
	PurposeDNSLabels = "dns-labels"
	PurposeWebPaths  = "web-paths"
	PurposeWebFiles  = "web-files"
	PurposeAPIRoutes = "api-routes"
	PurposeParams    = "params"
)

// purposeDir is the directory of a platform wordlist pack that holds the
// lists of a purpose.
var purposeDir = map[string]string{
	PurposeDNSLabels: "dns",
	PurposeWebPaths:  "paths",
	PurposeWebFiles:  "files",
	PurposeAPIRoutes: "api",
	PurposeParams:    "params",
}

// Size classes of the curated wordlist packs and the line cap each gives a
// job. The depth picks the class; a scan can lower it, never raise it.
const (
	classSmall  = "s"
	classMedium = "m"

	packPrefix = "wordlists-"

	maxLinesSmall  = 100_000
	maxLinesMedium = 1_000_000
)

// Bounds of a request and of the generated list.
const (
	maxRequests = 4
	// maxNameRows bounds the names read for one root.
	maxNameRows = 20_000
	// maxRoots bounds the roots a job's generated list draws on.
	maxRoots = 64
	// maxLabelLines bounds the lines of a generated list before the byte cap.
	maxLabelLines = 100_000
	// minPartLen is the shortest part of a label that is tried on its own.
	minPartLen = 2
)

// Delivery is what the planner needs of the content store.
type Delivery interface {
	PlatformStable(ctx context.Context, name string) (*contentpackapp.Pinnable, error)
	Deliverable(ctx context.Context, scope, digest string) (bool, error)
	Index(ctx context.Context, scope, digest string) ([]contentpackapp.IndexEntry, error)
}

// NameSource reads the names the organization already knows under a root.
// Every implementation is scoped to tenantID; there is no cross-tenant read.
type NameSource interface {
	KnownNames(ctx context.Context, tenantID shared.ID, root string, limit int) ([]string, error)
}

// Planner plans the content of a job. It implements command.ContentSource
// and command.ContentChecker.
type Planner struct {
	delivery Delivery
	names    NameSource
	logger   *slog.Logger
}

// New returns a planner. names may be nil: no list is generated.
func New(d Delivery, names NameSource, log *slog.Logger) *Planner {
	if log == nil {
		log = slog.Default()
	}
	return &Planner{delivery: d, names: names, logger: log}
}

// Deliverable implements command.ContentChecker.
func (p *Planner) Deliverable(ctx context.Context, tenantID shared.ID, sharedSensor bool, digest string) (bool, error) {
	scope := tenantID.String()
	if sharedSensor {
		scope = contentpackapp.InstanceScope
	}
	return p.delivery.Deliverable(ctx, scope, digest)
}

type request struct {
	Slot    string `json:"slot"`
	Purpose string `json:"purpose"`
}

var slotRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func refuse(format string, args ...any) error {
	return &command.ContentRefusedError{Reason: fmt.Sprintf(format, args...)}
}

// PinJobContent implements command.ContentSource.
func (p *Planner) PinJobContent(ctx context.Context, req command.PinRequest) ([]protov2.JobContent, []protov2.JobInput, error) {
	var payload struct {
		Wordlists []request `json:"wordlists"`
		Context   struct {
			Depth string `json:"depth"`
		} `json:"context"`
	}
	// A payload that does not decode names no list: a job that asks for none
	// carries none (a malformed one is refused elsewhere).
	_ = json.Unmarshal(req.Payload, &payload)
	if len(payload.Wordlists) == 0 {
		return nil, nil, nil
	}
	if len(payload.Wordlists) > maxRequests {
		return nil, nil, refuse("a job may ask for at most %d wordlists", maxRequests)
	}
	class, err := classOf(payload.Context.Depth)
	if err != nil {
		return nil, nil, err
	}
	var (
		content = make([]protov2.JobContent, 0, len(payload.Wordlists))
		inputs  = make([]protov2.JobInput, 0, len(payload.Wordlists))
		slots   = map[string]bool{}
		// inputsBytes is the compressed size of the inline lists so far.
		inputsBytes int
	)
	for _, r := range payload.Wordlists {
		if !slotRE.MatchString(r.Slot) || slots[r.Slot] {
			return nil, nil, refuse("wordlist slot %q is invalid or repeated", clip(r.Slot, 40))
		}
		slots[r.Slot] = true
		dir, ok := purposeDir[r.Purpose]
		if !ok {
			return nil, nil, refuse("wordlist purpose %q is not supported", clip(r.Purpose, 40))
		}
		item, err := p.packFor(ctx, r.Slot, dir, class)
		if err != nil {
			return nil, nil, err
		}
		content = append(content, *item)
		if r.Purpose != PurposeDNSLabels || p.names == nil {
			continue
		}
		in, err := p.dnsLabels(ctx, req.TenantID, r.Slot, commanddom.PayloadTargets(req.Payload))
		if err != nil {
			return nil, nil, err
		}
		if in == nil {
			continue
		}
		// A job's inline lists share one compressed budget; a list that
		// would pass it is left out (the pack's lists still apply).
		if inputsBytes+len(in.Data) > protov2.MaxJobInputsGzipTotal {
			p.logger.Warn("generated list left out: the job's inline budget is used", "tenant_id", req.TenantID.String(), "slot", r.Slot)
			continue
		}
		inputsBytes += len(in.Data)
		inputs = append(inputs, *in)
	}
	for _, c := range content {
		p.logger.Info("job content pinned", "tenant_id", req.TenantID.String(), "slot", c.Slot, "pack", c.Pack, "digest", c.Digest, "shared", req.Shared)
	}
	for _, in := range inputs {
		p.logger.Info("job input generated", "tenant_id", req.TenantID.String(), "slot", in.Slot, "sha256", in.SHA256, "lines", in.Lines, "shared", req.Shared)
	}
	return content, inputs, nil
}

// classOf is the size class of a run's depth: standard S, deep M. Passive
// runs send no traffic, so they never use a wordlist. A class above M needs
// a plan and a scope entry that do not exist yet, so none is offered.
func classOf(depth string) (string, error) {
	d, err := scanworkflow.ParseDepth(depth)
	if err != nil {
		return "", refuse("the run's depth is not valid")
	}
	switch d {
	case scanworkflow.DepthStandard:
		return classSmall, nil
	case scanworkflow.DepthDeep:
		return classMedium, nil
	}
	return "", refuse("a %s run uses no wordlist", d)
}

func maxLinesOf(class string) int {
	if class == classMedium {
		return maxLinesMedium
	}
	return maxLinesSmall
}

// packFor resolves the platform pack of the class on the stable channel and
// the files of it that hold the purpose's lists.
func (p *Planner) packFor(ctx context.Context, slot, dir, class string) (*protov2.JobContent, error) {
	name := packPrefix + class
	pack, err := p.delivery.PlatformStable(ctx, name)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, refuse("the platform has no stable %s pack yet", name)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	if pack.Kind != "wordlist" {
		return nil, refuse("pack %s is not a wordlist pack", name)
	}
	idx, err := p.delivery.Index(ctx, contentpackapp.InstanceScope, pack.Digest)
	if err != nil {
		return nil, fmt.Errorf("index %s: %w", name, err)
	}
	var files []string
	for _, e := range idx {
		if path.Dir(e.Path) == dir {
			files = append(files, e.Path)
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, refuse("pack %s holds no list for %s", name, dir)
	}
	if len(files) > protov2.MaxJobContentFiles {
		files = files[:protov2.MaxJobContentFiles]
	}
	return &protov2.JobContent{
		Slot: slot, Kind: pack.Kind, Scope: protov2.ContentScopePlatform, Pack: pack.Name,
		Digest: pack.Digest, Size: pack.Size, Files: files, MaxLines: maxLinesOf(class), Signature: pack.Signature,
	}, nil
}

// CoverageContentReady implements scan.CoverageContent: whether every
// request resolves to a list of the small platform pack (coverage runs at
// standard depth). A missing pack is false, not an error.
func (p *Planner) CoverageContentReady(ctx context.Context, requests []stage.WordlistRequest) (bool, error) {
	for _, r := range requests {
		dir, ok := purposeDir[r.Purpose]
		if !ok {
			return false, nil
		}
		if _, err := p.packFor(ctx, r.Slot, dir, classSmall); err != nil {
			if errors.Is(err, command.ErrContentRefused) {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

// dnsLabels builds the list of DNS labels learned from the organization's
// own names under the job's targets, or nil when it knows none.
func (p *Planner) dnsLabels(ctx context.Context, tenantID shared.ID, slot string, targets []string) (*protov2.JobInput, error) {
	roots := rootsOf(targets)
	if len(roots) == 0 {
		return nil, nil
	}
	var names []Named
	for _, root := range roots {
		got, err := p.names.KnownNames(ctx, tenantID, root, maxNameRows)
		if err != nil {
			return nil, fmt.Errorf("read known names: %w", err)
		}
		for _, n := range got {
			names = append(names, Named{Name: strings.ToLower(n), Root: root})
		}
	}
	labels := LearnedLabels(names)
	if len(labels) == 0 {
		return nil, nil
	}
	return encodeInput(slot, PurposeDNSLabels, labels)
}

// rootsOf are the DNS names among the job's targets, deduplicated and
// bounded: a target that is an address, a range or a URL has no labels.
func rootsOf(targets []string) []string {
	out := make([]string, 0, min(len(targets), maxRoots))
	seen := map[string]bool{}
	for _, t := range targets {
		t = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t), "."))
		if !validName(t) || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= maxRoots {
			break
		}
	}
	return out
}

var (
	nameRE  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	splitRE = regexp.MustCompile(`[a-z]+|[0-9]+`)
)

func validName(s string) bool { return len(s) <= 253 && nameRE.MatchString(s) }

// Named is a known name and the root of the job it is learned for.
type Named struct{ Name, Root string }

// LearnedLabels ranks the labels of names: the
// labels left of the root, and the parts of a label split at "-" and at
// letter/digit boundaries ("api-v2-eu" gives api, v2, eu and api-v2-eu).
// More frequent labels rank first, ties alphabetically; pure numbers, labels
// that are not valid DNS labels and the root's own labels are dropped. The
// result depends only on the set of names, so retries of one run agree.
func LearnedLabels(names []Named) []string {
	freq := map[string]int{}
	for _, nr := range names {
		name, root := nr.Name, nr.Root
		if !validName(name) || name == root || !strings.HasSuffix(name, "."+root) {
			continue
		}
		prefix := strings.TrimSuffix(name, "."+root)
		for _, label := range strings.Split(prefix, ".") {
			add := func(l string) {
				if labelRE.MatchString(l) && !allDigits(l) {
					freq[l]++
				}
			}
			// The label itself counts whatever its length; its parts only
			// when they are at least two characters (a lone letter from
			// "v2" is no word worth a query).
			part := func(l string) {
				if len(l) >= minPartLen {
					add(l)
				}
			}
			add(label)
			for _, p := range strings.Split(label, "-") {
				if p != label {
					part(p)
				}
				if sub := splitRE.FindAllString(p, -1); len(sub) > 1 {
					for _, q := range sub {
						part(q)
					}
				}
			}
		}
	}
	out := make([]string, 0, len(freq))
	for l := range freq {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if freq[out[i]] != freq[out[j]] {
			return freq[out[i]] > freq[out[j]]
		}
		return out[i] < out[j]
	})
	if len(out) > maxLabelLines {
		out = out[:maxLabelLines]
	}
	return out
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// encodeInput compresses lines (highest rank first) into an inline input,
// keeping the longest prefix that fits the compressed cap.
func encodeInput(slot, purpose string, lines []string) (*protov2.JobInput, error) {
	n := fittingPrefix(lines)
	for n > 0 {
		gz, raw, err := gzipLines(lines[:n])
		if err != nil {
			return nil, err
		}
		if len(gz) <= protov2.MaxJobInputGzipBytes && len(raw) <= protov2.MaxJobInputExpandedBytes {
			sum := sha256.Sum256(raw)
			return &protov2.JobInput{Slot: slot, Purpose: purpose, SHA256: hex.EncodeToString(sum[:]), Lines: n, Data: gz}, nil
		}
		n -= max(1, n/20)
	}
	return nil, nil
}

// fittingPrefix is how many leading lines stay inside the compressed cap,
// found in one pass over a flushed gzip stream (a little under the cap, which
// encodeInput then confirms with an exact compression).
func fittingPrefix(lines []string) int {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	const chunk = 256
	raw := 0
	for i := 0; i < len(lines); i += chunk {
		end := min(i+chunk, len(lines))
		for _, l := range lines[i:end] {
			raw += len(l) + 1
			_, _ = zw.Write([]byte(l + "\n"))
		}
		_ = zw.Flush()
		if buf.Len() > protov2.MaxJobInputGzipBytes-1024 || raw > protov2.MaxJobInputExpandedBytes {
			return i
		}
	}
	return len(lines)
}

func gzipLines(lines []string) (gz, raw []byte, err error) {
	raw = []byte(strings.Join(lines, "\n") + "\n")
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, werr := zw.Write(raw); werr != nil {
		return nil, nil, werr
	}
	if cerr := zw.Close(); cerr != nil {
		return nil, nil, cerr
	}
	return slices.Clone(buf.Bytes()), raw, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
