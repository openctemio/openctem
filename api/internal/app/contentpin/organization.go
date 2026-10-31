package contentpin

// Organization lists and the preview of a job's list
// (docs/architecture/wordlists.md, "Organization lists").
//
// Threat model. The organization's enabled lists are read with the job's
// own tenant id (OrganizationLists is tenant-scoped), merged without
// repeats and carried inline under the job signature: they reach a sensor
// only inside that organization's job, are written only to the task
// directory and are never cached. The preview reads the same data for the
// caller's organization and sends nothing to any sensor or resolver.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/command"
	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/wordlist"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// OrganizationLists reads an organization's enabled wordlists. Every
// implementation is scoped to tenantID.
type OrganizationLists interface {
	Enabled(ctx context.Context, tenantID shared.ID, purpose string) ([]*wordlist.Wordlist, error)
}

// SetOrganizationLists makes every DNS label job also carry the
// organization's enabled lists. Without it a job carries none.
func (p *Planner) SetOrganizationLists(l OrganizationLists) { p.lists = l }

// generatedLabels are the inline lists of a DNS label request: the labels
// learned from the organization's names (with their permutations), then
// the organization's own lists. Either may be absent.
func (p *Planner) generatedLabels(ctx context.Context, tenantID shared.ID, slot string, targets []string) ([]protov2.JobInput, error) {
	var out []protov2.JobInput
	if p.names != nil {
		in, err := p.dnsLabels(ctx, tenantID, slot, targets)
		if err != nil {
			return nil, err
		}
		if in != nil {
			in.Source = scanrundom.InputSourceLearned
			out = append(out, *in)
		}
	}
	if p.lists != nil {
		in, err := p.organizationLabels(ctx, tenantID, slot)
		if err != nil {
			return nil, err
		}
		if in != nil {
			out = append(out, *in)
		}
	}
	return out, nil
}

// organizationLabels merges the organization's enabled DNS label lists, in
// the order they were created, without repeats; nil when it has none. A
// merge larger than the inline cap keeps the leading labels.
func (p *Planner) organizationLabels(ctx context.Context, tenantID shared.ID, slot string) (*protov2.JobInput, error) {
	lists, err := p.lists.Enabled(ctx, tenantID, wordlist.PurposeDNSLabels)
	if err != nil {
		return nil, fmt.Errorf("read organization wordlists: %w", err)
	}
	labels, refs := mergeLists(lists)
	if len(labels) == 0 {
		return nil, nil
	}
	in, err := encodeInput(slot, PurposeDNSLabels, labels)
	if err != nil || in == nil {
		return in, err
	}
	if in.Lines < len(labels) {
		p.logger.Warn("organization wordlists cut to the job's inline cap", "tenant_id", tenantID.String(),
			"labels", len(labels), "kept", in.Lines)
	}
	in.Source, in.Lists = scanrundom.InputSourceOrganization, refs
	return in, nil
}

func mergeLists(lists []*wordlist.Wordlist) ([]string, []protov2.InputListRef) {
	var labels []string
	refs := make([]protov2.InputListRef, 0, len(lists))
	seen := map[string]bool{}
	for _, w := range lists {
		refs = append(refs, protov2.InputListRef{ID: w.ID.String(), Name: w.Name, Version: w.Version, SHA256: w.SHA256})
		for _, l := range w.Labels() {
			if !seen[l] {
				seen[l] = true
				labels = append(labels, l)
			}
		}
	}
	return labels, refs
}

// Preview is what a job's DNS label list would hold for one root, counted
// per source, before any traffic.
type Preview struct {
	Root string
	// Pack is the platform pack of the depth (nil: the platform has none,
	// and the job would be refused).
	Pack *PreviewPack
	// Learned counts the learned labels and permutations; Organization the
	// merged organization labels; OrganizationKept those that fit the
	// job's inline cap.
	Learned          int
	Organization     int
	OrganizationKept int
	Lists            []protov2.InputListRef
	// Total is the most labels the job queries (sources may overlap; the
	// sensor removes repeats), capped at the depth's line cap.
	Total int
}

// PreviewPack is the platform pack a preview counts.
type PreviewPack struct {
	Name, Version, Digest string
	Lines                 int
}

// ErrPreviewRoot: the root is not a DNS name.
var ErrPreviewRoot = shared.NewDomainError("WORDLIST_PREVIEW_ROOT", "the root must be a domain name such as example.com", shared.ErrValidation)

// Preview counts the list a standard (or deep) enumeration job of root
// would carry for the organization.
func (p *Planner) Preview(ctx context.Context, tenantID shared.ID, root, depth string) (*Preview, error) {
	root = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(root), "."))
	if !validName(root) {
		return nil, ErrPreviewRoot
	}
	class, err := classOf(depth)
	if err != nil {
		return nil, err
	}
	out := &Preview{Root: root}
	item, err := p.packFor(ctx, "labels", purposeDir[PurposeDNSLabels], class)
	switch {
	case errors.Is(err, command.ErrContentRefused):
	case err != nil:
		return nil, err
	default:
		lines, lerr := p.packLines(ctx, item)
		if lerr != nil {
			return nil, lerr
		}
		out.Pack = &PreviewPack{Name: item.Pack, Version: item.Version, Digest: item.Digest, Lines: lines}
		out.Total += lines
	}
	generated, err := p.generatedLabels(ctx, tenantID, "labels", []string{root})
	if err != nil {
		return nil, err
	}
	for _, in := range generated {
		switch in.Source {
		case scanrundom.InputSourceLearned:
			out.Learned = in.Lines
		case scanrundom.InputSourceOrganization:
			out.OrganizationKept, out.Lists = in.Lines, in.Lists
		}
		out.Total += in.Lines
	}
	if p.lists != nil && len(out.Lists) > 0 {
		lists, err := p.lists.Enabled(ctx, tenantID, wordlist.PurposeDNSLabels)
		if err != nil {
			return nil, fmt.Errorf("read organization wordlists: %w", err)
		}
		labels, _ := mergeLists(lists)
		out.Organization = len(labels)
	}
	out.Total = min(out.Total, maxLinesOf(class))
	return out, nil
}

// fileReader reads one file of a pack (contentpack.Delivery).
type fileReader interface {
	File(ctx context.Context, scope, digest, sha string) ([]byte, error)
}

// packLines counts the lines of the pack files a job reads, from the
// pack's linted wordlists.yaml (0 when it cannot be read: the preview still
// names the pack).
func (p *Planner) packLines(ctx context.Context, item *protov2.JobContent) (int, error) {
	fr, ok := p.delivery.(fileReader)
	if !ok {
		return 0, nil
	}
	idx, err := p.delivery.Index(ctx, contentpackapp.InstanceScope, item.Digest)
	if err != nil {
		return 0, fmt.Errorf("index %s: %w", item.Pack, err)
	}
	for _, e := range idx {
		if e.Path != wordlistManifestPath {
			continue
		}
		data, err := fr.File(ctx, contentpackapp.InstanceScope, item.Digest, e.SHA256)
		if err != nil {
			return 0, fmt.Errorf("read %s manifest: %w", item.Pack, err)
		}
		m, err := contentpackapp.ParseWordlistManifest(data)
		if err != nil {
			return 0, nil //nolint:nilerr // a platform pack passed the manifest lint; an unreadable one only loses the count
		}
		files := map[string]bool{}
		for _, f := range item.Files {
			files[f] = true
		}
		total := 0
		for _, f := range m.Files {
			if files[f.Path] {
				total += f.Lines
			}
		}
		return total, nil
	}
	return 0, nil
}

// wordlistManifestPath is the manifest of a wordlist pack.
const wordlistManifestPath = "wordlists.yaml"
