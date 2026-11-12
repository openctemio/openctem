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
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

const (
	digS = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	digM = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
)

type fakeDelivery struct {
	packs map[string]*contentpackapp.Pinnable
	index map[string][]contentpackapp.IndexEntry
	// deliverable[scope] is the digests that scope may hold.
	deliverable map[string][]string
}

func (f *fakeDelivery) PlatformStable(_ context.Context, name string) (*contentpackapp.Pinnable, error) {
	if p, ok := f.packs[name]; ok {
		return p, nil
	}
	return nil, shared.ErrNotFound
}

func (f *fakeDelivery) Deliverable(_ context.Context, scope, digest string) (bool, error) {
	return slices.Contains(f.deliverable[scope], digest), nil
}

func (f *fakeDelivery) Index(_ context.Context, scope, digest string) ([]contentpackapp.IndexEntry, error) {
	if scope != contentpackapp.InstanceScope {
		return nil, errors.New("a platform pack is indexed in the instance scope")
	}
	return f.index[digest], nil
}

func newDelivery() *fakeDelivery {
	mk := func(name, digest string) *contentpackapp.Pinnable {
		return &contentpackapp.Pinnable{
			DeliveredPack: contentpackapp.DeliveredPack{Digest: digest, Scope: contentpackapp.ScopePlatform, Size: 1234, Signature: json.RawMessage(`{"sig":"x"}`)},
			Name:          name, Kind: "wordlist",
		}
	}
	idx := []contentpackapp.IndexEntry{
		{Path: "dns/labels-b.txt"}, {Path: "dns/labels-a.txt"}, {Path: "paths/common.txt"}, {Path: "params/p.txt"}, {Path: "NOTICE"},
	}
	return &fakeDelivery{
		packs:       map[string]*contentpackapp.Pinnable{"wordlists-s": mk("wordlists-s", digS), "wordlists-m": mk("wordlists-m", digM)},
		index:       map[string][]contentpackapp.IndexEntry{digS: idx, digM: idx},
		deliverable: map[string][]string{contentpackapp.InstanceScope: {digS, digM}},
	}
}

// namesByTenant is a tenant-scoped NameSource: it never returns another
// tenant's names, as the SQL does not.
type namesByTenant map[string][]string

func (n namesByTenant) KnownNames(_ context.Context, tenantID shared.ID, root string, limit int) ([]string, error) {
	var out []string
	for _, name := range n[tenantID.String()] {
		if name == root || strings.HasSuffix(name, "."+root) {
			out = append(out, name)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func payload(depth, targets string, wl ...string) json.RawMessage {
	if len(wl) == 0 {
		wl = []string{`{"slot":"labels","purpose":"dns-labels"}`}
	}
	return json.RawMessage(fmt.Sprintf(`{"scanner":"dnsx","targets":[%s],"context":{"depth":%q},"wordlists":[%s]}`, targets, depth, strings.Join(wl, ",")))
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func refusedWith(t *testing.T, err error, substr string) {
	t.Helper()
	var cr *command.ContentRefusedError
	if !errors.As(err, &cr) || !strings.Contains(cr.Reason, substr) {
		t.Fatalf("err = %v, want a content refusal containing %q", err, substr)
	}
}

// Standard depth pins the small class, deep the medium class; the files are
// the pack's lists of the purpose only, in a fixed order.
func TestPin_DepthPicksTheClass(t *testing.T) {
	p := New(newDelivery(), nil, quiet())
	for depth, want := range map[string]struct {
		digest string
		lines  int
	}{"standard": {digS, maxLinesSmall}, "": {digS, maxLinesSmall}, "deep": {digM, maxLinesMedium}} {
		content, inputs, err := p.PinJobContent(context.Background(), command.PinRequest{TenantID: shared.NewID(), Payload: payload(depth, `"example.com"`)})
		if err != nil {
			t.Fatalf("%s: %v", depth, err)
		}
		if len(inputs) != 0 || len(content) != 1 {
			t.Fatalf("%s: content %d, inputs %d", depth, len(content), len(inputs))
		}
		c := content[0]
		if c.Digest != want.digest || c.MaxLines != want.lines || c.Scope != "platform" || c.Slot != "labels" || c.Kind != "wordlist" {
			t.Errorf("%s: %+v", depth, c)
		}
		if !slices.Equal(c.Files, []string{"dns/labels-a.txt", "dns/labels-b.txt"}) {
			t.Errorf("%s: files = %v", depth, c.Files)
		}
		if string(c.Signature) != `{"sig":"x"}` {
			t.Errorf("%s: the pack's signature was not carried: %s", depth, c.Signature)
		}
	}
}

// A passive run sends no traffic and uses no list; a class above the medium
// one is never planned; a missing or wrong pack refuses the job.
func TestPin_Refusals(t *testing.T) {
	d := newDelivery()
	p := New(d, nil, quiet())
	pin := func(pl json.RawMessage) error {
		_, _, err := p.PinJobContent(context.Background(), command.PinRequest{TenantID: shared.NewID(), Payload: pl})
		return err
	}
	refusedWith(t, pin(payload("passive", `"example.com"`)), "passive")
	refusedWith(t, pin(payload("maximum", `"example.com"`)), "depth")
	refusedWith(t, pin(payload("standard", `"example.com"`, `{"slot":"x","purpose":"nope"}`)), "purpose")
	refusedWith(t, pin(payload("standard", `"example.com"`, `{"slot":"../x","purpose":"dns-labels"}`)), "slot")
	refusedWith(t, pin(payload("standard", `"example.com"`, `{"slot":"a","purpose":"dns-labels"}`, `{"slot":"a","purpose":"params"}`)), "repeated")
	many := make([]string, maxRequests+1)
	for i := range many {
		many[i] = fmt.Sprintf(`{"slot":"s%d","purpose":"params"}`, i)
	}
	refusedWith(t, pin(payload("standard", `"example.com"`, many...)), "at most")

	delete(d.packs, "wordlists-s")
	refusedWith(t, pin(payload("standard", `"example.com"`)), "no stable")
	d.packs["wordlists-s"] = &contentpackapp.Pinnable{DeliveredPack: contentpackapp.DeliveredPack{Digest: digS}, Name: "wordlists-s", Kind: "rules"}
	refusedWith(t, pin(payload("standard", `"example.com"`)), "not a wordlist pack")
	d.packs["wordlists-s"].Kind = "wordlist"
	d.index[digS] = []contentpackapp.IndexEntry{{Path: "paths/x.txt"}}
	refusedWith(t, pin(payload("standard", `"example.com"`)), "no list")

	// No request, no content.
	c, in, err := p.PinJobContent(context.Background(), command.PinRequest{TenantID: shared.NewID(), Payload: json.RawMessage(`{"scanner":"nuclei","targets":["a.example.com"]}`)})
	if c != nil || in != nil || err != nil {
		t.Fatalf("a job that asks for no list: %v %v %v", c, in, err)
	}
}

// The list generated for a job holds the labels of the organization's own
// names under the job's targets, and nothing of another organization's.
func TestPin_GeneratedLabelsAreTheOrganizationsOwn(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	names := namesByTenant{
		a.String(): {"api-v2.example.com", "api-v3.example.com", "mail.example.com", "x.other.org"},
		b.String(): {"secretproject.example.com", "payroll-eu.example.com"},
	}
	p := New(newDelivery(), names, quiet())
	for _, shared := range []bool{false, true} {
		_, inputs, err := p.PinJobContent(context.Background(), command.PinRequest{TenantID: a, Shared: shared, Payload: payload("standard", `"example.com"`)})
		if err != nil || len(inputs) != 1 {
			t.Fatalf("shared=%v: %d inputs, %v", shared, len(inputs), err)
		}
		in := inputs[0]
		raw := gunzip(t, in.Data)
		sum := sha256.Sum256(raw)
		if in.SHA256 != hex.EncodeToString(sum[:]) || in.Purpose != "dns-labels" || in.Slot != "labels" {
			t.Fatalf("input metadata: %+v", in)
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if in.Lines != len(lines) {
			t.Errorf("lines = %d, list has %d", in.Lines, len(lines))
		}
		for _, want := range []string{"api", "api-v2", "mail", "v2", "v3"} {
			if !slices.Contains(lines, want) {
				t.Errorf("shared=%v: %q is missing from %v", shared, want, lines)
			}
		}
		for _, l := range lines {
			if strings.Contains(l, "secret") || strings.Contains(l, "payroll") || l == "eu" || l == "x" {
				t.Errorf("shared=%v: %q is not one of this organization's labels under the target", shared, l)
			}
		}
		if lines[0] != "api" {
			t.Errorf("the most frequent label should rank first: %v", lines)
		}
	}
	// The other organization gets its own and none of A's.
	_, inputs, err := p.PinJobContent(context.Background(), command.PinRequest{TenantID: b, Payload: payload("standard", `"example.com"`)})
	if err != nil || len(inputs) != 1 {
		t.Fatalf("%d inputs, %v", len(inputs), err)
	}
	if got := string(gunzip(t, inputs[0].Data)); strings.Contains(got, "mail") || strings.Contains(got, "api") || !strings.Contains(got, "payroll") {
		t.Errorf("tenant B's list: %q", got)
	}
	// Targets that are not names have no labels: nothing is generated.
	_, inputs, err = p.PinJobContent(context.Background(), command.PinRequest{TenantID: a, Payload: payload("standard", `"203.0.113.0/24","http://example.com"`)})
	if err != nil || len(inputs) != 0 {
		t.Fatalf("non-name targets: %d inputs, %v", len(inputs), err)
	}
}

// A generated list is cut by rank until it fits 256 KiB compressed; the
// highest ranks survive.
func TestPin_GeneratedListIsCapped(t *testing.T) {
	tenant := shared.NewID()
	var names []string
	var targets []string
	// Pseudo-random 20-character labels do not compress well. Five roots
	// at the row limit give far more than 256 KiB of them.
	x := uint64(88172645463325252)
	for r := 0; r < 5; r++ {
		root := fmt.Sprintf("r%d.example.com", r)
		targets = append(targets, fmt.Sprintf("%q", root))
		// A frequent label must be kept: it ranks first.
		for i := 0; i < 1000; i++ {
			names = append(names, fmt.Sprintf("www.h%d.%s", i, root))
		}
		for i := 0; i < maxNameRows-1000; i++ {
			var sb strings.Builder
			for j := 0; j < 20; j++ {
				x ^= x << 13
				x ^= x >> 7
				x ^= x << 17
				sb.WriteByte("abcdefghijklmnopqrstuvwxyz0123456789"[x%36])
			}
			names = append(names, "a"+sb.String()+"."+root)
		}
	}
	p := New(newDelivery(), namesByTenant{tenant.String(): names}, quiet())
	_, inputs, err := p.PinJobContent(context.Background(), command.PinRequest{TenantID: tenant, Payload: payload("standard", strings.Join(targets, ","))})
	if err != nil || len(inputs) != 1 {
		t.Fatalf("%d inputs, %v", len(inputs), err)
	}
	in := inputs[0]
	if len(in.Data) > protov2.MaxJobInputGzipBytes {
		t.Fatalf("compressed list is %d bytes, over the %d cap", len(in.Data), protov2.MaxJobInputGzipBytes)
	}
	if len(in.Data) < protov2.MaxJobInputGzipBytes/2 {
		t.Errorf("the list was cut far below the cap: %d bytes", len(in.Data))
	}
	raw := gunzip(t, in.Data)
	lines := strings.Count(string(raw), "\n")
	if lines != in.Lines || lines >= 5*(maxNameRows-1000) {
		t.Errorf("lines = %d (reported %d): the list should have been cut", lines, in.Lines)
	}
	if !strings.HasPrefix(string(raw), "www\n") {
		t.Errorf("the most frequent label should come first, got %q", string(raw[:20]))
	}
}

// A job's inline lists share 512 KiB compressed: a third list of near the
// per-list cap is left out.
func TestPin_InlineListsShareOneBudget(t *testing.T) {
	tenant := shared.NewID()
	var names []string
	var targets []string
	x := uint64(88172645463325252)
	for r := 0; r < 5; r++ {
		root := fmt.Sprintf("r%d.example.com", r)
		targets = append(targets, fmt.Sprintf("%q", root))
		for i := 0; i < maxNameRows; i++ {
			var sb strings.Builder
			for j := 0; j < 20; j++ {
				x ^= x << 13
				x ^= x >> 7
				x ^= x << 17
				sb.WriteByte("abcdefghijklmnopqrstuvwxyz0123456789"[x%36])
			}
			names = append(names, "a"+sb.String()+"."+root)
		}
	}
	p := New(newDelivery(), namesByTenant{tenant.String(): names}, quiet())
	_, inputs, err := p.PinJobContent(context.Background(), command.PinRequest{TenantID: tenant, Payload: payload("standard", strings.Join(targets, ","),
		`{"slot":"one","purpose":"dns-labels"}`, `{"slot":"two","purpose":"dns-labels"}`, `{"slot":"three","purpose":"dns-labels"}`)})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, in := range inputs {
		total += len(in.Data)
	}
	if len(inputs) != 2 || total > protov2.MaxJobInputsGzipTotal {
		t.Fatalf("%d inputs, %d bytes compressed, over the %d budget", len(inputs), total, protov2.MaxJobInputsGzipTotal)
	}
}

// The checker answers by the job's scope: an organization's own, or the
// instance scope for a job of a shared sensor.
func TestPlanner_DeliverableUsesTheJobsScope(t *testing.T) {
	tenant := shared.NewID()
	d := newDelivery()
	d.deliverable[tenant.String()] = []string{"sha256:own"}
	p := New(d, nil, quiet())
	for _, tc := range []struct {
		shared bool
		digest string
		want   bool
	}{
		{false, "sha256:own", true}, {false, digS, false}, {true, "sha256:own", false}, {true, digS, true},
	} {
		got, err := p.Deliverable(context.Background(), tenant, tc.shared, tc.digest)
		if err != nil || got != tc.want {
			t.Errorf("shared=%v %s: %v, %v", tc.shared, tc.digest, got, err)
		}
	}
}

func TestLearnedLabels(t *testing.T) {
	got := LearnedLabels([]Named{
		{"api-v2-eu.example.com", "example.com"},
		{"api.example.com", "example.com"},
		{"api.dev.example.com", "example.com"},
		{"123.example.com", "example.com"},   // a number alone is no label worth trying
		{"example.com", "example.com"},       // the root itself
		{"evil.example.org", "example.com"},  // not under the root
		{"-bad-.example.com", "example.com"}, // not a valid name
		{"UPPER.example.com", "example.com"}, // names are lower-cased by the caller; this one is not a valid name
	})
	want := []string{"api", "api-v2-eu", "dev", "eu", "v2"}
	if !slices.Equal(got, want) {
		t.Fatalf("labels = %v, want %v", got, want)
	}
}
