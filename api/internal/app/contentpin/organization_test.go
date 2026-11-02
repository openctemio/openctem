package contentpin

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/wordlist"
)

// listsByTenant is a tenant-scoped OrganizationLists, as the SQL is.
type listsByTenant map[string][]*wordlist.Wordlist

func (l listsByTenant) Enabled(_ context.Context, tenantID shared.ID, purpose string) ([]*wordlist.Wordlist, error) {
	var out []*wordlist.Wordlist
	for _, w := range l[tenantID.String()] {
		if w.Enabled && w.Purpose == purpose {
			out = append(out, w)
		}
	}
	return out, nil
}

func orgList(t *testing.T, name string, version int, text string) *wordlist.Wordlist {
	t.Helper()
	n, err := wordlist.Normalize(text)
	if err != nil {
		t.Fatal(err)
	}
	return &wordlist.Wordlist{ID: shared.NewID(), Name: name, Purpose: wordlist.PurposeDNSLabels, Enabled: true,
		Version: version, Lines: len(n.Labels), SHA256: n.SHA256, Content: n.Content}
}

// A DNS label job carries the organization's enabled lists as a second
// inline list after the learned one: merged in order without repeats,
// marked as the organization's, naming each list and version for the run
// record. Another organization's lists and disabled lists never join.
func TestPin_OrganizationLists(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	disabled := orgList(t, "old", 1, "legacy\n")
	disabled.Enabled = false
	lists := listsByTenant{
		a.String(): {orgList(t, "branches", 3, "hn01\nhcm02\n"), orgList(t, "words", 1, "hocvien\nhn01\n"), disabled},
		b.String(): {orgList(t, "theirs", 1, "payroll\n")},
	}
	p := New(newDelivery(), namesByTenant{a.String(): {"charts-uat.example.vn"}}, quiet())
	p.SetOrganizationLists(lists)
	_, inputs, err := p.PinJobContent(context.Background(), command.PinRequest{TenantID: a, Payload: payload("standard", `"example.vn"`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 || inputs[0].Source != scanrundom.InputSourceLearned || inputs[1].Source != scanrundom.InputSourceOrganization {
		t.Fatalf("inputs %+v", inputs)
	}
	org := inputs[1]
	lines := strings.Split(strings.TrimSpace(string(gunzip(t, org.Data))), "\n")
	if !slices.Equal(lines, []string{"hn01", "hcm02", "hocvien"}) || org.Lines != 3 {
		t.Fatalf("organization labels %v", lines)
	}
	if len(org.Lists) != 2 || org.Lists[0].Name != "branches" || org.Lists[0].Version != 3 || org.Lists[1].Name != "words" {
		t.Fatalf("lists %+v", org.Lists)
	}
	for _, l := range lines {
		if l == "payroll" || l == "legacy" {
			t.Fatalf("label %q from another organization or a disabled list", l)
		}
	}

	// Without learned names the organization's lists still go; with no
	// list either, the job carries only the pack.
	p2 := New(newDelivery(), namesByTenant{}, quiet())
	p2.SetOrganizationLists(lists)
	_, inputs, err = p2.PinJobContent(context.Background(), command.PinRequest{TenantID: b, Payload: payload("standard", `"example.vn"`)})
	if err != nil || len(inputs) != 1 || inputs[0].Source != scanrundom.InputSourceOrganization {
		t.Fatalf("B: %+v %v", inputs, err)
	}
	content, inputs, err := p2.PinJobContent(context.Background(), command.PinRequest{TenantID: shared.NewID(), Payload: payload("standard", `"example.vn"`)})
	if err != nil || len(inputs) != 0 || len(content) != 1 {
		t.Fatalf("no lists: %+v %+v %v", content, inputs, err)
	}
}

// The preview counts each source for a root and the caller's organization
// only; a root that is not a domain is refused.
func TestPreview(t *testing.T) {
	a := shared.NewID()
	p := New(newDelivery(), namesByTenant{a.String(): {"charts-uat.example.vn", "hocviendgo5.example.vn"}}, quiet())
	p.SetOrganizationLists(listsByTenant{a.String(): {orgList(t, "branches", 2, "hn01\nhcm02\n")}})
	got, err := p.Preview(context.Background(), a, "Example.VN.", "standard")
	if err != nil {
		t.Fatal(err)
	}
	if got.Root != "example.vn" || got.Pack == nil || got.Pack.Name != "wordlists-s" || got.Learned == 0 ||
		got.Organization != 2 || got.OrganizationKept != 2 || len(got.Lists) != 1 || got.Total < got.Learned+2 {
		t.Fatalf("preview %+v", got)
	}
	other, err := p.Preview(context.Background(), shared.NewID(), "example.vn", "standard")
	if err != nil || other.Learned != 0 || other.Organization != 0 || len(other.Lists) != 0 {
		t.Fatalf("another organization's preview %+v %v", other, err)
	}
	for _, bad := range []string{"", "http://example.vn", "*.example.vn", "10.0.0.1"} {
		if _, err := p.Preview(context.Background(), a, bad, "standard"); err == nil {
			t.Errorf("root %q accepted", bad)
		}
	}
	// No platform pack: the preview says so instead of failing.
	none := New(&fakeDelivery{}, nil, quiet())
	if got, err := none.Preview(context.Background(), a, "example.vn", "deep"); err != nil || got.Pack != nil {
		t.Fatalf("no pack: %+v %v", got, err)
	}
}
