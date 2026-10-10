package bountyprogram

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestDeliveryAllows(t *testing.T) {
	p1, p2 := shared.NewID(), shared.NewID()
	orgWide, attached1, attached2, both := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	channels := map[shared.ID]map[shared.ID]bool{
		attached1: {p1: true}, attached2: {p2: true}, both: {p1: true, p2: true},
	}

	// Nothing restricted: every destination.
	open := Delivery{Channels: channels}
	for _, i := range []shared.ID{orgWide, attached1, attached2, both} {
		if !open.Allows(i) {
			t.Fatalf("unrestricted event refused for %s", i)
		}
	}

	// One restricted asset listed by p1 and p2: a channel of either.
	one := Delivery{Restricted: [][]shared.ID{{p1, p2}}, Channels: channels}
	if one.Allows(orgWide) {
		t.Fatal("org-wide integration receives a restricted event")
	}
	for _, i := range []shared.ID{attached1, attached2, both} {
		if !one.Allows(i) {
			t.Fatalf("program channel %s refused", i)
		}
	}

	// Two restricted assets, one per program: only a channel of both.
	two := Delivery{Restricted: [][]shared.ID{{p1}, {p2}}, Channels: channels}
	if two.Allows(attached1) || two.Allows(attached2) || two.Allows(orgWide) {
		t.Fatal("a channel of one program receives the other program's asset")
	}
	if !two.Allows(both) {
		t.Fatal("channel of both programs refused")
	}
	if !one.IsRestricted() || open.IsRestricted() {
		t.Fatal("IsRestricted")
	}
}

func TestDeliveryScrub(t *testing.T) {
	p1, p2 := shared.NewID(), shared.NewID()
	orgWide, attached1 := shared.NewID(), shared.NewID()
	d := Delivery{
		Programs: []DeliveryProgram{
			{ID: p1, Name: "Acme Secret", Handle: "acme-secret", Tag: "program:h1:acme-secret"},
			{ID: p2, Name: "Zeta (VDP)", Handle: "z", Tag: "program:self:zeta-vdp-"},
		},
		Channels: map[shared.ID]map[shared.ID]bool{attached1: {p1: true}},
	}
	in := "New finding on shop for ACME SECRET (tag program:h1:acme-secret, handle acme-secret) and Zeta (VDP); z stays"
	got := d.Scrub(orgWide, in)
	want := "New finding on shop for [private program] (tag [private program], handle [private program]) and [private program]; z stays"
	if got != want {
		t.Fatalf("org-wide scrub:\n got %q\nwant %q", got, want)
	}
	// A channel of p1 keeps p1's name; p2's is still scrubbed.
	got = d.Scrub(attached1, in)
	want = "New finding on shop for ACME SECRET (tag program:h1:acme-secret, handle acme-secret) and [private program]; z stays"
	if got != want {
		t.Fatalf("program channel scrub:\n got %q\nwant %q", got, want)
	}
	if (Delivery{}).Scrub(orgWide, in) != in {
		t.Fatal("no private program: text changed")
	}
}

func TestDeliverySubjectEmpty(t *testing.T) {
	if !(DeliverySubject{}).Empty() || (DeliverySubject{FindingIDs: []shared.ID{shared.NewID()}}).Empty() {
		t.Fatal("Empty")
	}
}
