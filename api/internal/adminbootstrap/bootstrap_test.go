package adminbootstrap

import (
	"strings"
	"testing"
)

func TestOptionsRequireABackup(t *testing.T) {
	cases := map[string]struct {
		o       Options
		wantErr string
	}{
		"backup required":   {Options{Email: "a@x.io"}, "break-glass backup administrator is required"},
		"same email":        {Options{Email: "a@x.io", BackupEmail: "A@x.io"}, "different email"},
		"both flags":        {Options{Email: "a@x.io", BackupEmail: "b@x.io", NoBackup: true}, "mutually exclusive"},
		"bad role":          {Options{Email: "a@x.io", NoBackup: true, Role: "root"}, "invalid role"},
		"explicit opt-out":  {Options{Email: "a@x.io", NoBackup: true}, ""},
		"with backup":       {Options{Email: "a@x.io", BackupEmail: "b@x.io"}, ""},
		"link needs no bkp": {Options{Email: "a@x.io", LinkOnly: true}, ""},
	}
	for name, c := range cases {
		o := c.o
		err := o.Normalize()
		switch {
		case c.wantErr == "" && err != nil:
			t.Fatalf("%s: unexpected error %v", name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Fatalf("%s: want error containing %q, got %v", name, c.wantErr, err)
		}
	}
}

func TestOptionsFirstOrganization(t *testing.T) {
	base := func() Options { return Options{Email: "a@x.io", BackupEmail: "b@x.io"} }
	cases := map[string]struct {
		mut      func(*Options)
		wantErr  string
		wantSlug string
	}{
		"no org":              {func(*Options) {}, "", ""},
		"slug derived":        {func(o *Options) { o.OrgName, o.OrgOwnerEmail = "Acme Security, Inc.", "Owner@Acme.io" }, "", "acme-security-inc"},
		"explicit slug":       {func(o *Options) { o.OrgName, o.OrgSlug, o.OrgOwnerEmail = "Acme", " ACME-sec ", "o@acme.io" }, "", "acme-sec"},
		"name without owner":  {func(o *Options) { o.OrgName = "Acme" }, "-org-owner-email", ""},
		"owner without name":  {func(o *Options) { o.OrgOwnerEmail = "o@acme.io" }, "-org-name", ""},
		"slug without name":   {func(o *Options) { o.OrgSlug = "acme" }, "-org-name", ""},
		"bad owner email":     {func(o *Options) { o.OrgName, o.OrgOwnerEmail = "Acme", "nope" }, "invalid organization owner email", ""},
		"owner is the admin":  {func(o *Options) { o.OrgName, o.OrgOwnerEmail = "Acme", "A@x.io" }, "cannot own an organization", ""},
		"owner is the backup": {func(o *Options) { o.OrgName, o.OrgOwnerEmail = "Acme", "b@x.io" }, "cannot own an organization", ""},
		"underivable slug":    {func(o *Options) { o.OrgName, o.OrgOwnerEmail = "Ωμέγα", "o@acme.io" }, "-org-slug", ""},
		"bad explicit slug":   {func(o *Options) { o.OrgName, o.OrgSlug, o.OrgOwnerEmail = "Acme", "a_b", "o@acme.io" }, "invalid -org-slug", ""},
		"short name":          {func(o *Options) { o.OrgName, o.OrgOwnerEmail = "A", "o@acme.io" }, "-org-name", ""},
		"not with -link": {func(o *Options) {
			o.LinkOnly, o.BackupEmail, o.OrgName, o.OrgOwnerEmail = true, "", "Acme", "o@acme.io"
		}, "-link", ""},
	}
	for name, c := range cases {
		o := base()
		c.mut(&o)
		err := o.Normalize()
		switch {
		case c.wantErr == "" && err != nil:
			t.Fatalf("%s: unexpected error %v", name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Fatalf("%s: want error containing %q, got %v", name, c.wantErr, err)
		case c.wantErr == "" && o.OrgSlug != c.wantSlug:
			t.Fatalf("%s: slug %q, want %q", name, o.OrgSlug, c.wantSlug)
		}
		if c.wantErr == "" && o.OrgOwnerEmail != strings.ToLower(o.OrgOwnerEmail) {
			t.Fatalf("%s: owner email not normalized: %q", name, o.OrgOwnerEmail)
		}
	}
}

func TestSetupLinkURL(t *testing.T) {
	cases := map[string]string{
		"https://ctem.example.com/": "https://ctem.example.com/set-password?token=tok",
		"https://ctem.example.com":  "https://ctem.example.com/set-password?token=tok",
		"":                          "<ui-url>/set-password?token=tok",
	}
	for base, want := range cases {
		if got := setupLinkURL(base, "tok"); got != want {
			t.Fatalf("base %q: got %q want %q", base, got, want)
		}
	}
}
