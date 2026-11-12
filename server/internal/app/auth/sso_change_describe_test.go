package auth

import (
	"encoding/json"
	"strings"
	"testing"

	identityproviderdom "github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
)

// An owner approves an SSO change by reading its summary: it names the
// provider the way the console does, never by its type id or row id.
func TestDescribeSSOChange_NamesProviders(t *testing.T) {
	change := func(kind ssochange.Kind, target string, payload any) *ssochange.Change {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return &ssochange.Change{Kind: kind, TargetID: target, Payload: raw}
	}
	const rowID = "0b0e6f4a-8d9c-4c58-9a51-2f7f3c1d2e10"
	name := "Corp SSO"
	cases := []struct {
		name   string
		change *ssochange.Change
		want   string
		absent []string
	}{
		{
			name: "create",
			change: change(ssochange.KindIdPCreate, "", IdPCreatePayload{
				Provider: "google_workspace", DisplayName: "Corp SSO", ClientID: "cid-1",
			}),
			want:   `add the Google Workspace identity provider "Corp SSO"`,
			absent: []string{"google_workspace"},
		},
		{
			name: "create with an unknown provider type",
			change: change(ssochange.KindIdPCreate, "", IdPCreatePayload{
				Provider: "made_up", DisplayName: "X",
			}),
			want:   `add the identity provider "X"`,
			absent: []string{"made_up"},
		},
		{
			name: "update",
			change: change(ssochange.KindIdPUpdate, rowID, IdPUpdatePayload{
				DisplayName: &name, TargetProvider: "entra_id", TargetName: "Corp SSO",
			}),
			want:   `change the Microsoft Entra ID identity provider "Corp SSO" (display name)`,
			absent: []string{rowID, "entra_id"},
		},
		{
			// Proposed before the summary named its target.
			name:   "update without a recorded target",
			change: change(ssochange.KindIdPUpdate, rowID, map[string]any{"client_secret_changed": true}),
			want:   "change an identity provider (client secret)",
			absent: []string{rowID},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DescribeSSOChange(tc.change)
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("summary %q, want prefix %q", got, tc.want)
			}
			for _, s := range tc.absent {
				if strings.Contains(got, s) {
					t.Fatalf("summary %q contains %q", got, s)
				}
			}
		})
	}
}

func TestProviderLabel(t *testing.T) {
	for p, want := range map[identityproviderdom.Provider]string{
		identityproviderdom.ProviderEntraID:         "Microsoft Entra ID",
		identityproviderdom.ProviderOkta:            "Okta",
		identityproviderdom.ProviderGoogleWorkspace: "Google Workspace",
		"unknown": "",
	} {
		if got := p.Label(); got != want {
			t.Errorf("%s.Label() = %q, want %q", p, got, want)
		}
	}
}
