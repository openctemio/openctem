package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	identityproviderdom "github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type byIDIPRepo struct {
	fakeIPRepo
	ip *identityproviderdom.IdentityProvider
}

func (f *byIDIPRepo) GetByID(context.Context, string, string) (*identityproviderdom.IdentityProvider, error) {
	return f.ip, nil
}

func storedOIDCProvider(tenantID string) *identityproviderdom.IdentityProvider {
	now := time.Now()
	return identityproviderdom.Reconstruct(shared.NewID().String(), tenantID, identityproviderdom.Provider("okta"),
		"Okta", "client-1", "stored-secret", "https://idp.corp.example", "", nil, nil, false, "member", true, nil, now, now, "")
}

func strp(s string) *string { return &s }

// The client secret goes to the issuer's token endpoint at every sign-in, so
// moving the provider to another issuer (or Entra directory) must come with
// a new secret.
func TestBuildProviderUpdate_IssuerChangeNeedsNewSecret(t *testing.T) {
	tenantID := shared.NewID().String()
	for name, tc := range map[string]struct {
		in      UpdateProviderInput
		wantErr bool
	}{
		"new issuer, no secret":       {UpdateProviderInput{IssuerURL: strp("https://idp.other.example")}, true},
		"new issuer, empty secret":    {UpdateProviderInput{IssuerURL: strp("https://idp.other.example"), ClientSecret: strp("")}, true},
		"new issuer, new secret":      {UpdateProviderInput{IssuerURL: strp("https://idp.other.example"), ClientSecret: strp("fresh")}, false},
		"same issuer":                 {UpdateProviderInput{IssuerURL: strp("https://idp.corp.example")}, false},
		"same issuer, case and slash": {UpdateProviderInput{IssuerURL: strp("https://IDP.corp.example/")}, false},
		"other fields only":           {UpdateProviderInput{DisplayName: strp("Corp")}, false},
		"new org, no secret":          {UpdateProviderInput{TenantIdentifier: strp("https://dev-2.okta.com")}, true},
	} {
		t.Run(name, func(t *testing.T) {
			ip := storedOIDCProvider(tenantID)
			s := newSSOForTest(&fakeIPRepo{}, enabledEntra())
			s.ipRepo = &byIDIPRepo{ip: ip}
			tc.in.TenantID, tc.in.ID = tenantID, ip.ID()
			got, err := s.BuildProviderUpdate(context.Background(), tc.in)
			if tc.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("err = %v, want a validation error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if tc.in.ClientSecret != nil && *tc.in.ClientSecret != "" && got.ClientSecretEncrypted() != "fresh" {
				t.Fatalf("secret = %q, want the new one", got.ClientSecretEncrypted())
			}
		})
	}
}
