package auth

import (
	"context"
	"errors"
	"testing"

	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// fakeDomainJIT adds per-domain JIT (RFC-058) to the verified-domain fake.
type fakeDomainJIT struct {
	fakeDomainVerifier
	on   map[string]bool
	role map[string]string
	err  error
}

func (f *fakeDomainJIT) DomainJITPolicy(_ context.Context, _ string, domain string) (bool, string, error) {
	if f.err != nil {
		return false, "", f.err
	}
	return f.on[domain], f.role[domain], nil
}

func TestDomainJIT(t *testing.T) {
	verified := map[string]bool{"corp.com": true, "sub.corp.com": true, "old.com": true}
	for _, tc := range []struct {
		name     string
		email    string
		lookup   error
		wantErr  error
		wantRole tenantdom.Role
	}{
		{"domain role overrides the provider default", "a@sub.corp.com", nil, nil, tenantdom.RoleViewer},
		{"no domain role keeps the provider default", "a@corp.com", nil, nil, tenantdom.RoleMember},
		{"JIT off on the domain refuses newcomers", "a@old.com", nil, ErrSSONotAMember, ""},
		{"lookup failure refuses (fail closed)", "a@corp.com", errors.New("db down"), ErrSSONotAMember, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, u, tenant, mr := memberTestFixtures(t)
			svc.domainVerifier = &fakeDomainJIT{
				fakeDomainVerifier: fakeDomainVerifier{verified: verified},
				on:                 map[string]bool{"corp.com": true, "sub.corp.com": true, "old.com": false},
				role:               map[string]string{"sub.corp.com": "viewer"},
				err:                tc.lookup,
			}
			rp := &resolvedProvider{autoProvision: true, defaultRole: "member"}
			err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, tc.email)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || mr.created != nil {
					t.Fatalf("want %v and no membership, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil || mr.created == nil {
				t.Fatalf("want provisioned, got %v", err)
			}
			if mr.created.Role() != tc.wantRole {
				t.Fatalf("role = %s, want %s", mr.created.Role(), tc.wantRole)
			}
		})
	}
}
