package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The shared reads of the bootstrap (support access, AI setup, SLA windows)
// answer what their endpoints answer for the same caller: the same permission
// and module gates, the token's own tenant, and nothing when a source fails.

type sharedReadCalls struct {
	support, ai, sla bool
	tenant           shared.ID
}

func sharedReadsHandler(c *sharedReadCalls, failing bool) *BootstrapHandler {
	down := errors.New("source down")
	return (&BootstrapHandler{logger: logger.NewNop()}).WithSession(BootstrapSession{
		SupportAccess: func(_ context.Context, tenantID shared.ID) (*SupportActiveResponse, error) {
			c.support, c.tenant = true, tenantID
			if failing {
				return nil, down
			}
			return &SupportActiveResponse{Data: []SupportActiveGrant{{AdminName: "Support"}}}, nil
		},
		AIConfig: func(_ context.Context, tenantID shared.ID) (any, error) {
			c.ai, c.tenant = true, tenantID
			if failing {
				return nil, down
			}
			return map[string]any{"mode": "platform", "is_enabled": true}, nil
		},
		SLA: func(_ context.Context, tenantID shared.ID) (*BootstrapSLA, error) {
			c.sla, c.tenant = true, tenantID
			if failing {
				return nil, down
			}
			return &BootstrapSLA{Policy: SLAPolicyResponse{CriticalDays: 7}}, nil
		},
	})
}

func TestBootstrapSharedReads_FullCaller(t *testing.T) {
	c := &sharedReadCalls{}
	resp := withModules(module.ModuleAITriage)
	perms := []string{permission.TeamRead.String(), permission.FindingsRead.String(), permission.AITriageRead.String(), permission.AssetsRead.String()}
	sharedReadsHandler(c, false).addSession(bsRequest(t, bsUserEntity(t, bsUser), perms, false), resp, bsTenant, bsUser)

	if resp.SupportAccess == nil || len(resp.SupportAccess.Data) != 1 {
		t.Fatalf("support_access = %+v", resp.SupportAccess)
	}
	if resp.AIConfig == nil {
		t.Fatal("ai_config missing for a caller with ai_triage:read and the module on")
	}
	if resp.SLA == nil || resp.SLA.Policy.CriticalDays != 7 {
		t.Fatalf("sla = %+v", resp.SLA)
	}
	if c.tenant.String() != bsTenant {
		t.Fatalf("read for tenant %s, want the token's", c.tenant)
	}
}

// A user without the AI module, the AI permission, the SLA (assets:read)
// permission or team:read gets none of those fields, and the sources are not
// even asked.
func TestBootstrapSharedReads_GatedByPermissionAndModule(t *testing.T) {
	cases := []struct {
		name    string
		perms   []string
		modules []string
	}{
		{"no ai module", []string{permission.FindingsRead.String(), permission.AITriageRead.String(), permission.AssetsRead.String(), permission.TeamRead.String()}, nil},
		{"no ai permission", []string{permission.FindingsRead.String()}, []string{module.ModuleAITriage}},
		{"ai permission without findings read", []string{permission.AITriageRead.String()}, []string{module.ModuleAITriage}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &sharedReadCalls{}
			resp := withModules(tc.modules...)
			sharedReadsHandler(c, false).addSession(bsRequest(t, bsUserEntity(t, bsUser), tc.perms, false), resp, bsTenant, bsUser)
			if c.ai || resp.AIConfig != nil {
				t.Fatalf("ai config read=%v field=%v", c.ai, resp.AIConfig)
			}
		})
	}

	t.Run("no sla permission and no team read", func(t *testing.T) {
		c := &sharedReadCalls{}
		resp := withModules(module.ModuleAITriage)
		perms := []string{permission.FindingsRead.String(), permission.AITriageRead.String()}
		sharedReadsHandler(c, false).addSession(bsRequest(t, bsUserEntity(t, bsUser), perms, false), resp, bsTenant, bsUser)
		if c.sla || resp.SLA != nil {
			t.Fatalf("sla read=%v field=%v for a caller without assets:read", c.sla, resp.SLA)
		}
		if c.support || resp.SupportAccess != nil {
			t.Fatalf("support access read=%v field=%v for a caller without team:read", c.support, resp.SupportAccess)
		}
		if !c.ai || resp.AIConfig == nil {
			t.Fatal("the AI setup is still due to a caller who may read it")
		}
	})
}

func TestBootstrapSharedReads_AFailingSourceIsLeftOut(t *testing.T) {
	c := &sharedReadCalls{}
	resp := withModules(module.ModuleAITriage)
	sharedReadsHandler(c, true).addSession(bsRequest(t, bsUserEntity(t, bsUser), nil, true), resp, bsTenant, bsUser)
	if resp.SupportAccess != nil || resp.AIConfig != nil || resp.SLA != nil {
		t.Fatalf("fields after failures: %+v", resp)
	}
}
