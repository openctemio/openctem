package handler

// A person's Confirm adds the asset's exact scope entry (research/117): the
// caller the confirmation acts as, and the audit of the entries it added.

import (
	"context"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// confirmActor is the authenticated caller as the scope service sees it.
// Nothing comes from the request body.
func confirmActor(ctx context.Context) easmapp.ScopeActor {
	return easmapp.ScopeActor{
		Actor: scope.Actor{
			UserID:     middleware.GetUserID(ctx),
			CanApprove: middleware.HasPermission(ctx, permission.ScopeApprove.String()),
		},
		CanWriteScope: middleware.HasPermission(ctx, permission.ScopeWrite.String()),
	}
}

// auditConfirmEntries records each scope entry a confirmation added, as an
// ordinary scope entry creation.
func auditConfirmEntries(ctx context.Context, audit AttributionAuditor, actx auditapp.AuditContext, res *easmapp.ConfirmScopeResult, via string) {
	if audit == nil || res == nil {
		return
	}
	for _, e := range res.Entries {
		if e.Outcome != easmapp.EntryAdded || e.TargetID == "" {
			continue
		}
		auditapp.RecordOrWarn(ctx, nil, audit, actx, auditapp.NewSuccessEvent(auditdom.ActionScopeTargetCreated, auditdom.ResourceTypeScopeTarget, e.TargetID).
			WithResourceName(e.Pattern).WithMessage("Scope entry added: a person confirmed the asset as the organization's").
			WithMetadata("via", via).WithMetadata("origin", "confirmed_asset").WithMetadata("asset_id", e.AssetID).
			WithMetadata("status", e.Status))
	}
}
