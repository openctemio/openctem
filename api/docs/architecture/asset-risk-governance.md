# Asset risk governance

Status: shipped for the asset edit, the crown-jewel flag and the attribute lock (migration `asset_risk_requests`). Designed and not shipped: see "Not covered yet".

Exposure, criticality and the crown-jewel flag decide the priority class of every finding on an asset (a public asset's critical finding is P1; the same finding on an isolated one is P2). Anyone who can edit an asset, including a member and the asset's own owner, can set them. Without a check, the person who has to fix the findings could shorten their own queue by lowering the asset.

Raising risk stays free. Lowering it shows its impact first, and when it would lower an open P0 or P1 finding it is decided under the organization's approval policy.

## What counts as lowering

| Input | Lowered when |
|---|---|
| exposure | the new value is less reachable: public, then restricted (unknown counts the same), then private, then isolated |
| criticality | the new value is lower: critical, high, medium, low, none |
| crown jewel | the flag is removed |

`asset.LoweredFields` (`pkg/domain/asset/risk_change.go`) is the one definition.

## Preview

`POST /api/v1/assets/{id}/risk-impact` with any of `exposure`, `criticality`, `is_crown_jewel` (omitted fields keep the asset's values). It classifies the asset's open findings with the proposed inputs, using the same enrichment and rules as the finding-priority worker, and compares with the stored class. Read-only. The answer:

- `impact`: `open_findings`, `class_drops`, `p0_p1_drops`, `raised`, the `moves` (`P1` to `P2`: n) and `manual_overrides_kept` (a class a person set does not move);
- `approval` (when a P0/P1 would drop): whether a second person is needed for the caller, the tier, the required approvals, the eligible approvers and whether enough exist;
- `pending_request`: the asset already has a request waiting.

The asset must be in the caller's data scope (404 otherwise); the findings counted are the ones the caller may see.

## Deciding an edit

`PUT /assets/{id}` (also `risk_change_reason`), `PATCH /assets/{id}/crown-jewel` and `PUT /assets/{id}/attribute-sources/{criticality|exposure}/lock` (also `reason`) run the same decision before anything is applied:

1. Nothing is lowered: applied as before.
2. Lowered, and no open P0/P1 would drop: applied, no reason needed.
3. Lowered, and an open P0/P1 would drop: a reason is required (400 without one). The approval policy is evaluated on the worst finding that would drop, with the organization's false-positive level (`all`, `high_and_above`, `off`, plus the policy's tiers, exclusions and security pool), exactly as for a false positive:
   - the caller may decide alone (level allows it, they hold `findings:approve`, they do not own the asset): applied, audited as `asset_risk.lowered` at High severity with the reason and the impact;
   - otherwise the lowered fields are **not applied** and a pending request is stored (202, `pending_request` on the asset). The rest of the edit (name, description, a raised value) is applied. The people who may approve are told in-app. With no eligible approver the edit is refused (409) rather than left waiting for nobody.

One request is pending per asset (409 for a second). A request waits for the policy's decision window (7 days when it names none) and then expires.

## Requests

`GET /assets/{id}/risk-requests/pending`; `POST /assets/{id}/risk-requests/{request_id}/approve` and `/reject` (`findings:approve`), `/cancel` (`assets:write`, the requester only).

- Approve evaluates the policy again on the facts of that moment; the requester and the asset's owners never approve (403); each approval is a row in `approval_signoffs` (`subject_type = asset_risk_request`); step-up when the tier asks for it. The last approval applies the lowered fields in the same transaction as the request row, through the ordinary edit path (the values become the requester's locks, the asset is rescored and the change is on its timeline), and only while the asset still has the values the request was made from (otherwise 409: request again).
- Reject needs a reason; the requester withdraws instead of rejecting.
- A request on another tenant's or another asset's id is 404.

Audit actions: `asset_risk.lowered` (High), `asset_risk.requested`, `asset_risk.signed`, `asset_risk.approved` (High), `asset_risk.request_closed`.

## Threat model

Lowering risk inputs hides risk the way a false positive does (class, SLA urgency for new findings, the P0/P1 queue, dashboards). Controls: the decision runs in the service, before the write, for every route that can lower the inputs; the same approval policy, approver pool, step-up and sign-off rows as other finding decisions (no second mechanism); the requester and asset owners never approve; a reason is required where it matters; the impact is counted on the asset's own findings under the caller's data scope; a request is bound to the values it was made from and applies only while they hold; tenant on every statement; every step audited.

Platform-internal writers (a scan, a sensor report, an integration, an approved request) are not governed here: they carry their own source ranking (asset attribute sources).

## Not covered yet

- Fresh external scan evidence of exposure does not yet override a manual `isolated` value until the evidence expires. Today a person's lock ranks first for display and for the classifier; the approval above is the control.
- Bulk edits in the inventory (criticality for many assets) go through the same decision per asset; an asset that needs a reason or approval is reported as failed in the bulk result.
- A banner on the asset page to approve, reject or withdraw a pending request: the API is complete, the web currently shows the impact and the "waiting for approval" state in the edit dialog only.
- The asset's primary owner is not yet told when someone decides alone.

## Key files

- `api/pkg/domain/asset/risk_change.go` (inputs, lowering, request, repository interface)
- `api/internal/app/finding/asset_risk_governance.go` (simulation, decision, approvals)
- `api/internal/app/asset/risk_governance.go` (the asset service side)
- `api/internal/infra/postgres/asset_risk_request_repository.go`, migration `asset_risk_requests`
- `api/internal/infra/http/handler/asset_risk_governance_handler.go`
- `web/src/features/assets/components/asset-risk-impact-notice.tsx`
