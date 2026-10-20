/**
 * Lowering an asset's risk inputs (api docs/architecture/asset-risk-governance.md).
 *
 * Exposure and criticality feed the priority class of every finding on the
 * asset. Raising them is free. Lowering them shows what it would do to the
 * asset's open findings first, and when it would drop an open P0/P1 finding
 * the change waits for a second person under the organization's approval
 * policy (the API answers 202 and keeps the asset's values).
 */
import { post } from '@/lib/api/client'

/** How reachable an asset is; an unknown exposure counts like restricted. */
const EXPOSURE_RANK: Record<string, number> = {
  public: 4,
  restricted: 3,
  unknown: 3,
  private: 2,
  isolated: 1,
}

const CRITICALITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
}

export type LoweredField = 'exposure' | 'criticality'

/** The inputs a form value lowers (a field that is not set is not lowered). */
export function loweredRiskFields(
  before: { exposure?: string; criticality?: string },
  after: { exposure?: string; criticality?: string }
): LoweredField[] {
  const out: LoweredField[] = []
  if (
    after.exposure &&
    (EXPOSURE_RANK[after.exposure] ?? 3) < (EXPOSURE_RANK[before.exposure ?? ''] ?? 3)
  ) {
    out.push('exposure')
  }
  if (
    after.criticality &&
    (CRITICALITY_RANK[after.criticality] ?? 0) < (CRITICALITY_RANK[before.criticality ?? ''] ?? 0)
  ) {
    out.push('criticality')
  }
  return out
}

export interface RiskImpact {
  lowered_fields: string[]
  open_findings: number
  class_drops: number
  p0_p1_drops: number
  raised: number
  moves: { from: string; to: string; count: number }[]
  manual_overrides_kept: number
}

export interface RiskApprovalView {
  /** The change would wait for a second person. */
  required: boolean
  tier: string
  required_approvals: number
  reasons: string[]
  eligible_approvers: number
  /** Enough eligible people exist to approve it. */
  satisfiable: boolean
  min_note_length: number
  step_up: boolean
}

export interface RiskPreview {
  impact: RiskImpact
  approval?: RiskApprovalView
  pending_request: boolean
}

export interface RiskRequest {
  id: string
  lowered_fields: string[]
  reason: string
  status: string
  tier: string
  required_approvals: number
  approvals_collected: number
  decide_by: string
  created_at: string
  requested_by?: string
}

/** What lowering the given inputs would do to the asset's open findings. */
export function previewRiskImpact(
  assetId: string,
  body: { exposure?: string; criticality?: string }
): Promise<RiskPreview> {
  return post<RiskPreview>(`/api/v1/assets/${encodeURIComponent(assetId)}/risk-impact`, body)
}
