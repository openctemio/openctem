import type { Severity } from '@/features/shared'

/**
 * A remediation group: the set of open findings a single fix resolves
 * (RFC-015). One patch/upgrade closes the whole family.
 */
export interface RemediationGroup {
  /** Stable fix-identity key (sca:<component> or sol:<hash>). */
  key: string
  /** Human-readable fix action, e.g. "Upgrade OpenSSL to 3.0.7". */
  title: string
  finding_count: number
  asset_count: number
  /** Count per severity bucket (critical/high/medium/low/info). */
  severity_counts: Partial<Record<Severity, number>>
  fix_available: boolean
}

export interface RemediationGroupsResponse {
  groups: RemediationGroup[]
}

/** A group resolve is a "mark fixed" (shared with campaigns). */
export type {
  MarkFixedRequest as ResolveGroupRequest,
  MarkFixedResult as ResolveGroupResult,
} from '@/features/remediation/api/mark-fixed.types'
