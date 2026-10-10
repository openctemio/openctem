/**
 * Scan approval governance (RFC-073): the organization's settings, the New
 * Scan preview, a scan's approval state, and the approvals inbox.
 * The backend is the authority: these calls only show what it decided.
 */

import useSWR, { type SWRConfiguration } from 'swr'
import { get, post, put } from './client'
import { useTenant } from '@/context/tenant-provider'

export type ScanApprovalMode = 'off' | 'on' | 'strict'
export type ScanApprovalValidity = 'run' | 'days' | 'definition'
export type ScanApprovalStatus =
  'pending' | 'approved' | 'rejected' | 'expired' | 'superseded' | 'canceled'

export interface ScanApprovalConditions {
  min_intensity?: 'passive' | 'active' | 'intrusive'
  tools?: string[]
  asset_tags?: string[]
  min_criticality?: 'low' | 'medium' | 'high' | 'critical'
  crown_jewel?: boolean
  dynamic_selectors?: boolean
  targets_over?: number
  cidr_wider_than?: number
  recurring?: boolean
  sensor_placement?: 'platform' | 'tenant'
  zone_ids?: string[]
}

export interface ScanApprovalRequirement {
  approvals: number
  approver_roles?: string[]
  approver_user_ids?: string[]
  require_justification?: boolean
  require_ticket?: boolean
  ticket_pattern?: string
  validity?: ScanApprovalValidity
  validity_days?: number
}

export interface ScanApprovalRule {
  id: string
  name: string
  enabled: boolean
  monitor?: boolean
  conditions: ScanApprovalConditions
  requirement: ScanApprovalRequirement
}

export interface ScanGovernanceSettings {
  mode: ScanApprovalMode
  source: 'organization' | 'platform'
  organization_mode: ScanApprovalMode
  platform_policy: 'tenant_controlled' | 'off' | 'on' | 'strict'
  selectable_modes: ScanApprovalMode[]
  scope_entries_need_approval: boolean
  rules: ScanApprovalRule[]
  pending_expiry_days: number
  presets: Record<string, ScanApprovalRule[]>
}

export interface MatchedRule {
  id: string
  name: string
  monitor?: boolean
  requirement: ScanApprovalRequirement
}

export interface ScanApprovalEvaluation {
  mode: ScanApprovalMode
  required: boolean
  matched?: MatchedRule[]
  monitored?: MatchedRule[]
  decisive?: string
  approvals?: number
  approver_roles?: string[]
  approver_user_ids?: string[]
  require_justification?: boolean
  require_ticket?: boolean
  ticket_patterns?: string[]
  validity?: ScanApprovalValidity
  validity_days?: number
}

export interface ActorRef {
  kind?: string
  id: string
  name?: string
}

export interface ScanDefinitionChange {
  field: string
  before: unknown
  after: unknown
}

export interface ScanApprovalRequest {
  id: string
  scan_id: string
  scan_name: string
  status: ScanApprovalStatus
  definition_digest: string
  definition: {
    targets?: string[]
    asset_group_ids?: string[]
    scan_type?: string
    scanner_name?: string
    workflow_steps?: string[]
    intensity?: string
    schedule_type?: string
    sensor_preference?: string
    scan_zone_id?: string
  }
  changes: ScanDefinitionChange[]
  evaluation: ScanApprovalEvaluation
  justification?: string
  ticket?: string
  run_on_approval: boolean
  requested_by?: ActorRef
  requested_at: string
  expires_at: string
  approvals: {
    approver?: ActorRef
    approved_at: string
    note?: string
    self: boolean
    emergency: boolean
  }[]
  remaining: number
  valid_until?: string
  decided_at?: string
  decided_by?: ActorRef
  decision_note?: string
  reminded_at?: string
  emergency: boolean
  can_approve: boolean
  self_approval_available: boolean
  eligible_approver_count: number
  eligible_approvers?: ActorRef[]
}

export interface ScanApprovalStatusResponse {
  mode: ScanApprovalMode
  evaluation: ScanApprovalEvaluation
  required: boolean
  approved: boolean
  current?: ScanApprovalRequest
  changes: ScanDefinitionChange[]
}

export interface ScanApprovalPreviewInput {
  targets: string[]
  asset_group_ids: string[]
  scan_type: string
  scanner_name?: string
  scan_workflow_id?: string
  schedule_type?: string
  sensor_preference?: string
  run_on_tenant_runner?: boolean
  scan_zone_id?: string
}

const SETTINGS = '/api/v1/organization/settings/scan-governance'
const APPROVALS = '/api/v1/scan-approvals'

export const scanApprovalKeys = {
  settings: SETTINGS,
  list: (status: string) => `${APPROVALS}?status=${encodeURIComponent(status)}&per_page=100`,
  scan: (scanId: string) => `/api/v1/scans/${encodeURIComponent(scanId)}/approval`,
}

/** The organization's scan approval settings. */
export function useScanGovernance(config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  return useSWR<ScanGovernanceSettings>(
    currentTenant ? SETTINGS : null,
    (url: string) => get<ScanGovernanceSettings>(url),
    config
  )
}

/** Owner only, with step-up (the client asks for it) and a reason. */
export function saveScanGovernanceMode(mode: ScanApprovalMode, reason: string) {
  return put<ScanGovernanceSettings>(`${SETTINGS}/mode`, { mode, reason })
}

/** Owner or administrator, with step-up and a reason. */
export function saveScanGovernanceRules(
  rules: ScanApprovalRule[],
  pendingExpiryDays: number,
  reason: string
) {
  return put<ScanGovernanceSettings>(`${SETTINGS}/rules`, {
    rules,
    pending_expiry_days: pendingExpiryDays,
    reason,
  })
}

/** Which rules an unsaved scan would need (the New Scan review). */
export function useScanApprovalPreview(input: ScanApprovalPreviewInput | null) {
  const { currentTenant } = useTenant()
  const key = currentTenant && input ? ['scan-approval-preview', JSON.stringify(input)] : null
  return useSWR<ScanApprovalEvaluation>(
    key,
    () => post<ScanApprovalEvaluation>('/api/v1/scans/approval-preview', input),
    { revalidateOnFocus: false, dedupingInterval: 2000 }
  )
}

/** A scan's approval state. */
export function useScanApprovalStatus(scanId: string | null) {
  const { currentTenant } = useTenant()
  return useSWR<ScanApprovalStatusResponse>(
    currentTenant && scanId ? scanApprovalKeys.scan(scanId) : null,
    (url: string) => get<ScanApprovalStatusResponse>(url)
  )
}

export function submitScanApproval(
  scanId: string,
  input: { justification: string; ticket: string; run_on_approval: boolean }
) {
  return post<ScanApprovalRequest>(scanApprovalKeys.scan(scanId), input)
}

/** The approvals inbox. */
export function useScanApprovals(status: string) {
  const { currentTenant } = useTenant()
  return useSWR<{ data: ScanApprovalRequest[]; total: number }>(
    currentTenant ? scanApprovalKeys.list(status) : null,
    (url: string) => get<{ data: ScanApprovalRequest[]; total: number }>(url)
  )
}

export function approveScanRequest(id: string, note: string) {
  return post<ScanApprovalRequest>(`${APPROVALS}/${encodeURIComponent(id)}/approve`, { note })
}

export function rejectScanRequest(id: string, note: string) {
  return post<ScanApprovalRequest>(`${APPROVALS}/${encodeURIComponent(id)}/reject`, { note })
}

export function selfApproveScanRequest(id: string, reason: string, totpCode: string) {
  return post<ScanApprovalRequest>(`${APPROVALS}/${encodeURIComponent(id)}/self-approve`, {
    reason,
    totp_code: totpCode,
  })
}

export function remindScanApprovers(id: string) {
  return post<ScanApprovalRequest>(`${APPROVALS}/${encodeURIComponent(id)}/remind`, {})
}

export function cancelScanRequest(id: string) {
  return post<ScanApprovalRequest>(`${APPROVALS}/${encodeURIComponent(id)}/cancel`, {})
}

export function emergencyRunScan(scanId: string, reason: string, hours: number) {
  return post<ScanApprovalRequest>(`/api/v1/scans/${encodeURIComponent(scanId)}/emergency-run`, {
    reason,
    hours,
  })
}
