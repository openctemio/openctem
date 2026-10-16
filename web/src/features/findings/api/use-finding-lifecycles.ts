/**
 * The organization's finding lifecycles (api/docs/rfcs/RFC-110-tenant-lifecycles.md):
 * the sub-status catalog and the lifecycle schemes with their versions.
 * Reading needs findings:read; every change needs findings:lifecycles:write,
 * and publishing also needs a recent sign-in (the shared API client opens the
 * step-up dialog and retries once). The API validates and decides everything;
 * the console only edits and renders.
 */

import { useMemo } from 'react'
import useSWR, { type SWRConfiguration } from 'swr'
import { del, get, patch, post, put } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { SEVERITY_LEVELS } from '@/lib/severity'
import type { FindingStatus } from '../types'

export const LIFECYCLE_SUB_STATUSES_URL = '/api/v1/lifecycle-sub-statuses'
export const LIFECYCLES_URL = '/api/v1/lifecycles'

/** The canonical statuses, in lifecycle order: one lane each. */
export const CANONICAL_STATUSES: FindingStatus[] = [
  'new',
  'confirmed',
  'in_progress',
  'fix_applied',
  'resolved',
  'false_positive',
  'accepted',
  'duplicate',
]

/** Closed statuses: their sub-statuses bind one closure reason. */
export const CLOSED_STATUSES: FindingStatus[] = [
  'resolved',
  'false_positive',
  'accepted',
  'duplicate',
]

/** The reasons a sub-status of each closed status may bind (api ClosureReasonsFor). */
export const SUB_STATUS_CLOSURE_REASONS: Partial<Record<FindingStatus, string[]>> = {
  resolved: ['fixed', 'mitigated', 'obsolete_asset', 'obsolete_source', 'obsolete_rule'],
  false_positive: [
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
    'detection_error',
    'test_or_example_code',
  ],
  accepted: ['risk_accepted', 'compensating_control', 'wont_fix', 'no_fix_available'],
  duplicate: ['duplicate', 'correlated'],
}

export interface LifecycleSubStatus {
  id: string
  key: string
  canonical_status: FindingStatus
  closure_reason?: string
  name: string
  /** Per-language names, e.g. { vi: '...' }. */
  labels: Record<string, string>
  description: string
  color: string
  sort_order: number
  archived: boolean
  archived_at?: string
  created_at: string
  updated_at: string
}

export interface LifecycleSubStatusList {
  data: LifecycleSubStatus[]
  colors: string[]
}

export interface LifecycleSubStatusInput {
  key?: string
  canonical_status?: FindingStatus
  closure_reason?: string
  name?: string
  labels?: Record<string, string>
  description?: string
  color?: string
  sort_order?: number
}

/** A condition of a `when` or a context selector, from the closed field catalog. */
export interface LifecycleCondition {
  field: string
  op: string
  value?: unknown
}

export type GuardKind =
  'require_note' | 'require_fields' | 'require_permission' | 'deny_actor_kinds'

export interface LifecycleGuard {
  kind: GuardKind
  min_len?: number
  fields?: string[]
  any_of?: string[]
  kinds?: string[]
}

export interface LifecycleTransition {
  id: string
  name: string
  labels?: Record<string, string>
  /** Sub-status ids or `status:<canonical>`. */
  from: string[]
  /** A sub-status id or `status:<canonical>`. */
  to: string
  when?: LifecycleCondition[]
  guards?: LifecycleGuard[]
}

export type PersonMoves = 'canonical_plus_listed' | 'listed_only'

export interface LifecycleSpec {
  sub_statuses: string[]
  defaults?: Record<string, string>
  person_moves?: PersonMoves
  transitions: LifecycleTransition[]
}

export type LifecycleVersionState = 'draft' | 'published' | 'superseded'

export interface LifecycleVersion {
  version: number
  state: LifecycleVersionState
  spec: LifecycleSpec
  spec_hash: string
  note: string
  created_at: string
  created_by?: string
  published_at?: string
  published_by?: string
}

export interface Lifecycle {
  id: string
  key: string
  name: string
  description: string
  priority: number
  default: boolean
  context: LifecycleCondition[]
  archived: boolean
  published?: LifecycleVersion
  draft?: LifecycleVersion
  created_at: string
  updated_at: string
}

export interface LifecycleInput {
  key?: string
  name?: string
  description?: string
  priority?: number
  context?: LifecycleCondition[]
}

export interface LifecycleIssue {
  code: string
  path: string
  message: string
}

export interface LifecycleValidation {
  errors: LifecycleIssue[] | null
  warnings: LifecycleIssue[] | null
}

export interface LifecycleValidationResult {
  valid: boolean
  validation: LifecycleValidation
  version?: LifecycleVersion
}

/** The inputs a move may require (api RequiredFields), in display order. */
export const REQUIRED_FIELDS = [
  'ticket_link',
  'fix_reference',
  'change_id',
  'target_version',
  'due_date',
  'compensating_control',
] as const
export type RequiredField = (typeof REQUIRED_FIELDS)[number]

/** Delegated actors a move may refuse. */
export const DENIABLE_ACTOR_KINDS = ['workflow', 'ticket_inbound', 'api_key'] as const

/** Finding permissions a move may require on top of the platform's. */
export const LIFECYCLE_PERMISSIONS = [
  'findings:status',
  'findings:triage',
  'findings:verify',
  'findings:fix_apply',
  'findings:write',
] as const

/** Fields a `when` or context condition may read, and the operators each takes. */
export const CONDITION_FIELDS: Record<string, { ops: string[]; values?: string[] }> = {
  severity: {
    ops: ['eq', 'neq', 'in', 'not_in', 'gte', 'lte'],
    values: [...SEVERITY_LEVELS],
  },
  priority_class: {
    ops: ['eq', 'neq', 'in', 'not_in', 'gte', 'lte'],
    values: ['P0', 'P1', 'P2', 'P3'],
  },
  is_kev: { ops: ['eq', 'neq'], values: ['true', 'false'] },
  source: { ops: ['eq', 'neq', 'in', 'not_in', 'exists'] },
  finding_type: { ops: ['eq', 'neq', 'in', 'not_in', 'exists'] },
  tool_name: { ops: ['eq', 'neq', 'in', 'not_in', 'exists'] },
}

/** `status:<canonical>` place reference. */
export function statusRef(status: string): string {
  return `status:${status}`
}

/** The canonical status of a place reference, or undefined for a sub-status id. */
export function statusOfRef(ref: string): string | undefined {
  return ref.startsWith('status:') ? ref.slice('status:'.length) : undefined
}

export function lifecycleKey(id: string): string {
  return `${LIFECYCLES_URL}/${encodeURIComponent(id)}`
}

export function lifecycleVersionsKey(id: string): string {
  return `${lifecycleKey(id)}/versions`
}

/** The sub-status catalog; `archived` includes archived entries. */
export function useLifecycleSubStatuses(
  opts: { archived?: boolean; enabled?: boolean } = {},
  config?: SWRConfiguration
) {
  const { currentTenant } = useTenant()
  const enabled = opts.enabled ?? true
  const url = opts.archived
    ? `${LIFECYCLE_SUB_STATUSES_URL}?include_archived=true`
    : LIFECYCLE_SUB_STATUSES_URL
  return useSWR<LifecycleSubStatusList>(
    currentTenant && enabled ? url : null,
    (u: string) => get<LifecycleSubStatusList>(u),
    { revalidateOnFocus: false, ...config }
  )
}

export function useLifecycles(config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  return useSWR<{ data: Lifecycle[] }>(
    currentTenant ? LIFECYCLES_URL : null,
    (u: string) => get<{ data: Lifecycle[] }>(u),
    { revalidateOnFocus: false, ...config }
  )
}

export function useLifecycleVersions(id: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  return useSWR<{ data: LifecycleVersion[] }>(
    currentTenant && id ? lifecycleVersionsKey(id) : null,
    (u: string) => get<{ data: LifecycleVersion[] }>(u),
    { revalidateOnFocus: false, ...config }
  )
}

export function createSubStatus(input: LifecycleSubStatusInput) {
  return post<LifecycleSubStatus>(`${LIFECYCLE_SUB_STATUSES_URL}/`, input)
}

export function updateSubStatus(id: string, input: LifecycleSubStatusInput) {
  return patch<LifecycleSubStatus>(`${LIFECYCLE_SUB_STATUSES_URL}/${encodeURIComponent(id)}`, input)
}

export function archiveSubStatus(id: string) {
  return del<LifecycleSubStatus>(`${LIFECYCLE_SUB_STATUSES_URL}/${encodeURIComponent(id)}`)
}

export function reactivateSubStatus(id: string) {
  return post<LifecycleSubStatus>(
    `${LIFECYCLE_SUB_STATUSES_URL}/${encodeURIComponent(id)}/reactivate`
  )
}

export function createLifecycle(input: LifecycleInput) {
  return post<Lifecycle>(`${LIFECYCLES_URL}/`, input)
}

export function updateLifecycle(id: string, input: LifecycleInput) {
  return patch<Lifecycle>(lifecycleKey(id), input)
}

export function archiveLifecycle(id: string) {
  return del<void>(lifecycleKey(id))
}

/** A new draft, copied from version `from` (default: the published one). */
export function createLifecycleDraft(id: string, from?: number) {
  return post<LifecycleVersion>(lifecycleVersionsKey(id), from ? { from } : {})
}

/** Replaces the draft's spec; `specHash` is the hash read (409 when it changed since). */
export function saveLifecycleDraft(
  id: string,
  version: number,
  specHash: string,
  spec: LifecycleSpec,
  note?: string
) {
  return put<LifecycleValidationResult>(
    `${lifecycleVersionsKey(id)}/${version}`,
    { spec, note },
    { headers: { 'If-Match': `"${specHash}"` } }
  )
}

export function testLifecycleVersion(id: string, version: number) {
  return post<LifecycleValidationResult>(`${lifecycleVersionsKey(id)}/${version}/test`)
}

/** Puts a draft in force, or publishes an older version again (roll back). Needs step-up. */
export function publishLifecycleVersion(id: string, version: number, note?: string) {
  return post<LifecycleVersion>(`${lifecycleVersionsKey(id)}/${version}/publish`, { note })
}

/** The name of a sub-status in the reader's language. */
export function subStatusName(s: Pick<LifecycleSubStatus, 'name' | 'labels'>, locale: string) {
  return s.labels?.[locale] || s.name
}

/**
 * The catalog by id, archived entries included (a finding may still carry
 * one), for showing a finding's sub-status. One request per page, shared by
 * every caller through SWR.
 */
export function useSubStatusCatalog(enabled = true): Map<string, LifecycleSubStatus> {
  const { data } = useLifecycleSubStatuses(
    { archived: true, enabled },
    { dedupingInterval: 60_000 }
  )
  return useMemo(() => new Map((data?.data ?? []).map((s) => [s.id, s])), [data])
}
