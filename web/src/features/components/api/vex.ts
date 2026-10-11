'use client'

/**
 * The organization's VEX statements (api/docs/rfcs/RFC-070-software-components-inventory.md).
 * Reading needs components:read; writing needs findings:approve, and the API
 * also checks the caller's data scope (a statement for every asset needs
 * access to every asset).
 */

import useSWR from 'swr'
import { del, get, patch, post } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import { toQuery } from './hooks'
import type { ListResponse } from './types'

export const VEX_BASE = '/api/v1/vex-statements'

export const VEX_STATUSES = ['not_affected', 'affected', 'fixed', 'under_investigation'] as const
export type VexStatus = (typeof VEX_STATUSES)[number]

export const VEX_JUSTIFICATIONS = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
] as const
export type VexJustification = (typeof VEX_JUSTIFICATIONS)[number]

export interface VexStatement {
  id: string
  vuln_id: string
  product_id: string
  versions: string[]
  version_range?: string
  asset_id?: string
  status: VexStatus
  justification?: VexJustification
  impact_statement?: string
  action_statement?: string
  origin: 'manual' | 'document'
  document_ref?: string
  expires_at?: string
  expired: boolean
  created_at: string
  updated_at: string
}

export interface VexApplyResult {
  matched: number
  closed: number
  reopened: number
  finding_ids?: string[]
}

export interface VexWriteResponse {
  statement: VexStatement
  applied: VexApplyResult
}

export interface VexStatementInput {
  vuln_id?: string
  product_id?: string
  asset_id?: string
  versions?: string[]
  version_range?: string
  status: VexStatus
  justification?: string
  impact_statement?: string
  action_statement?: string
  expires_at?: string
  clear_expiry?: boolean
}

export interface VexImportItem {
  vuln_id: string
  purl: string
  product_id: string
  versions: string[] | null
  status: VexStatus
  justification?: string
  action: 'create' | 'update' | 'unchanged'
}

export interface VexImportResult {
  format: string
  dry_run: boolean
  statements: number
  created: number
  updated: number
  unchanged: number
  skipped_total: number
  skipped: { vuln_id?: string; purl?: string; reason: string }[]
  issues: string[]
  items: VexImportItem[]
  applied: VexApplyResult
}

/** Statements about one package (the API hides what the caller may not see). */
export function useVexStatements(productId: string | null | undefined) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const enabled = Boolean(currentTenant) && can(Permission.ComponentsRead) && Boolean(productId)
  return useSWR<ListResponse<VexStatement>>(
    enabled ? `${VEX_BASE}${toQuery({ product_id: productId, per_page: 100 })}` : null,
    (url: string) => get<ListResponse<VexStatement>>(url),
    { revalidateOnFocus: false }
  )
}

export function createVexStatement(input: VexStatementInput): Promise<VexWriteResponse> {
  return post<VexWriteResponse>(VEX_BASE, input)
}

export function updateVexStatement(
  id: string,
  input: VexStatementInput
): Promise<VexWriteResponse> {
  return patch<VexWriteResponse>(`${VEX_BASE}/${encodeURIComponent(id)}`, input)
}

export function deleteVexStatement(id: string): Promise<{ applied: VexApplyResult }> {
  return del<{ applied: VexApplyResult }>(`${VEX_BASE}/${encodeURIComponent(id)}`)
}

export function importVexDocument(
  document: unknown,
  assetId: string | null,
  dryRun: boolean
): Promise<VexImportResult> {
  return post<VexImportResult>(
    `${VEX_BASE}/import${toQuery({ asset_id: assetId, dry_run: dryRun ? 'true' : undefined })}`,
    document
  )
}

/** Splits a comma or space separated version list. */
export function parseVersions(text: string): string[] {
  return Array.from(
    new Set(
      text
        .split(/[\s,]+/)
        .map((v) => v.trim())
        .filter(Boolean)
    )
  )
}
