/**
 * Inventory triage requests (research/124, RFC-054 §15): mark out of scope
 * in bulk (scope exclusions, with a preview), "Not ours" and its undo
 * (attribution decisions), and archive and its undo (asset status). The API
 * decides everything; these are thin calls.
 */

import { post } from '@/lib/api/client'

export interface ExclusionItem {
  exclusion_type: 'domain' | 'subdomain' | 'ip_address' | 'ip_range' | 'cidr'
  pattern: string
}

export interface ExclusionPreviewItem extends ExclusionItem {
  /** The caller's visible inventory assets it would match. */
  matched: number
  sample: string[]
  /** Set when the item would be refused. */
  code?: string
  message?: string
}

export interface ExclusionResult extends ExclusionItem {
  result: 'created' | 'exists' | 'refused'
  id?: string
  status?: string
  code?: string
  message?: string
}

export interface BulkExclusionsResponse {
  results: ExclusionResult[]
  created: number
  existing: number
  refused: number
}

/** Most items one bulk request takes. */
export const MAX_BULK_EXCLUSIONS = 200

export function previewExclusions(items: ExclusionItem[]) {
  return post<{ items: ExclusionPreviewItem[] }>('/api/v1/scope/exclusions/bulk/preview', { items })
}

export function createExclusions(items: ExclusionItem[], reason?: string) {
  return post<BulkExclusionsResponse>('/api/v1/scope/exclusions/bulk', {
    items,
    ...(reason ? { reason } : {}),
  })
}

/** The undo of createExclusions (widens scope: the client asks for re-authentication). */
export function deleteExclusions(ids: string[]) {
  return post('/api/v1/scope/exclusions/bulk/delete', { exclusion_ids: ids.slice(0, 100) })
}

/** rejected = "Not ours"; automatic = forget a person's decision (the undo). */
export function decideAttribution(assetIds: string[], state: 'rejected' | 'automatic') {
  return post<{ decided: { asset_id: string }[]; not_found: string[] }>(
    '/api/v1/easm/candidates/decisions',
    { asset_ids: assetIds.slice(0, MAX_BULK_EXCLUSIONS), state }
  )
}

/** Most assets one status change takes. */
export const MAX_BULK_STATUS = 100

export function setAssetsStatus(assetIds: string[], status: 'active' | 'archived') {
  return post<{ updated: number; failed: number }>('/api/v1/assets/bulk/status', {
    asset_ids: assetIds.slice(0, MAX_BULK_STATUS),
    status,
  })
}
