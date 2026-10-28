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
  /** Open findings on those assets: what a permanent not_ours or retired exclusion closes. */
  open_findings?: number
  /** Limited data access and not an exact hostname or IP: a closing rule needs full data access. */
  closing_needs_full_access?: boolean
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

/**
 * Why something is out of scope (research/320). Every kind stops scanning;
 * not_ours and retired, when permanent, also close the open findings of what
 * they match (reopened when the exclusion goes).
 */
export type ExclusionKind = 'not_ours' | 'retired' | 'do_not_scan'

export interface CreateExclusionsOptions {
  reason?: string
  kind?: ExclusionKind
  /** ISO time; omitted = until re-included. */
  expiresAt?: string
}

export function createExclusions(items: ExclusionItem[], opts: CreateExclusionsOptions = {}) {
  return post<BulkExclusionsResponse>('/api/v1/scope/exclusions/bulk', {
    items,
    ...(opts.reason ? { reason: opts.reason } : {}),
    ...(opts.kind ? { kind: opts.kind } : {}),
    ...(opts.expiresAt ? { expires_at: opts.expiresAt } : {}),
  })
}

/** Ids one bulk delete takes on every server version. */
const DELETE_CHUNK = 100

/**
 * The undo of createExclusions (widens scope: the client asks for
 * re-authentication). Every id is sent, in chunks, so an undo never leaves
 * part of a batch in place.
 */
export async function deleteExclusions(ids: string[]) {
  for (let i = 0; i < ids.length; i += DELETE_CHUNK) {
    await post('/api/v1/scope/exclusions/bulk/delete', {
      exclusion_ids: ids.slice(i, i + DELETE_CHUNK),
    })
  }
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
