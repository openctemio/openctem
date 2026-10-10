/**
 * Asset change timeline (RFC-069 §11): what changed on an asset, when, from
 * which source and why. One entry per change of a value or of the source
 * that decides it; re-sightings are not listed.
 */

import type { SourceKind, TrackedAttribute } from './attribute-sources'

export type ChangeReason =
  | 'newer_observation'
  | 'manual_lock'
  | 'lock_released'
  | 'ttl_expiry'
  | 'policy_change'
  | 'source_removed'

export interface AssetChange {
  id: string
  asset_id: string
  asset_name?: string
  asset_type?: string
  at: string
  attribute: TrackedAttribute | string
  old_value: string
  new_value: string
  added?: string[]
  removed?: string[]
  source: { kind: SourceKind; name: string; run: string }
  actor_id?: string
  reason: ChangeReason
  flap_count: number
}

export interface AssetChangePage {
  items: AssetChange[]
  next_cursor: string
}

export interface ChangeFilters {
  attribute?: string
  sourceKind?: string
  tag?: string
}

export const TIMELINE_PAGE_SIZE = 50

/** The URL of one page: an asset's timeline, or the organization feed. */
export function changesUrl(assetId: string | null, f: ChangeFilters, cursor?: string): string {
  const base = assetId
    ? `/api/v1/assets/${encodeURIComponent(assetId)}/changes`
    : '/api/v1/assets/changes'
  const q = new URLSearchParams({ limit: String(TIMELINE_PAGE_SIZE) })
  if (f.attribute) q.set('attribute', f.attribute)
  if (f.sourceKind) q.set('source_kind', f.sourceKind)
  if (!assetId && f.tag?.trim()) q.set('tag', f.tag.trim())
  if (cursor) q.set('cursor', cursor)
  return `${base}?${q.toString()}`
}

/** The local calendar day of a timestamp, as YYYY-MM-DD (sortable). */
export function dayKey(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const m = String(d.getMonth() + 1).padStart(2, '0')
  const day = String(d.getDate()).padStart(2, '0')
  return `${d.getFullYear()}-${m}-${day}`
}

/** Events grouped by local day, newest day first, order kept within a day. */
export function groupByDay(events: AssetChange[]): { day: string; events: AssetChange[] }[] {
  const out: { day: string; events: AssetChange[] }[] = []
  for (const e of events) {
    const k = dayKey(e.at)
    const last = out[out.length - 1]
    if (last && last.day === k) last.events.push(e)
    else out.push({ day: k, events: [e] })
  }
  return out
}

/** The source as one label: "scan:nmap", or the kind alone. */
export function sourceRef(s: AssetChange['source']): string {
  return s.name ? `${s.kind}:${s.name}` : s.kind
}
