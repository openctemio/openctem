/**
 * Dynamic target selectors (RFC-068). A scan keeps `*.example.com` and CIDRs
 * as typed; the API expands them from the inventory at the start of every
 * run, so a scheduled scan also scans what was found since its last run:
 *
 * - `*.example.com`: the apex and every domain or subdomain asset at or
 *   under it;
 * - a CIDR: swept whole (default), or with `cidr_mode: 'inventory'` the
 *   address assets the inventory holds inside it.
 *
 * Every expanded target still goes through the API's scope gate. These
 * helpers only shape the request and the preview.
 */

import type { ScanTargetOptions } from '@/lib/api/scan-types'
import { enTranslate, type Translate } from './translate'
import { classifyTarget } from './target-format'

export type CidrMode = 'sweep' | 'inventory'

/** Freshness windows offered (0: any). The API takes 0-365. */
export const SEEN_WITHIN_CHOICES = [0, 7, 30, 90] as const

/** At most this many assets one selector adds to a run (the API's cap). */
export const MAX_SELECTOR_TARGETS = 5000

export interface TargetSelector {
  kind: 'wildcard' | 'cidr'
  /** The target as stored. */
  target: string
  /** wildcard: the apex; cidr: the range. */
  value: string
}

export function isWildcardTarget(t: string): boolean {
  return t.trim().startsWith('*.')
}

export function isCidrTarget(t: string): boolean {
  return classifyTarget(t).kind === 'cidr'
}

/**
 * The selectors among the targets: every wildcard, and the CIDRs when they
 * are read from the inventory. Each once, in order.
 */
export function selectorsOf(
  targets: readonly string[],
  options?: ScanTargetOptions
): TargetSelector[] {
  const inventoryCidr = options?.cidr_mode === 'inventory'
  const seen = new Set<string>()
  const out: TargetSelector[] = []
  for (const raw of targets) {
    const t = raw.trim()
    let sel: TargetSelector | null = null
    if (isWildcardTarget(t)) {
      sel = { kind: 'wildcard', target: t, value: t.slice(2).toLowerCase().replace(/\.$/, '') }
    } else if (inventoryCidr && isCidrTarget(t)) {
      sel = { kind: 'cidr', target: t, value: classifyTarget(t).value }
    }
    if (!sel || seen.has(`${sel.kind}:${sel.value}`)) continue
    seen.add(`${sel.kind}:${sel.value}`)
    out.push(sel)
  }
  return out
}

/** Whether any target is a CIDR (the CIDR mode choice applies). */
export function hasCidrTarget(targets: readonly string[]): boolean {
  return targets.some(isCidrTarget)
}

/** Whether the scan has a target the API resolves again at every run. */
export function hasDynamicTargets(
  targets: readonly string[],
  options?: ScanTargetOptions
): boolean {
  return selectorsOf(targets, options).length > 0
}

/**
 * "Host and its subdomains": each typed domain becomes its wildcard, which
 * covers the domain itself (RFC-054 S1) and is re-resolved at every run.
 * Other targets are kept; duplicates (case-insensitive) dropped.
 */
export function toWildcards(targets: readonly string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of targets) {
    const c = classifyTarget(raw)
    const t = c.kind === 'domain' ? `*.${c.value}` : raw.trim()
    const key = t.toLowerCase()
    if (!t || seen.has(key)) continue
    seen.add(key)
    out.push(t)
  }
  return out
}

/** The options as the API takes them, or undefined when all are default. */
export function apiTargetOptions(o?: ScanTargetOptions): ScanTargetOptions | undefined {
  if (!o) return undefined
  const out: ScanTargetOptions = {}
  if (o.cidr_mode === 'inventory') out.cidr_mode = 'inventory'
  if (o.seen_within_days && o.seen_within_days > 0) out.seen_within_days = o.seen_within_days
  if (o.include_stale) out.include_stale = true
  if (o.new_since_last_run) out.new_since_last_run = true
  return Object.keys(out).length > 0 ? out : undefined
}

/** YYYY-MM-DD of `days` ago (UTC), the list API's `last_seen_after`. */
export function seenSince(days: number, now: Date = new Date()): string {
  const d = new Date(now.getTime() - days * 86_400_000)
  return d.toISOString().slice(0, 10)
}

/**
 * GET /assets for one selector's preview: the assets a run would take now,
 * freshest first. The caller's data scope applies on the server, so this is
 * what the viewer can see, not a promise of what the run scans.
 */
export function selectorPreviewURL(
  sel: TargetSelector,
  options: ScanTargetOptions | undefined,
  perPage = 5,
  now: Date = new Date()
): string {
  const params = new URLSearchParams({ per_page: String(perPage), sort: '-last_seen' })
  if (sel.kind === 'wildcard') {
    params.set('under', sel.value)
    params.set('types', 'domain,subdomain')
  } else {
    params.set('in_cidr', sel.value)
  }
  params.set('statuses', options?.include_stale ? 'active,stale,inactive' : 'active')
  if (options?.seen_within_days && options.seen_within_days > 0) {
    params.set('last_seen_after', seenSince(options.seen_within_days, now))
  }
  return `/api/v1/assets?${params}`
}

/** How a run resolves the scan's dynamic targets, in words (scan detail). */
export function describeTargetOptions(
  targets: readonly string[],
  o: ScanTargetOptions | undefined,
  t: Translate = enTranslate
): string[] {
  const out: string[] = []
  if (hasCidrTarget(targets)) {
    out.push(
      o?.cidr_mode === 'inventory'
        ? t('scans.targetOptions.rangesInventory')
        : t('scans.targetOptions.rangesSweep')
    )
  }
  if (selectorsOf(targets, o).length > 0) {
    if (o?.seen_within_days)
      out.push(t('scans.targetOptions.seenWithin', undefined, { days: o.seen_within_days }))
    if (o?.include_stale) out.push(t('scans.targetOptions.includesStale'))
  }
  return out
}
