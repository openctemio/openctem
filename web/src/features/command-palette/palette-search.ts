/**
 * Entity search for the command palette (research/236 C8): findings,
 * assets and remediation tasks, through each type's own list API, so the
 * server applies the caller's tenant and data scope to every result. A type
 * the caller may not read is not queried at all (omitted, never counted).
 * No shared cache: results live in the open palette only.
 */

import { get } from '@/lib/api/client'
import { toDisplayText } from '@/lib/untrusted-text'
import { taskListUrl } from '@/features/remediation-hub/api/use-remediation-hub'

/** Results per type. */
export const PALETTE_PER_TYPE = 5
/** The shortest query sent to the server. */
export const PALETTE_MIN_QUERY = 2
const MAX_QUERY = 200
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i

export type PaletteEntityKind = 'finding' | 'asset' | 'task'

export interface PaletteEntity {
  kind: PaletteEntityKind
  id: string
  label: string
  href: string
}

export interface PaletteSearchAccess {
  findings: boolean
  assets: boolean
  tasks: boolean
}

/** The query as sent: trimmed and capped; null below the minimum length. */
export function paletteQuery(raw: string): string | null {
  const q = raw.trim().slice(0, MAX_QUERY)
  if (q.startsWith('>') || q.length < PALETTE_MIN_QUERY) return null
  return q
}

/** A CVE id typed as the whole query, normalised; null otherwise. */
export function cveOf(raw: string): string | null {
  const q = raw.trim()
  return CVE_RE.test(q) ? q.toUpperCase() : null
}

/** The list API URL of one type's search. */
export function paletteSearchUrls(
  q: string,
  access: PaletteSearchAccess
): Partial<Record<PaletteEntityKind, string>> {
  const enc = encodeURIComponent(q)
  const out: Partial<Record<PaletteEntityKind, string>> = {}
  if (access.findings) out.finding = `/api/v1/findings?q=${enc}&per_page=${PALETTE_PER_TYPE}`
  if (access.assets) out.asset = `/api/v1/assets?search=${enc}&per_page=${PALETTE_PER_TYPE}`
  if (access.tasks) out.task = taskListUrl({ search: q, perPage: PALETTE_PER_TYPE })
  return out
}

type Row = { id?: unknown; title?: unknown; name?: unknown; message?: unknown; rule_id?: unknown }

function rowsOf(res: unknown): Row[] {
  const data = (res as { data?: unknown } | null)?.data
  return Array.isArray(data) ? (data as Row[]) : []
}

function entity(kind: PaletteEntityKind, r: Row): PaletteEntity | null {
  if (typeof r.id !== 'string' || !/^[0-9a-f-]{8,64}$/i.test(r.id)) return null
  const raw =
    kind === 'asset'
      ? r.name
      : (r.title ?? (kind === 'finding' ? (r.message ?? r.rule_id) : undefined))
  const label = toDisplayText(typeof raw === 'string' ? raw : '', 120) || r.id
  const id = encodeURIComponent(r.id)
  const href =
    kind === 'finding'
      ? `/findings/${id}`
      : kind === 'asset'
        ? `/assets/${id}`
        : `/remediation/tasks/${id}`
  return { kind, id: r.id, label, href }
}

/**
 * Runs the search for every type the caller may read, in parallel. A type
 * that fails is left out; the others still show.
 */
export async function searchPalette(
  q: string,
  access: PaletteSearchAccess,
  signal?: AbortSignal,
  fetcher: (url: string, opts?: { signal?: AbortSignal }) => Promise<unknown> = (url, opts) =>
    get(url, opts)
): Promise<PaletteEntity[]> {
  const urls = paletteSearchUrls(q, access)
  const kinds = Object.keys(urls) as PaletteEntityKind[]
  const settled = await Promise.allSettled(kinds.map((k) => fetcher(urls[k] as string, { signal })))
  const out: PaletteEntity[] = []
  settled.forEach((s, i) => {
    if (s.status !== 'fulfilled') return
    for (const r of rowsOf(s.value).slice(0, PALETTE_PER_TYPE)) {
      const e = entity(kinds[i], r)
      if (e) out.push(e)
    }
  })
  return out
}
