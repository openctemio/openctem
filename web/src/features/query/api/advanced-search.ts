/**
 * A list for a filter that chips cannot show (`fq`: an OR across fields, a
 * nested group). A list never receives text: the page's other list params and
 * the fq text are checked by POST /api/v1/query/parse as the signed-in person
 * and the resulting filter document is sent to the entity's search endpoint,
 * which uses the same registry, data scope and tenant as its GET list.
 */

import { post } from '@/lib/api/client'
import { queryApi, type QueryEntity } from './query-api'

/** An fq filter the server refused: the list shows its problem. */
export class AdvancedFilterError extends Error {
  constructor(readonly code: string) {
    super('the filter is not valid')
  }
}

export interface AdvancedSearchSpec {
  entity: QueryEntity
  /** The POST endpoint taking a filter document. */
  searchPath: string
  /** Params of the list URL that are not part of the filter. */
  pageParams: ReadonlySet<string>
  /** Per-page when the URL has none. */
  defaultPerPage?: number
  /** Params added to the filter unless the fq text names this field (a default the list applies). */
  defaultParams?: { field: string; params: Record<string, string> }
}

/** Whether a filter document has a condition on `field`. */
export function documentUsesField(node: unknown, field: string): boolean {
  if (Array.isArray(node)) return node.some((n) => documentUsesField(n, field))
  if (node && typeof node === 'object') {
    const o = node as Record<string, unknown>
    if (o.field === field) return true
    return Object.values(o).some((v) => documentUsesField(v, field))
  }
  return false
}

/**
 * The checked filter document of a list URL that carries fq (the page's other
 * list params and the fq text, as one document), plus the URL's parts.
 */
export async function advancedDocument(
  url: string,
  spec: AdvancedSearchSpec
): Promise<{ document: Record<string, unknown>; url: URL }> {
  const u = new URL(url, 'http://local')
  const fq = u.searchParams.get('fq') ?? ''
  const rest = new URLSearchParams()
  u.searchParams.forEach((v, k) => {
    if (!spec.pageParams.has(k)) rest.append(k, v)
  })
  if (rest.has('view')) throw new AdvancedFilterError('view_with_query')
  const dflt = spec.defaultParams
  if (dflt) {
    const own = await queryApi.parse({ entity: spec.entity, text: fq })
    if (!own.valid || !own.document)
      throw new AdvancedFilterError(own.problems[0]?.code ?? 'invalid')
    if (!documentUsesField(own.document, dflt.field)) {
      for (const [k, v] of Object.entries(dflt.params)) if (!rest.has(k)) rest.set(k, v)
    }
  }
  let text = fq
  if (rest.toString() !== '') {
    const base = await queryApi.parse({ entity: spec.entity, params: rest.toString() })
    if (!base.valid) throw new AdvancedFilterError(base.problems[0]?.code ?? 'invalid')
    if (base.text) text = `(${base.text}) (${fq})`
  }
  const res = await queryApi.parse({ entity: spec.entity, text })
  if (!res.valid || !res.document) throw new AdvancedFilterError(res.problems[0]?.code ?? 'invalid')
  return { document: res.document, url: u }
}

/** The list for a URL that carries fq. */
export async function fetchAdvanced<T>(url: string, spec: AdvancedSearchSpec): Promise<T> {
  const { document, url: u } = await advancedDocument(url, spec)
  const sort = u.searchParams.get('sort')
  const page = Number(u.searchParams.get('page') ?? '1') || 1
  const perPage = Number(u.searchParams.get('per_page') ?? String(spec.defaultPerPage ?? 20)) || 20
  return post<T>(spec.searchPath, {
    ...document,
    ...(sort ? { sort: sort.split(',') } : {}),
    page: { page, per_page: perPage },
  })
}
