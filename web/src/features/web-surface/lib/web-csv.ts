/**
 * CSV export of an origin's web surface. Every value is scan output, so each
 * cell goes through `buildCsv`, which prefixes a cell starting with
 * `=`, `+`, `-`, `@`, tab or CR with a single quote (formula injection) and
 * quotes commas, quotes and newlines. Rows are fetched with the same
 * data-scoped list endpoints and filters as the tables.
 */
import { buildCsv, downloadCsv } from '@/hooks/use-csv-export'
import { get } from '@/lib/api/client'
import type { WebEndpointEventResponse, WebEndpointResponse } from '@/lib/api/generated'
import { endpointsUrl, eventsUrl, type EndpointFilters, type EventFilters } from './web-surface-url'
import type { ParamRow } from './origin-params'

/** Rows per request and the most requests one export makes. */
const EXPORT_PER_PAGE = 100
const EXPORT_MAX_PAGES = 20

export interface CsvTable {
  headers: string[]
  rows: unknown[][]
}

export function endpointsCsv(
  rows: WebEndpointResponse[],
  headers: [string, string, string, string, string, string, string]
): string {
  return buildCsv(
    headers,
    rows.map((e) => [
      e.method,
      e.path_template,
      e.kind,
      e.last_status,
      e.auth_state,
      e.param_count,
      e.last_seen_at,
    ])
  )
}

export function eventsCsv(
  rows: WebEndpointEventResponse[],
  headers: [string, string, string, string, string]
): string {
  return buildCsv(
    headers,
    rows.map((e) => [e.at, e.kind, e.method, e.path_template, e.catalog_key])
  )
}

export function paramsCsv(
  rows: ParamRow[],
  headers: [string, string, string, string, string, string]
): string {
  return buildCsv(
    headers,
    rows.map((p) => [
      p.name,
      p.location,
      p.method,
      p.pathTemplate,
      (p.risk_hints ?? []).join('; '),
      p.sensitive,
    ])
  )
}

interface Page<T> {
  data?: T[]
  total?: number
}

async function fetchAll<T>(url: (page: number) => string): Promise<T[]> {
  const out: T[] = []
  for (let page = 1; page <= EXPORT_MAX_PAGES; page++) {
    const res = await get<Page<T>>(url(page))
    const data = res.data ?? []
    out.push(...data)
    if (data.length < EXPORT_PER_PAGE || out.length >= (res.total ?? 0)) break
  }
  return out
}

export function fetchAllEndpoints(f: EndpointFilters): Promise<WebEndpointResponse[]> {
  return fetchAll((page) => endpointsUrl(f, { page, perPage: EXPORT_PER_PAGE }))
}

export function fetchAllEvents(f: EventFilters): Promise<WebEndpointEventResponse[]> {
  return fetchAll((page) => eventsUrl(f, { page, perPage: EXPORT_PER_PAGE }))
}

export { downloadCsv }
