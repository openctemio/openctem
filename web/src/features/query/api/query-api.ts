/**
 * The search box API (server/docs/architecture/query-language.md, "Short
 * form"): parse a filter, complete values, read the caller's fields. Every
 * call runs as the signed-in person; nothing here sends a tenant or a scope.
 */

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'

export type QueryEntity = 'findings' | 'assets' | 'scans'

/** One problem of a filter, with its byte range in the text. */
export interface QueryProblem {
  code: string
  message: string
  start: number
  end: number
  line: number
  column: number
  suggestions?: string[]
}

export interface QueryChip {
  kind: 'condition' | 'text' | 'advanced'
  field?: string
  op?: string
  values?: unknown[]
  text: string
}

export interface ParseResult {
  entity: QueryEntity
  form?: 'short' | 'long'
  valid: boolean
  text: string
  query: string
  document?: Record<string, unknown>
  chips: QueryChip[]
  advanced: boolean
  params?: Record<string, string>
  problems: QueryProblem[]
}

export interface ParseRequest {
  entity: QueryEntity
  text?: string
  document?: Record<string, unknown>
  params?: string
}

export interface ValueCount {
  value: string | number | boolean
  count?: number
}

export interface ValuesResult {
  entity: QueryEntity
  field: string
  values: ValueCount[]
  counted: boolean
}

export interface QuerySchemaField {
  path: string
  type: string
  operators: string[]
  enum?: string[]
  group_by?: boolean
}

export const queryApi = {
  parse: (body: ParseRequest) => post<ParseResult>('/api/v1/query/parse', body),
  values: (entity: QueryEntity, field: string, prefix: string, fq: string) =>
    get<ValuesResult>(
      `/api/v1/query/values?${new URLSearchParams({ entity, field, prefix, fq }).toString()}`
    ),
}

/** The fields the caller may use on an entity (for completion). */
export function useQuerySchema(entity: QueryEntity, enabled = true) {
  return useSWR<{ fields?: QuerySchemaField[] }>(
    enabled ? `/api/v1/query/schema?entity=${entity}` : null,
    get,
    { revalidateOnFocus: false }
  )
}
