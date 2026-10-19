/**
 * Remediation tasks created from a custom query
 * (api/docs/rfcs/RFC-098-remediation-tasks.md, "Tasks from a query").
 * The query always runs on the server as the signed-in person: nothing
 * here sends a tenant or a scope.
 */

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import { ApiClientError } from '@/lib/api/error-handler'
import type { ConflictResolution, FindingConflict, RemediationTask } from './types'

const TASKS = '/api/v1/remediation/tasks'

export type QueryMode = 'snapshot' | 'auto'
export type AutoState = 'active' | 'paused' | 'suspended'
export type AutoReason = 'owner_removed' | 'owner_lost_access' | 'task_closed' | 'query_invalid'

export const MAX_QUERY_TASK_FINDINGS = 1000

export interface QueryBreakdown {
  key: string
  name: string
  count: number
  user_id?: string
  group_id?: string
}

export interface QuerySample {
  finding_id: string
  title: string
  severity: string
  status: string
  asset_id?: string
  asset_name: string
  sla_deadline?: string
}

export interface QueryStats {
  severity: QueryBreakdown[]
  assets: QueryBreakdown[]
  owners: QueryBreakdown[]
  sample: QuerySample[]
  earliest_deadline?: string
}

export interface QueryTaskPreview {
  query: string
  query_version: number
  description: string
  scope_kind: 'data_scope' | 'organization'
  scope_rules: string[]
  total: number
  too_many: boolean
  max: number
  claimable: number
  stats?: QueryStats
  conflicts: FindingConflict[]
  suggested_assignee?: { user_id?: string; group_id?: string }
}

export interface TaskQuery {
  task_id: string
  query: string
  query_version: number
  mode: QueryMode
  auto_state: AutoState | null
  auto_reason: AutoReason | null
  cap: number
  owner_user_id: string | null
  last_run_at: string | null
  last_added_count: number
  total_added: number
  created_at: string
}

export interface CreateQueryTaskBody {
  title: string
  query: string
  mode: QueryMode
  cap?: number
  assignee_user_id?: string
  assignee_group_id?: string
  deadline?: string
  campaign_id?: string
  conflicts?: ConflictResolution
}

export interface CreateQueryTaskResult {
  task: RemediationTask
  query: TaskQuery
  matched: number
  added: number
  moved: number
  skipped: number
}

export interface QueryRerunPreview {
  query: string
  new: number
  truncated: boolean
  room: number
  stats?: QueryStats
}

export interface QueryRerunResult {
  task: RemediationTask
  added: number
  skipped: number
  capped: number
}

export interface QueryExplanation {
  query: string
  description: string
  entity: string
}

/** One problem of a query, with its place in the text. */
export interface QueryProblem {
  start: number
  end: number
  line: number
  column: number
  message: string
}

export interface QuerySchemaField {
  path: string
  type: string
  operators: string[]
  enum?: string[]
}

export const taskQueryApi = {
  preview: (query: string) => post<QueryTaskPreview>(`${TASKS}/query/preview`, { query }),
  create: (body: CreateQueryTaskBody) => post<CreateQueryTaskResult>(`${TASKS}/query`, body),
  previewRerun: (taskId: string) =>
    post<QueryRerunPreview>(`${TASKS}/${taskId}/query/rerun/preview`, {}),
  rerun: (taskId: string) => post<QueryRerunResult>(`${TASKS}/${taskId}/query/rerun`, {}),
  setAuto: (taskId: string, paused: boolean) =>
    post<TaskQuery>(`${TASKS}/${taskId}/query/auto`, { paused }),
  explain: (query: string) => post<QueryExplanation>('/api/v1/query/explain', { query }),
  fromFilters: (params: string) =>
    post<{ query: string; ignored: string[] }>('/api/v1/query/from-filters', {
      entity: 'findings',
      params,
    }),
}

/** The query a task was created from; null when it was not (404). */
export function useTaskQuery(taskId: string | undefined) {
  return useSWR<TaskQuery | null>(
    taskId ? `${TASKS}/${taskId}/query` : null,
    async (url: string) => {
      try {
        return await get<TaskQuery>(url)
      } catch (err) {
        if (err instanceof ApiClientError && err.statusCode === 404) return null
        throw err
      }
    },
    { revalidateOnFocus: false }
  )
}

/** The findings fields the caller may query (names for autocomplete). */
export function useFindingQuerySchema(enabled: boolean) {
  return useSWR<{ fields?: QuerySchemaField[] }>(
    enabled ? '/api/v1/query/schema?entity=findings' : null,
    get,
    { revalidateOnFocus: false }
  )
}

/** The problems of an INVALID_QUERY answer, or an empty list. */
export function queryProblems(err: unknown): QueryProblem[] {
  if (!(err instanceof ApiClientError)) return []
  const raw: unknown = Array.isArray(err.details)
    ? err.details
    : (err.details as { details?: unknown } | undefined)?.details
  if (!Array.isArray(raw)) return []
  return raw
    .filter((d): d is Record<string, unknown> => !!d && typeof d === 'object')
    .map((d) => ({
      start: Number(d.start ?? 0),
      end: Number(d.end ?? 0),
      line: Number(d.line ?? 0),
      column: Number(d.column ?? 0),
      message: typeof d.message === 'string' ? d.message : '',
    }))
}
