'use client'

/**
 * Data hooks of the remediation hub: tasks, their findings and timeline,
 * suggestions, and every change (create, edit, move, split, merge, mark
 * fixed, accept, dismiss, snooze). Every list is paged on the server.
 */

import useSWR, { useSWRConfig } from 'swr'
import { useCallback } from 'react'
import { get, post, patch } from '@/lib/api/client'
import type {
  AcceptResult,
  BulkAcceptItem,
  ConflictResolution,
  DismissReason,
  MarkFixedResult,
  MovePreview,
  MoveResult,
  Page,
  RemediationSuggestion,
  RemediationTask,
  SuggestionCounts,
  SuggestionKind,
  SuggestionMember,
  TaskEvent,
  TaskMember,
  TaskState,
} from './types'

const TASKS = '/api/v1/remediation/tasks'
const SUGGESTIONS = '/api/v1/remediation/suggestions'

export interface TaskListFilters {
  states?: TaskState[]
  mine?: boolean
  /** Only tasks whose deadline has passed (counted on the server). */
  overdue?: boolean
  search?: string
  sort?: 'deadline' | 'risk' | 'updated' | 'created'
  findingId?: string
  actionId?: string
  /** Tasks of one campaign. */
  campaignId?: string
  /** Tasks in no campaign (the campaign "Add tasks" picker). */
  noCampaign?: boolean
  page?: number
  perPage?: number
}

export function taskListUrl(f: TaskListFilters): string {
  const p = new URLSearchParams()
  if (f.states?.length) p.set('state', f.states.join(','))
  if (f.mine) p.set('assignee', 'me')
  if (f.overdue) p.set('overdue', 'true')
  if (f.search?.trim()) p.set('search', f.search.trim())
  if (f.sort) p.set('sort', f.sort)
  if (f.findingId) p.set('finding_id', f.findingId)
  if (f.actionId) p.set('action_id', f.actionId)
  if (f.campaignId) p.set('campaign_id', f.campaignId)
  if (f.noCampaign) p.set('no_campaign', 'true')
  p.set('page', String(f.page ?? 1))
  p.set('per_page', String(f.perPage ?? 25))
  return `${TASKS}?${p.toString()}`
}

export function useTasks(f: TaskListFilters, enabled = true) {
  return useSWR<Page<RemediationTask>>(enabled ? taskListUrl(f) : null, get, {
    keepPreviousData: true,
  })
}

export function useTask(id: string | undefined) {
  return useSWR<RemediationTask>(id ? `${TASKS}/${id}` : null, get)
}

export function memberPageUrl(
  taskId: string,
  page: number,
  perPage: number,
  status?: string
): string {
  const p = new URLSearchParams({ page: String(page), per_page: String(perPage) })
  if (status) p.set('status', status)
  return `${TASKS}/${taskId}/members?${p.toString()}`
}

export function useTaskMembers(
  taskId: string | undefined,
  page: number,
  perPage: number,
  status?: string
) {
  return useSWR<Page<TaskMember>>(
    taskId ? memberPageUrl(taskId, page, perPage, status) : null,
    get,
    {
      keepPreviousData: true,
    }
  )
}

export function useTaskTimeline(taskId: string | undefined) {
  return useSWR<Page<TaskEvent>>(taskId ? `${TASKS}/${taskId}/timeline?per_page=50` : null, get)
}

export interface SuggestionFilters {
  kinds?: SuggestionKind[]
  keyKind?: string
  minRisk?: number
  search?: string
  state?: 'proposed' | 'snoozed' | 'dismissed'
  page?: number
  perPage?: number
}

export function suggestionListUrl(f: SuggestionFilters): string {
  const p = new URLSearchParams()
  if (f.state) p.set('state', f.state)
  if (f.kinds?.length) p.set('kind', f.kinds.join(','))
  if (f.keyKind) p.set('key_kind', f.keyKind)
  if (f.minRisk) p.set('min_risk', String(f.minRisk))
  if (f.search?.trim()) p.set('search', f.search.trim())
  p.set('page', String(f.page ?? 1))
  p.set('per_page', String(f.perPage ?? 25))
  return `${SUGGESTIONS}?${p.toString()}`
}

export function useSuggestions(f: SuggestionFilters, enabled = true) {
  return useSWR<Page<RemediationSuggestion>>(enabled ? suggestionListUrl(f) : null, get, {
    keepPreviousData: true,
  })
}

export function useSuggestionStats(enabled = true) {
  return useSWR<SuggestionCounts>(enabled ? `${SUGGESTIONS}/stats` : null, get)
}

/** One suggestion by id (a deep link may name one that is not on the page). */
export function useSuggestion(id: string | undefined) {
  return useSWR<RemediationSuggestion>(id ? `${SUGGESTIONS}/${id}` : null, get)
}

export function useSuggestionMembers(id: string | undefined, page: number, perPage = 50) {
  return useSWR<Page<SuggestionMember>>(
    id ? `${SUGGESTIONS}/${id}/members?page=${page}&per_page=${perPage}` : null,
    get,
    { keepPreviousData: true }
  )
}

/** Revalidates every cached remediation hub list and record. */
export function useRevalidateHub() {
  const { mutate } = useSWRConfig()
  return useCallback(
    () =>
      mutate(
        (key) =>
          typeof key === 'string' &&
          (key.startsWith(TASKS) ||
            key.startsWith(SUGGESTIONS) ||
            key.startsWith('/api/v1/remediation/actions'))
      ),
    [mutate]
  )
}

export interface UpdateTaskBody {
  version: number
  title?: string
  description?: string
  assignee_user_id?: string | null
  assignee_group_id?: string | null
  deadline?: string | null
  hold?: boolean
  cancel?: boolean
  note?: string
}

export const hubApi = {
  updateTask: (id: string, body: UpdateTaskBody) => patch<RemediationTask>(`${TASKS}/${id}`, body),
  createTask: (body: {
    title: string
    finding_ids: string[]
    assignee_user_id?: string
    assignee_group_id?: string
    deadline?: string
    action_id?: string
    campaign_id?: string
    conflicts?: ConflictResolution
  }) => post<RemediationTask>(TASKS, body),
  addMembers: (
    id: string,
    body: { version: number; finding_ids: string[]; conflicts?: ConflictResolution }
  ) => post<RemediationTask>(`${TASKS}/${id}/members`, body),
  resolveTask: (id: string, body: { version: number; note: string }) =>
    post<MarkFixedResult>(`${TASKS}/${id}/resolve`, body),
  splitTask: (
    id: string,
    body: {
      version: number
      finding_ids: string[]
      title?: string
      assignee_user_id?: string
      assignee_group_id?: string
    }
  ) => post<MoveResult>(`${TASKS}/${id}/splits`, body),
  mergeTasks: (
    id: string,
    body: { version: number; sources: { task_id: string; version: number }[] }
  ) => post<RemediationTask>(`${TASKS}/${id}/merges`, body),
  previewMove: (body: MoveBody) => post<MovePreview>('/api/v1/remediation/moves/preview', body),
  move: (body: MoveBody & { confirm?: boolean }) =>
    post<MoveResult>('/api/v1/remediation/moves', body),
  approve: (id: string, body: ApproveBody) =>
    post<AcceptResult>(`${SUGGESTIONS}/${id}/approve`, body),
  bulkApprove: (ids: string[]) => post<BulkAcceptItem[]>(`${SUGGESTIONS}/approve`, { ids }),
  reject: (id: string, body: { version: number; reason: DismissReason; note?: string }) =>
    post<RemediationSuggestion>(`${SUGGESTIONS}/${id}/reject`, body),
  snooze: (id: string, body: { version: number; snoozed_until: string }) =>
    patch<RemediationSuggestion>(`${SUGGESTIONS}/${id}`, body),
  reopen: (id: string, version: number) =>
    post<RemediationSuggestion>(`${SUGGESTIONS}/${id}/reopen`, { version }),
  runNow: () => post<Record<string, number>>(`${SUGGESTIONS}/run`, {}),
}

export interface MoveBody {
  from_task_id: string
  from_version: number
  to_task_id?: string
  to_version?: number
  finding_ids: string[]
}

export interface ApproveBody {
  version: number
  title?: string
  exclude_finding_ids?: string[]
  owners?: { index: number; assignee_user_id?: string; assignee_group_id?: string }[]
  deadline?: string
  auto_join?: boolean
  /** Resolves findings another active task took since the suggestion was made. */
  conflicts?: ConflictResolution
}
