'use client'

/**
 * Remediation campaigns: programmes of remediation tasks under one owner and
 * one due date (api/docs/rfcs/RFC-098-remediation-tasks.md). A campaign holds
 * tasks, never findings; its numbers come from its tasks, counted on the
 * server within the caller's data scope.
 */

import useSWR, { useSWRConfig } from 'swr'
import useSWRMutation from 'swr/mutation'
import { useCallback } from 'react'
import { get, post, patch, del } from '@/lib/api/client'

export type CampaignStatus = 'draft' | 'active' | 'completed' | 'canceled'
export type CampaignPriority = 'critical' | 'high' | 'medium' | 'low'

export const CAMPAIGN_STATUSES: readonly CampaignStatus[] = [
  'draft',
  'active',
  'completed',
  'canceled',
]

/** Campaign priorities, highest first (pkg/domain/remediation CampaignPriority). */
export const CAMPAIGN_PRIORITIES: readonly CampaignPriority[] = [
  'critical',
  'high',
  'medium',
  'low',
]

export interface CampaignSummary {
  /** Tasks of the campaign the caller can see. */
  tasks: number
  /** Open, in progress, verifying or on hold. */
  live_tasks: number
  done_tasks: number
  /** Live and past their deadline. */
  overdue_tasks: number
  /** Tasks outside the caller's data scope (count only). */
  hidden_tasks: number
  /** Primary findings of the visible tasks. */
  findings: number
  closed_findings: number
  verified_findings: number
  /** 0..100 = closed_findings / findings. */
  progress: number
}

export interface CampaignTicketLink {
  provider: string
  issue_key: string
  issue_url: string
}

export interface RemediationCampaign {
  id: string
  name: string
  description: string
  status: CampaignStatus
  priority: CampaignPriority
  assigned_to?: string
  assigned_team?: string
  created_by?: string
  start_date?: string
  due_date?: string
  completed_at?: string
  tags: string[]
  created_at: string
  updated_at: string
  /** Changes on every save; sent back on edits so a stale save answers 409. */
  version: number
  is_overdue: boolean
  /** The caller may change it (a restricted caller: every task is fully in scope). */
  can_edit: boolean
  summary: CampaignSummary
  ticket?: CampaignTicketLink | null
}

export interface CampaignPage {
  data: RemediationCampaign[]
  total: number
  page: number
  per_page: number
  total_pages?: number
}

export const CAMPAIGNS = '/api/v1/remediation/campaigns'

export interface CampaignListFilters {
  status?: CampaignStatus
  priority?: CampaignPriority
  search?: string
  page?: number
  perPage?: number
}

export function campaignListUrl(f: CampaignListFilters): string {
  const p = new URLSearchParams()
  if (f.status) p.set('status', f.status)
  if (f.priority) p.set('priority', f.priority)
  if (f.search?.trim()) p.set('search', f.search.trim())
  p.set('page', String(f.page ?? 1))
  p.set('per_page', String(f.perPage ?? 25))
  return `${CAMPAIGNS}?${p.toString()}`
}

export function useRemediationCampaigns(f: CampaignListFilters, enabled = true) {
  return useSWR<CampaignPage>(enabled ? campaignListUrl(f) : null, get, {
    keepPreviousData: true,
  })
}

/**
 * Totals per status for the filter chips: one page-of-one request per status,
 * so the counts are the server's, never one page counted in the browser.
 */
export function useCampaignStatusCounts(search: string, enabled = true) {
  const key = enabled ? ['campaign-status-counts', search.trim()] : null
  return useSWR<Record<CampaignStatus | 'all', number>>(
    key,
    async () => {
      const totals = await Promise.all(
        [undefined, ...CAMPAIGN_STATUSES].map((status) =>
          get<CampaignPage>(campaignListUrl({ status, search, perPage: 1 })).then((r) => r.total)
        )
      )
      const [all, ...rest] = totals
      const out = { all } as Record<CampaignStatus | 'all', number>
      CAMPAIGN_STATUSES.forEach((s, i) => (out[s] = rest[i]))
      return out
    },
    { keepPreviousData: true }
  )
}

export function useRemediationCampaign(id: string | undefined) {
  return useSWR<RemediationCampaign>(id ? `${CAMPAIGNS}/${id}` : null, get)
}

/** Revalidates every cached campaign list, count and record. */
export function useRevalidateCampaigns() {
  const { mutate } = useSWRConfig()
  return useCallback(
    () =>
      mutate(
        (key) =>
          (typeof key === 'string' && key.startsWith(CAMPAIGNS)) ||
          (Array.isArray(key) && key[0] === 'campaign-status-counts')
      ),
    [mutate]
  )
}

export interface CampaignFields {
  name?: string
  description?: string
  priority?: CampaignPriority
  assigned_to?: string | null
  assigned_team?: string | null
  start_date?: string | null
  due_date?: string | null
  tags?: string[]
}

export const campaignApi = {
  create: (body: CampaignFields & { name: string; task_ids?: string[]; move?: boolean }) =>
    post<RemediationCampaign>(`${CAMPAIGNS}/`, body),
  update: (id: string, body: CampaignFields & { version: number }) =>
    patch<RemediationCampaign>(`${CAMPAIGNS}/${id}`, body),
  setStatus: (id: string, body: { status: 'active' | 'completed' | 'canceled'; version: number }) =>
    patch<RemediationCampaign>(`${CAMPAIGNS}/${id}/status`, body),
  addTasks: (id: string, body: { task_ids: string[]; move?: boolean }) =>
    post<RemediationCampaign>(`${CAMPAIGNS}/${id}/tasks`, body),
  removeTask: (id: string, taskId: string) =>
    del<RemediationCampaign>(`${CAMPAIGNS}/${id}/tasks/${taskId}`),
  remove: (id: string) => del<void>(`${CAMPAIGNS}/${id}`),
}

export interface CampaignTicketInfo {
  campaign_id: string
  provider: string
  issue_key: string
  issue_url: string
  already_existed: boolean
}

/** A task the request named that is in another campaign (409 TASKS_IN_OTHER_CAMPAIGN). */
export interface TaskInOtherCampaign {
  task_id: string
  campaign_id: string
  campaign_name: string | null
  can_move: boolean
}

/**
 * Creates (or returns the existing) Jira epic for a campaign. Idempotent on the
 * backend: invoking it again returns the existing link with already_existed=true.
 */
export function useCreateCampaignTicket(id: string) {
  return useSWRMutation<CampaignTicketInfo, Error, string, { project_key: string }>(
    `${CAMPAIGNS}/${id}/create-ticket`,
    (url: string, { arg }: { arg: { project_key: string } }) => post(url, arg)
  )
}
