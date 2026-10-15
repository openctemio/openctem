'use client'

import useSWR from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, patch, del } from '@/lib/api/client'
import { fetchAllPages } from '@/lib/api/fetch-all-pages'
import type { ApiFinding } from '@/features/findings/api/finding-api.types'
import type { MarkFixedRequest, MarkFixedResult } from './mark-fixed.types'

export interface RemediationCampaign {
  id: string
  name: string
  description: string
  status: string
  priority: string
  finding_filter: Record<string, unknown>
  finding_count: number
  resolved_count: number
  /** Findings closed as resolved (a verified fix). Done = all closed and >= 1 verified. */
  verified_count: number
  progress: number
  risk_before: number | null
  risk_after: number | null
  risk_reduction: number | null
  assigned_to: string | null
  assigned_team: string | null
  is_overdue: boolean
  start_date: string | null
  due_date: string | null
  completed_at: string | null
  tags: string[]
  created_at: string
  updated_at: string
  /** Changes on every save; sent back on edits so a stale save answers 409. */
  version: number
  /** Linked external tracker epic (e.g. Jira), or null when not linked. */
  ticket: CampaignTicketLink | null
}

export interface CampaignTicketLink {
  provider: string
  issue_key: string
  issue_url: string
}

interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  per_page: number
}

// The task list reads every campaign (its metrics, board, search and the
// "add to existing task" picker all work on the whole list), one API page at a
// time through the shared fetchAllPages, bounded so a runaway list cannot
// stall the page.
const CAMPAIGN_PAGE_SIZE = 100
const CAMPAIGN_MAX_PAGES = 20

/** Reads every page of a campaign list URL (the URL carries the filters). */
export async function fetchAllCampaigns(
  url: string
): Promise<PaginatedResponse<RemediationCampaign>> {
  const sep = url.includes('?') ? '&' : '?'
  const data = await fetchAllPages<RemediationCampaign>(
    (page, perPage) => `${url}${sep}page=${page}&per_page=${perPage}`,
    { perPage: CAMPAIGN_PAGE_SIZE, maxPages: CAMPAIGN_MAX_PAGES }
  )
  return { data, total: data.length, page: 1, per_page: data.length }
}

export function useRemediationCampaigns(filters?: {
  status?: string
  priority?: string
  search?: string
}) {
  const params = new URLSearchParams()
  if (filters?.status) params.set('status', filters.status)
  if (filters?.priority) params.set('priority', filters.priority)
  if (filters?.search) params.set('search', filters.search)
  const qs = params.toString()
  return useSWR<PaginatedResponse<RemediationCampaign>>(
    `/api/v1/remediation/campaigns${qs ? `?${qs}` : ''}`,
    fetchAllCampaigns,
    { revalidateOnFocus: false }
  )
}

export function useRemediationCampaign(id: string) {
  return useSWR<RemediationCampaign>(id ? `/api/v1/remediation/campaigns/${id}` : null, get)
}

/**
 * The findings a campaign tracks: the same set its finding_count counts (its
 * finding filter or remediation key, any status), on the caller's in-scope
 * assets. Needs findings:read; pass enabled=false without it.
 */
export function useRemediationCampaignFindings(id: string, enabled = true) {
  return useSWR<PaginatedResponse<ApiFinding>>(
    id && enabled ? `/api/v1/remediation/campaigns/${id}/findings?per_page=100` : null,
    get,
    { revalidateOnFocus: false }
  )
}

export function useCreateRemediationCampaign() {
  return useSWRMutation(
    '/api/v1/remediation/campaigns',
    (url: string, { arg }: { arg: Partial<RemediationCampaign> }) => post(url, arg)
  )
}

export function useUpdateRemediationCampaign(id: string) {
  return useSWRMutation(
    `/api/v1/remediation/campaigns/${id}`,
    (url: string, { arg }: { arg: Partial<RemediationCampaign> }) => patch(url, arg)
  )
}

export function useUpdateCampaignStatus(id: string) {
  return useSWRMutation(
    `/api/v1/remediation/campaigns/${id}/status`,
    (
      url: string,
      { arg }: { arg: { status: string; version?: number; close_with_open_members?: boolean } }
    ) => patch(url, arg)
  )
}

export function useDeleteRemediationCampaign(id: string) {
  return useSWRMutation(`/api/v1/remediation/campaigns/${id}`, (url: string) => del(url))
}

export type ResolveCampaignRequest = MarkFixedRequest
export type ResolveCampaignResult = MarkFixedResult

/** Marks the campaign's open findings fixed in one action; never closes them. */
export function useResolveRemediationCampaign(id: string) {
  return useSWRMutation<ResolveCampaignResult, Error, string, ResolveCampaignRequest>(
    `/api/v1/remediation/campaigns/${id}/resolve`,
    (url: string, { arg }: { arg: ResolveCampaignRequest }) => post(url, arg)
  )
}

export interface CampaignTicketInfo {
  campaign_id: string
  provider: string
  issue_key: string
  issue_url: string
  already_existed: boolean
}

/**
 * Creates (or returns the existing) Jira epic for a campaign. Idempotent on the
 * backend — re-invoking returns the existing link with already_existed=true.
 */
export function useCreateCampaignTicket(id: string) {
  return useSWRMutation<CampaignTicketInfo, Error, string, { project_key: string }>(
    `/api/v1/remediation/campaigns/${id}/create-ticket`,
    (url: string, { arg }: { arg: { project_key: string } }) => post(url, arg)
  )
}
