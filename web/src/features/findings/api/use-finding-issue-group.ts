/**
 * Same-issue group of a finding.
 *
 *   GET    /api/v1/findings/{id}/issue-links
 *   DELETE /api/v1/findings/{id}/issue-links/{other}
 *
 * Findings that other tools (or rules) report for the same issue, linked
 * without being merged: each keeps its own status. The API lists only the
 * members the caller may see; an empty list means "no group".
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import { del, get } from '@/lib/api/client'
import { handleApiError } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'

/** Mirrors handler.FindingIssueGroupMember. */
export interface FindingIssueGroupMember {
  id: string
  title: string
  tool_name: string
  rule_id: string
  status: string
  severity: string
  asset_id?: string
  asset_name?: string
  file_path?: string
  start_line?: number
  is_primary: boolean
  /** The rule that linked this member: sast_overlap | secret_value | vuln_alias. */
  rule?: string
  /** Field names the rule compared (never values). */
  basis?: string[]
  linked_at?: string
}

interface FindingIssueGroupResponse {
  members: FindingIssueGroupMember[]
}

const config: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
  onError: (error) => {
    handleApiError(error, { showToast: false, logError: true })
  },
}

export function issueGroupKey(findingId: string) {
  return `/api/v1/findings/${findingId}/issue-links`
}

export function useFindingIssueGroup(findingId: string | null | undefined) {
  const { currentTenant } = useTenant()
  const key = currentTenant && findingId ? issueGroupKey(findingId) : null
  const { data, error, isLoading, mutate } = useSWR<FindingIssueGroupResponse>(
    key,
    (url: string) => get<FindingIssueGroupResponse>(url),
    config
  )
  return { members: data?.members ?? [], error, isLoading, mutate }
}

/** Takes `otherId` out of the group of `findingId` (or `findingId` out of it). */
export function unlinkIssue(findingId: string, otherId: string) {
  return del<void>(`${issueGroupKey(findingId)}/${otherId}`)
}
