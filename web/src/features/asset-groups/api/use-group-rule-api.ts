/**
 * API of the groups that fill themselves: rule preview, set and clear a rule,
 * pasted lists, "add all matching" and the membership history.
 * Every call is tenant-scoped by the caller's token.
 */

'use client'

import useSWR, { mutate as globalMutate, type SWRConfiguration } from 'swr'
import { get, post, put } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import type {
  AddMatchingResult,
  GroupHistoryResponse,
  GroupRule,
  GroupRuleDocument,
  GroupRulePreview,
  PasteGroupResult,
  SetGroupRuleResult,
} from '../types'

const BASE_URL = '/api/v1/asset-groups'

/** What a rule matches now, as the caller, without saving anything. */
export function previewGroupRule(
  rule: GroupRuleDocument,
  groupId?: string
): Promise<GroupRulePreview> {
  return post<GroupRulePreview>(`${BASE_URL}/rule/preview`, {
    rule,
    group_id: groupId || undefined,
  })
}

/** Set a group's rule (null removes it) and evaluate it at once. */
export function setGroupRule(
  groupId: string,
  rule: GroupRuleDocument | null
): Promise<SetGroupRuleResult> {
  return put<SetGroupRuleResult>(`${BASE_URL}/${encodeURIComponent(groupId)}/rule`, { rule })
}

/** Match a pasted list against the assets and add what is found. */
export function pasteIntoGroup(
  groupId: string,
  input: { text: string; createMissing?: boolean; dryRun?: boolean }
): Promise<PasteGroupResult> {
  return post<PasteGroupResult>(`${BASE_URL}/${encodeURIComponent(groupId)}/assets/paste`, {
    text: input.text,
    create_missing: input.createMissing ?? false,
    dry_run: input.dryRun ?? false,
  })
}

/** Add every asset a filter matches (not only the visible page). */
export function addMatchingToGroup(
  groupId: string,
  rule: GroupRuleDocument
): Promise<AddMatchingResult> {
  return post<AddMatchingResult>(`${BASE_URL}/${encodeURIComponent(groupId)}/assets/matching`, {
    rule,
  })
}

/** Refresh everything that shows a group after its members changed. */
export async function invalidateGroupMembership(groupId: string): Promise<void> {
  await globalMutate(
    (key) =>
      typeof key === 'string' &&
      (key === BASE_URL ||
        key.startsWith(`${BASE_URL}/${groupId}`) ||
        key.startsWith(`${BASE_URL}?`)),
    undefined,
    { revalidate: true }
  )
}

/** The join and leave history of a group, newest first. */
export function useGroupHistoryApi(
  groupId: string | null,
  page = 1,
  perPage = 20,
  config?: SWRConfiguration
) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const key =
    currentTenant && groupId && can(Permission.AssetGroupsRead)
      ? `${BASE_URL}/${encodeURIComponent(groupId)}/history?page=${page}&per_page=${perPage}`
      : null
  return useSWR<GroupHistoryResponse>(key, (url: string) => get<GroupHistoryResponse>(url), {
    revalidateOnFocus: false,
    ...config,
  })
}

/** A group's rule, or undefined for a plain group. */
export function ruleOf(group: { rule?: GroupRule } | undefined | null): GroupRule | undefined {
  return group?.rule
}
