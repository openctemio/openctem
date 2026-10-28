'use client'

/**
 * Team access presets (api RFC-127): GET/PUT /api/v1/groups/{groupId}/access,
 * POST .../access/upgrade, the templates a team can use as presets, and what
 * a person inherits from their teams.
 */

import useSWR, { mutate as globalMutate } from 'swr'
import { fetcher, fetcherWithOptions } from '@/lib/api/client'
import type { SetTeamAccessInput, TeamAccess, TeamPresetTemplate, UserTeamAccess } from '../types'
import { groupRolesKey } from './use-group-roles'

const API_BASE = '/api/v1/groups'

export function teamAccessKey(groupId: string): string {
  return `${API_BASE}/${encodeURIComponent(groupId)}/access`
}

/** The access a team carries (null id or skip: nothing is fetched). */
export function useTeamAccess(groupId: string | null, options?: { skip?: boolean }) {
  const { data, error, isLoading, mutate } = useSWR<TeamAccess>(
    groupId && !options?.skip ? teamAccessKey(groupId) : null,
    fetcher
  )
  return { access: data, error, isLoading, mutate }
}

/** The role templates a team can use as presets. */
export function useTeamPresetTemplates(options?: { skip?: boolean }) {
  const { data, error, isLoading } = useSWR<{ templates: TeamPresetTemplate[] }>(
    options?.skip ? null : '/api/v1/roles/templates',
    fetcher
  )
  return { templates: data?.templates ?? [], error, isLoading }
}

async function refresh(groupId: string) {
  await Promise.all([globalMutate(teamAccessKey(groupId)), globalMutate(groupRolesKey(groupId))])
}

/** Makes the team's presets and scope mode what the input says. */
export async function setTeamAccess(
  groupId: string,
  input: SetTeamAccessInput
): Promise<TeamAccess> {
  const out = await fetcherWithOptions<TeamAccess>(teamAccessKey(groupId), {
    method: 'PUT',
    body: JSON.stringify(input),
  })
  await refresh(groupId)
  return out
}

/** Applies a newer template version to one preset; `version` is the one the editor reviewed. */
export async function upgradeTeamPreset(
  groupId: string,
  templateId: string,
  version: number
): Promise<TeamAccess> {
  const out = await fetcherWithOptions<TeamAccess>(`${teamAccessKey(groupId)}/upgrade`, {
    method: 'POST',
    body: JSON.stringify({ template_id: templateId, version }),
  })
  await refresh(groupId)
  return out
}

/** What a person inherits from their teams (skip: nothing is fetched). */
export function useUserTeamAccess(userId: string | null | undefined) {
  const { data, error, isLoading } = useSWR<{ data: UserTeamAccess[] }>(
    userId ? `/api/v1/users/${encodeURIComponent(userId)}/team-access` : null,
    fetcher,
    { shouldRetryOnError: false }
  )
  return { grants: data?.data ?? [], error, isLoading }
}
