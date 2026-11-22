'use client'

import { useMemo } from 'react'
import { useTenant } from '@/context/tenant-provider'
import { useMembers } from '@/features/organization/api/use-members'
import { useGroups } from '@/features/access-control/api/use-groups'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'

export interface OwnerOption {
  id: string
  name: string
}

/** Why an owner list is what it is: the pickers say it instead of showing an empty list. */
export interface OwnerListState {
  /** The caller may read the list at all. */
  allowed: boolean
  loading: boolean
  error: boolean
}

/**
 * Names of the organization's members and groups, for owner labels and
 * pickers. Each list loads only with the permission to read it; an id
 * without a name shows as "unknown". The list states tell a picker why a
 * list is empty (no permission, still loading, failed, or really empty).
 */
export function useOwnerNames(enabled = true) {
  const { currentTenant } = useTenant()
  const { hasPermission } = usePermissions()
  const canUsers = hasPermission(Permission.MembersRead)
  const canGroups = hasPermission(Permission.GroupsRead)
  const m = useMembers(enabled ? currentTenant?.id : undefined, { limit: 500 })
  const g = useGroups(undefined, canGroups && enabled)
  const { members } = m
  const { groups } = g
  const usersState: OwnerListState = {
    allowed: canUsers,
    loading: Boolean(m.isLoading),
    error: Boolean(m.isError),
  }
  const groupsState: OwnerListState = {
    allowed: canGroups,
    loading: Boolean(g.isLoading),
    error: Boolean(g.isError),
  }
  const { allowed: ua, loading: ul, error: ue } = usersState
  const { allowed: ga, loading: gl, error: ge } = groupsState
  return useMemo(() => {
    const users: OwnerOption[] = members.map((x) => ({ id: x.user_id, name: x.name || x.email }))
    const groupOpts: OwnerOption[] = groups.map((x) => ({ id: x.id, name: x.name }))
    const userName = new Map(users.map((u) => [u.id, u.name]))
    const groupName = new Map(groupOpts.map((x) => [x.id, x.name]))
    return {
      users,
      groups: groupOpts,
      usersState: { allowed: ua, loading: ul, error: ue },
      groupsState: { allowed: ga, loading: gl, error: ge },
      user: (id?: string) => (id ? userName.get(id) : undefined),
      group: (id?: string) => (id ? groupName.get(id) : undefined),
    }
  }, [members, groups, ua, ul, ue, ga, gl, ge])
}

/**
 * Names of the few people and teams a page shows (an owner, the actors of a
 * timeline), looked up by id instead of loading the whole member list. Nothing
 * is read for an empty list; an id without a name gives undefined (the caller
 * shows "unknown"). Ids are sorted so two views of the same ids share one read.
 */
export function useOwnerLabels(userIds: (string | undefined)[], groupIds: (string | undefined)[]) {
  const { currentTenant } = useTenant()
  const { hasPermission } = usePermissions()
  const userKey = [...new Set(userIds.filter((x): x is string => !!x))].sort().join(',')
  const groupKey = [...new Set(groupIds.filter((x): x is string => !!x))].join(',')
  const users = useMemo(() => (userKey ? userKey.split(',') : []), [userKey])
  const m = useMembers(users.length ? currentTenant?.id : undefined, {
    userIds: users,
    limit: Math.min(Math.max(users.length, 1), 100),
  })
  const g = useGroups(undefined, groupKey !== '' && hasPermission(Permission.GroupsRead))
  const { members } = m
  const { groups } = g
  return useMemo(() => {
    const userName = new Map(members.map((x) => [x.user_id, x.name || x.email]))
    const groupName = new Map(groups.map((x) => [x.id, x.name]))
    return {
      user: (id?: string) => (id ? userName.get(id) : undefined),
      group: (id?: string) => (id ? groupName.get(id) : undefined),
    }
  }, [members, groups])
}
