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

/**
 * Names of the organization's members and groups, for owner labels and
 * pickers. Each list loads only with the permission to read it; an id
 * without a name shows as "unknown".
 */
export function useOwnerNames() {
  const { currentTenant } = useTenant()
  const { hasPermission } = usePermissions()
  const { members } = useMembers(currentTenant?.id, { limit: 500 })
  const { groups } = useGroups(undefined, hasPermission(Permission.GroupsRead))
  return useMemo(() => {
    const users: OwnerOption[] = members.map((m) => ({ id: m.user_id, name: m.name || m.email }))
    const groupOpts: OwnerOption[] = groups.map((g) => ({ id: g.id, name: g.name }))
    const userName = new Map(users.map((u) => [u.id, u.name]))
    const groupName = new Map(groupOpts.map((g) => [g.id, g.name]))
    return {
      users,
      groups: groupOpts,
      user: (id?: string) => (id ? userName.get(id) : undefined),
      group: (id?: string) => (id ? groupName.get(id) : undefined),
    }
  }, [members, groups])
}
