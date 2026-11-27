'use client'

/**
 * People on a remediation task (RFC-120): its owner (a person or a team), the
 * watchers summary with your own Watch toggle; watchers are listed, added and
 * removed in the manage sheet (research/256). The member picker lists members;
 * the API refuses anyone who cannot read the task with one generic answer, so
 * the list never promises access.
 */

import { useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { useCanMutate, Permission } from '@/lib/permissions'
import { usePermissions } from '@/context/permission-provider'
import { PropertyGroup, PropertyRow } from '@/features/shared/components/detail'
import { WatchersControl } from '@/features/shared/components/watchers/watchers-control'
import { useMembers } from '@/features/organization/api/use-members'
import { useSearchQuery } from '@/hooks/use-search-query'

export interface TaskPeopleProps {
  taskId: string
  /** The owner as text: a person, a team, or "unassigned". */
  owner: string
}

export function TaskPeople({ taskId, owner }: TaskPeopleProps) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const { hasPermission } = usePermissions()
  const canManage = useCanMutate('POST /api/v1/remediation/tasks/{task_id}/watchers')
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const searchTerm = useSearchQuery(search).term
  const { members, isLoading } = useMembers(open && canManage ? currentTenant?.id : undefined, {
    search: searchTerm || undefined,
    limit: 20,
  })

  return (
    <PropertyGroup caption={t('remediationHub.people.title', 'People')}>
      <PropertyRow label={t('remediationHub.people.owner', 'Owner')}>{owner}</PropertyRow>
      <WatchersControl
        kind="task"
        deferred
        itemId={taskId}
        canAdd={canManage && hasPermission(Permission.MembersRead)}
        canRemoveOthers={canManage}
        picker={{
          candidates: members.map((m) => ({
            id: m.user_id,
            name: m.name || m.email || m.user_id,
          })),
          isLoading,
          onSearch: setSearch,
          onOpenChange: setOpen,
        }}
      />
    </PropertyGroup>
  )
}
