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
import { WatchersControl } from '@/features/shared/components/watchers/watchers-control'
import { useMembers } from '@/features/organization/api/use-members'

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
  const { members, isLoading } = useMembers(open && canManage ? currentTenant?.id : undefined, {
    search: search.trim() || undefined,
    limit: 20,
  })

  return (
    <div
      role="group"
      aria-label={t('remediationHub.people.title', 'People')}
      className="space-y-2 rounded-lg border p-4"
    >
      <h2 className="text-sm font-semibold">{t('remediationHub.people.title', 'People')}</h2>
      <dl className="space-y-1">
        <div className="grid min-h-8 grid-cols-[6.5rem_minmax(0,1fr)] items-center gap-x-3">
          <dt className="text-body text-muted-foreground">
            {t('remediationHub.people.owner', 'Owner')}
          </dt>
          <dd className="min-w-0 text-body break-words">{owner}</dd>
        </div>
        <WatchersControl
          kind="task"
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
      </dl>
    </div>
  )
}
