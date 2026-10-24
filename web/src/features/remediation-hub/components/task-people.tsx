'use client'

/**
 * People on a remediation task (RFC-120): its owner (a person or a team), the
 * watchers with why each one watches, and the bell. The member picker lists
 * members; the API refuses anyone who cannot read the task with one generic
 * answer, so the list never promises access.
 */

import { useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { useAuthStore } from '@/stores/auth-store'
import { useCanMutate, Permission } from '@/lib/permissions'
import { usePermissions } from '@/context/permission-provider'
import { WatchersBlock } from '@/features/shared/components/watchers-block'
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
  const me = useAuthStore((s) => s.user?.id)
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
    <div
      role="group"
      aria-label={t('remediationHub.people.title', 'People')}
      className="space-y-2 rounded-lg border p-4"
    >
      <h2 className="text-sm font-semibold">{t('remediationHub.people.title', 'People')}</h2>
      <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] items-center gap-x-3 text-sm">
        <span className="text-xs text-muted-foreground">
          {t('remediationHub.people.owner', 'Owner')}
        </span>
        <span className="min-w-0 break-words">{owner}</span>
      </div>
      <WatchersBlock
        kind="task"
        itemId={taskId}
        canAdd={canManage && hasPermission(Permission.MembersRead)}
        canRemoveOthers={canManage}
        currentUserId={me}
        picker={{
          candidates: members.map((m) => ({ id: m.user_id, name: m.name || m.email || m.user_id })),
          isLoading,
          onSearch: setSearch,
          onOpenChange: setOpen,
        }}
      />
    </div>
  )
}
