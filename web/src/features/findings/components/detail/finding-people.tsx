'use client'

/**
 * People on a finding (RFC-120): the assignee, the watchers with why each one
 * watches, the owners of the asset as context, and the bell. Rendered in the
 * finding's rail on the page and in the drawer.
 */

import { useState, type ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useAuthStore } from '@/stores/auth-store'
import { useCanMutate } from '@/lib/permissions'
import { WatchersBlock } from '@/features/shared/components/watchers-block'
import { useAssignableMembers } from '../../api/use-assignable-members'
import { useSearchQuery } from '@/hooks/use-search-query'

export interface FindingPeopleProps {
  findingId: string
  /** The assignee control (page) or the read-only assignee (drawer). */
  assignee: ReactNode
}

export function FindingPeople({ findingId, assignee }: FindingPeopleProps) {
  const { t } = useTranslation()
  const me = useAuthStore((s) => s.user?.id)
  // Adding and removing others is the assignment permission; the API refuses
  // anyone else, this only decides what to show.
  const canManage = useCanMutate('POST /api/v1/findings/{id}/watchers')
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const searchTerm = useSearchQuery(search).term
  const { members, isLoading } = useAssignableMembers(findingId, {
    search: searchTerm,
    limit: 20,
    enabled: open && canManage,
  })

  return (
    <div role="group" aria-label={t('findings.people.title', 'People')} className="space-y-2">
      <div className="my-2 border-t" role="presentation" />
      <h3 className="text-xs font-medium text-muted-foreground">
        {t('findings.people.title', 'People')}
      </h3>
      <div className="grid min-h-8 grid-cols-[6.5rem_minmax(0,1fr)] items-center gap-x-3">
        <span className="text-body text-muted-foreground">
          {t('findings.properties.assignee', 'Assignee')}
        </span>
        <div className="min-w-0 text-body break-words">{assignee}</div>
      </div>
      <WatchersBlock
        kind="finding"
        itemId={findingId}
        canAdd={canManage}
        canRemoveOthers={canManage}
        currentUserId={me}
        picker={{
          candidates: members.map((m) => ({ id: m.user_id, name: m.name })),
          isLoading,
          onSearch: setSearch,
          onOpenChange: setOpen,
        }}
      />
    </div>
  )
}
