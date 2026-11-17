'use client'

/**
 * People on a finding (RFC-120): the assignee, the watchers summary with your
 * own Watch toggle, and the owners of the asset as context. Watchers are
 * listed, added and removed in the manage sheet (research/256). Rendered in
 * the finding's rail on the page and in the drawer, as its own `<dl>` in the
 * properties group.
 */

import { useState, type ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useCanMutate } from '@/lib/permissions'
import { PropertyGroup, PropertyRow } from '@/features/shared/components/detail'
import { WatchersControl } from '@/features/shared/components/watchers/watchers-control'
import { useAssignableMembers } from '../../api/use-assignable-members'
import { useSearchQuery } from '@/hooks/use-search-query'

export interface FindingPeopleProps {
  findingId: string
  /** The assignee control (page) or the read-only assignee (drawer). */
  assignee: ReactNode
}

export function FindingPeople({ findingId, assignee }: FindingPeopleProps) {
  const { t } = useTranslation()
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
    <PropertyGroup caption={t('findings.people.title', 'People')}>
      <PropertyRow label={t('findings.properties.assignee', 'Assignee')}>{assignee}</PropertyRow>
      <WatchersControl
        kind="finding"
        itemId={findingId}
        canAdd={canManage}
        canRemoveOthers={canManage}
        picker={{
          candidates: members.map((m) => ({ id: m.user_id, name: m.name })),
          isLoading,
          onSearch: setSearch,
          onOpenChange: setOpen,
        }}
      />
    </PropertyGroup>
  )
}
