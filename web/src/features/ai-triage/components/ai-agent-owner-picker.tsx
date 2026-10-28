'use client'

import { useMemo, useState } from 'react'

import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useGroups } from '@/features/access-control/api/use-groups'
import { useMembers } from '@/features/organization/api/use-members'
import { ListSearch } from '@/features/shared/components/list-search'
import { TeamPicker } from '@/features/organization/components/team-picker'
import { toDisplayText } from '@/lib/untrusted-text'

import type { AIOwnerInput } from '../api/use-ai-agents'

/** The API's cap on accountable owners. */
export const MAX_AI_OWNERS = 20

const keyOf = (o: AIOwnerInput) => `${o.kind}:${o.id}`

/**
 * Accountable owners of an AI agent: active members (people) and teams.
 * The API decides whether the chosen people may hold the preset's permissions
 * and explains a refusal.
 */
export function AIAgentOwnerPicker({
  tenant,
  value,
  onChange,
  disabled,
}: {
  tenant: string | undefined
  value: AIOwnerInput[]
  onChange: (next: AIOwnerInput[]) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const { members, isLoading: membersLoading } = useMembers(tenant, { limit: 100 })
  const { groups, isLoading: teamsLoading } = useGroups(undefined, true)

  const selected = useMemo(() => new Set(value.map(keyOf)), [value])
  const people = useMemo(() => {
    const q = query.trim().toLowerCase()
    return members.filter(
      (m) => !q || m.name?.toLowerCase().includes(q) || m.email?.toLowerCase().includes(q)
    )
  }, [members, query])
  const full = value.length >= MAX_AI_OWNERS

  const toggleUser = (id: string, on: boolean) =>
    onChange(
      on
        ? [...value, { kind: 'user', id }]
        : value.filter((o) => !(o.kind === 'user' && o.id === id))
    )
  const teamIds = value.filter((o) => o.kind === 'team').map((o) => o.id)
  const setTeams = (ids: string[]) =>
    onChange([
      ...value.filter((o) => o.kind === 'user'),
      ...ids.map((id) => ({ kind: 'team' as const, id })),
    ])

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label>{t('settings.ai.agents.owners.people', 'People')}</Label>
        {membersLoading ? (
          <Skeleton className="h-9 w-full" />
        ) : (
          <>
            <ListSearch
              value={query}
              onChange={setQuery}
              placeholder={t('settings.ai.agents.owners.search', 'Search people')}
              inputProps={{ disabled }}
            />
            <ul
              className="max-h-40 space-y-1 overflow-y-auto"
              aria-label={t('settings.ai.agents.owners.people', 'People')}
            >
              {people.map((m) => {
                const on = selected.has(`user:${m.user_id}`)
                const id = `ai-owner-${m.user_id}`
                return (
                  <li key={m.user_id} className="flex items-center gap-2">
                    <Checkbox
                      id={id}
                      checked={on}
                      disabled={disabled || (!on && full)}
                      onCheckedChange={(c) => toggleUser(m.user_id, c === true)}
                    />
                    <Label htmlFor={id} className="font-normal">
                      {toDisplayText(m.name || m.email, 80)}
                    </Label>
                  </li>
                )
              })}
              {people.length === 0 && (
                <li className="text-sm text-muted-foreground">
                  {t('settings.ai.agents.owners.noPeople', 'No matching people.')}
                </li>
              )}
            </ul>
          </>
        )}
      </div>
      <div className="space-y-2">
        <Label id="ai-owner-teams">{t('settings.ai.agents.owners.teams', 'Teams')}</Label>
        <TeamPicker
          teams={groups}
          selected={teamIds}
          onChange={setTeams}
          loading={teamsLoading}
          disabled={disabled || (full && teamIds.length === 0)}
          labelledBy="ai-owner-teams"
        />
      </div>
    </div>
  )
}
