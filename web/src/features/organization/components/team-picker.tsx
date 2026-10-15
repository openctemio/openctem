'use client'

import { useId, useMemo, useState } from 'react'
import { Users } from 'lucide-react'

import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { Group } from '@/features/access-control/types/group.types'

/** The API's cap on teams per invitation. */
export const MAX_INVITATION_TEAMS = 20

/** Show a search box above this many teams. */
const SEARCH_FROM = 8

export type TeamPickerItem = Pick<Group, 'id' | 'name' | 'group_type' | 'is_active'> &
  Partial<Pick<Group, 'member_count'>>

/**
 * Teams the invitee joins when they accept (api RFC-095 §5): the teams give
 * data access. Inactive teams are left out; the API decides whether the
 * inviter may add the person to each team and explains a refusal.
 */
export function TeamPicker({
  teams,
  selected,
  onChange,
  loading,
  disabled,
  labelledBy,
}: {
  teams: TeamPickerItem[]
  selected: string[]
  onChange: (next: string[]) => void
  loading?: boolean
  disabled?: boolean
  labelledBy?: string
}) {
  const { t } = useTranslation()
  const searchId = useId()
  const [query, setQuery] = useState('')

  const active = useMemo(
    () =>
      teams
        .filter((g) => g.id && g.is_active !== false)
        .sort((a, b) => a.name.localeCompare(b.name)),
    [teams]
  )
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    return q ? active.filter((g) => g.name.toLowerCase().includes(q)) : active
  }, [active, query])

  if (loading) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-9 w-full" />
        <Skeleton className="h-9 w-full" />
      </div>
    )
  }
  if (active.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('org.invite.teams.none')}</p>
  }

  const full = selected.length >= MAX_INVITATION_TEAMS
  const toggle = (id: string, on: boolean) =>
    onChange(on ? [...selected, id] : selected.filter((s) => s !== id))

  return (
    <div className="space-y-2">
      {active.length > SEARCH_FROM && (
        <Input
          id={searchId}
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('org.invite.teams.search')}
          aria-label={t('org.invite.teams.search')}
          disabled={disabled}
        />
      )}
      <div role="group" aria-labelledby={labelledBy} className="grid gap-1.5 sm:grid-cols-2">
        {shown.map((g) => {
          const checked = selected.includes(g.id)
          const id = `invite-team-${g.id}`
          return (
            <label
              key={g.id}
              htmlFor={id}
              className={cn(
                'flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm',
                checked ? 'border-primary bg-primary/5' : 'border-border hover:bg-muted/50',
                (disabled || (full && !checked)) && 'cursor-not-allowed opacity-60'
              )}
            >
              <Checkbox
                id={id}
                checked={checked}
                disabled={disabled || (full && !checked)}
                onCheckedChange={(v) => toggle(g.id, v === true)}
              />
              <Users className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
              <span className="min-w-0 flex-1 truncate">{g.name}</span>
              {g.group_type === 'external' && (
                <span className="shrink-0 text-xs text-muted-foreground">
                  {t('org.invite.teams.external')}
                </span>
              )}
            </label>
          )
        })}
      </div>
      {shown.length === 0 && (
        <p className="text-sm text-muted-foreground">{t('org.invite.teams.noMatch')}</p>
      )}
      {full && (
        <p className="text-xs text-muted-foreground">
          {t('org.invite.teams.max', undefined, { max: MAX_INVITATION_TEAMS })}
        </p>
      )}
    </div>
  )
}
