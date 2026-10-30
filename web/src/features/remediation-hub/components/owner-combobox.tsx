'use client'

/**
 * Picks the owner of a task: a person or a team, searchable. When a list is
 * empty the picker says why (no permission to see it, still loading, failed,
 * or the organization has none yet, with a link to create one when the
 * viewer may) instead of showing an empty menu. The suggested owner (the
 * asset's owner) is marked.
 */

import { useState } from 'react'
import Link from '@/components/link'
import { Check, ChevronsUpDown, Loader2, User, Users } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command'
import { cn } from '@/lib/utils'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import type { OwnerListState, OwnerOption } from '../api/use-owner-names'
import type { OwnerCandidates, OwnerCandidate } from '../api/use-owner-access'

export interface OwnerValue {
  userId?: string
  groupId?: string
}

export interface OwnerComboboxProps {
  value: OwnerValue
  onChange: (v: OwnerValue) => void
  users: OwnerOption[]
  groups: OwnerOption[]
  usersState?: OwnerListState
  groupsState?: OwnerListState
  /** The owner proposed (the asset's owner, or the current owner). */
  suggested?: OwnerValue
  /** How the proposed owner is marked; "Asset owner" by default. */
  suggestedLabel?: string
  /** Accessible name of the trigger. */
  label: string
  disabled?: boolean
  id?: string
  /**
   * What each candidate cannot see among the task's open findings (counts
   * only). Without it the picker behaves as before.
   */
  access?: OwnerCandidates
  /** The viewer holds findings:assign: may choose an owner who lacks access. */
  canAssign?: boolean
  /** The viewer accepted that the chosen owner will see the findings. */
  consent?: boolean
  onConsentChange?: (v: boolean) => void
  /** "Request access" on a candidate the viewer may not pick. */
  onRequestAccess?: (c: OwnerCandidate) => void
}

/** The gap of the person or team a value names (the larger of the two). */
export function gapOf(
  access: OwnerCandidates | undefined,
  v: OwnerValue
): OwnerCandidate | undefined {
  if (!access) return undefined
  const found = access.candidates.filter(
    (c) => (c.type === 'user' && c.id === v.userId) || (c.type === 'team' && c.id === v.groupId)
  )
  return found
    .filter((c) => c.missing_findings > 0)
    .sort((a, b) => b.missing_findings - a.missing_findings)[0]
}

const OK: OwnerListState = { allowed: true, loading: false, error: false }

/** Why a list has nothing to pick, or null when it has items. */
export function listNotice(
  state: OwnerListState,
  count: number
): 'forbidden' | 'loading' | 'error' | 'empty' | null {
  if (!state.allowed) return 'forbidden'
  if (state.loading && count === 0) return 'loading'
  if (state.error) return 'error'
  if (count === 0) return 'empty'
  return null
}

export function OwnerCombobox({
  value,
  onChange,
  users,
  groups,
  usersState = OK,
  groupsState = OK,
  suggested,
  suggestedLabel,
  label,
  disabled,
  id,
  access,
  canAssign = false,
  consent = false,
  onConsentChange,
  onRequestAccess,
}: OwnerComboboxProps) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const [open, setOpen] = useState(false)
  const canCreateTeam = hasPermission(Permission.GroupsWrite)
  const userName = value.userId ? users.find((u) => u.id === value.userId)?.name : undefined
  const groupName = value.groupId ? groups.find((g) => g.id === value.groupId)?.name : undefined
  const current =
    [userName, groupName].filter(Boolean).join(', ') ||
    (value.userId || value.groupId ? t('remediationHub.ownerPicker.unknown') : '')
  const isSuggested = (v: OwnerValue) =>
    !!suggested &&
    (v.userId ?? '') === (suggested.userId ?? '') &&
    (v.groupId ?? '') === (suggested.groupId ?? '') &&
    !!(v.userId || v.groupId)
  const mark = suggestedLabel ?? t('remediationHub.owner.assetOwner')
  const gap = (type: 'user' | 'team', gid: string) =>
    access?.candidates.find((c) => c.type === type && c.id === gid && c.missing_findings > 0)
  // Without findings:assign an owner who lacks access cannot be chosen.
  const blocked = (type: 'user' | 'team', gid: string) => !canAssign && !!gap(type, gid)
  const pick = (v: OwnerValue) => {
    onChange(v)
    onConsentChange?.(false)
    setOpen(false)
  }
  const chosenGap = gapOf(access, value)
  const gapLine = (c: OwnerCandidate) =>
    c.type === 'team'
      ? t('remediationHub.ownerAccess.teamGap', undefined, {
          missing: c.members_missing ?? 0,
          members: c.members ?? 0,
          findings: c.missing_findings,
        })
      : t('remediationHub.ownerAccess.gap', undefined, {
          findings: c.missing_findings,
          assets: c.missing_assets,
        })
  const gapRow = (type: 'user' | 'team', gid: string) => {
    const c = gap(type, gid)
    if (!c) return null
    return (
      <span className="ms-auto flex shrink-0 items-center gap-2 text-xs">
        <span className="text-warning" data-testid={`owner-gap-${gid}`}>
          {gapLine(c)}
        </span>
        {!canAssign && onRequestAccess && (
          <button
            type="button"
            className="text-primary underline underline-offset-2"
            onPointerDown={(e) => e.stopPropagation()}
            onClick={(e) => {
              e.stopPropagation()
              onRequestAccess(c)
            }}
          >
            {t('remediationHub.ownerAccess.request')}
          </button>
        )}
      </span>
    )
  }
  const teamNotice = listNotice(groupsState, groups.length)
  const userNotice = listNotice(usersState, users.length)

  const notice = (kind: 'forbidden' | 'loading' | 'error' | 'empty', list: 'teams' | 'people') => (
    <p
      className="text-muted-foreground flex items-center gap-2 px-2 py-1.5 text-xs"
      role={kind === 'error' ? 'alert' : undefined}
      data-testid={`owner-notice-${list}-${kind}`}
    >
      {kind === 'loading' && <Loader2 className="size-3 animate-spin" aria-hidden />}
      <span>
        {t(`remediationHub.ownerPicker.${list}.${kind}`)}
        {kind === 'empty' && list === 'teams' && canCreateTeam && (
          <>
            {' '}
            <Link href="/settings/teams" className="text-primary underline underline-offset-2">
              {t('remediationHub.ownerPicker.teams.create')}
            </Link>
          </>
        )}
      </span>
    </p>
  )

  return (
    <div className="space-y-2">
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            id={id}
            type="button"
            variant="outline"
            role="combobox"
            aria-expanded={open}
            aria-label={label}
            disabled={disabled}
            className="w-full justify-between font-normal"
          >
            <span className={cn('truncate', !current && 'text-muted-foreground')}>
              {current || t('remediationHub.ownerPicker.placeholder')}
            </span>
            {isSuggested(value) && (
              <span className="text-muted-foreground ms-auto me-1 shrink-0 text-xs">{mark}</span>
            )}
            <ChevronsUpDown className="size-4 shrink-0 opacity-50" aria-hidden />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[--radix-popover-trigger-width] min-w-72 p-0" align="start">
          <Command>
            <CommandInput placeholder={t('remediationHub.ownerPicker.search')} />
            <CommandList>
              <CommandEmpty>{t('remediationHub.ownerPicker.noMatch')}</CommandEmpty>
              {suggested && (suggested.userId || suggested.groupId) && (
                <CommandGroup heading={t('remediationHub.ownerPicker.suggested')}>
                  <CommandItem value={`suggested ${mark}`} onSelect={() => pick({ ...suggested })}>
                    <Check
                      className={cn('size-4', isSuggested(value) ? 'opacity-100' : 'opacity-0')}
                      aria-hidden
                    />
                    {[
                      suggested.userId ? users.find((u) => u.id === suggested.userId)?.name : '',
                      suggested.groupId ? groups.find((g) => g.id === suggested.groupId)?.name : '',
                    ]
                      .filter(Boolean)
                      .join(', ') || t('remediationHub.ownerPicker.unknown')}
                    <span className="text-muted-foreground ms-auto text-xs">{mark}</span>
                  </CommandItem>
                </CommandGroup>
              )}
              <CommandGroup heading={t('remediationHub.ownerPicker.teams.heading')}>
                {teamNotice
                  ? notice(teamNotice, 'teams')
                  : groups.map((g) => (
                      <CommandItem
                        key={g.id}
                        value={`team ${g.name} ${g.id}`}
                        disabled={blocked('team', g.id)}
                        onSelect={() => pick({ groupId: g.id })}
                      >
                        <Users className="size-4" aria-hidden />
                        <span className="truncate">{g.name}</span>
                        {gapRow('team', g.id)}
                        {value.groupId === g.id && !value.userId && (
                          <Check className="ms-auto size-4" aria-hidden />
                        )}
                      </CommandItem>
                    ))}
              </CommandGroup>
              <CommandSeparator />
              <CommandGroup heading={t('remediationHub.ownerPicker.people.heading')}>
                {userNotice
                  ? notice(userNotice, 'people')
                  : users.map((u) => (
                      <CommandItem
                        key={u.id}
                        value={`person ${u.name} ${u.id}`}
                        disabled={blocked('user', u.id)}
                        onSelect={() => pick({ userId: u.id })}
                      >
                        <User className="size-4" aria-hidden />
                        <span className="truncate">{u.name}</span>
                        {gapRow('user', u.id)}
                        {value.userId === u.id && !value.groupId && (
                          <Check className="ms-auto size-4" aria-hidden />
                        )}
                      </CommandItem>
                    ))}
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
      {chosenGap && canAssign && (
        <div
          className="space-y-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-xs"
          data-testid="owner-consent"
        >
          <p>
            {t('remediationHub.ownerAccess.consent', undefined, {
              name: chosenGap.name,
              findings: chosenGap.missing_findings,
            })}
          </p>
          <div className="flex items-start gap-2">
            <Checkbox
              id={`${id ?? 'owner'}-consent`}
              checked={consent}
              onCheckedChange={(v) => onConsentChange?.(v === true)}
            />
            <Label htmlFor={`${id ?? 'owner'}-consent`} className="text-xs font-normal">
              {t('remediationHub.ownerAccess.consentCheck')}
            </Label>
          </div>
        </div>
      )}
      {chosenGap && !canAssign && (
        <p className="text-xs text-warning" role="alert">
          {t('remediationHub.ownerAccess.noPermission')}
        </p>
      )}
    </div>
  )
}
