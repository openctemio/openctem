'use client'

/**
 * Who did something, as a person or as a system action in words (research/53
 * §4.6). Every place that renders a `created_by` / approver uses this, so no
 * raw user id or "system:migration-…" string reaches the screen.
 *
 * Input is either the API's actor object (`{kind: "user", id, name}` or
 * `{kind: "system", code}`) or, for older responses, the bare stored value.
 * A bare user id is resolved against this organization's member list (names
 * only, never e-mail; the member list is tenant-scoped by the server). A
 * person the list does not hold reads "Former member"; without permission
 * to read members it reads "A team member".
 */

import { useMemo } from 'react'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { useMembers } from '@/features/organization/api/use-members'
import { Permission, usePermissions } from '@/lib/permissions'
import { cn } from '@/lib/utils'

export interface ActorRef {
  kind?: 'user' | 'system' | string
  id?: string
  name?: string | null
  code?: string
  former_member?: boolean
}

/** System actor codes -> English fallback (i18n keys `actor.system.<code>`). */
export const SYSTEM_ACTOR_TEXT: Record<string, string> = {
  upgrade_wildcard_split: 'OpenCTEM upgrade (wildcard rule change)',
  seed_migration: 'OpenCTEM upgrade (was a discovery seed)',
  review_rule: 'Accepted from a review rule',
  refusal_fix: 'Allowed from a refused scan',
  system: 'OpenCTEM (automatic)',
}

/** Stored system strings older rows carry, mapped to a code. */
export function systemCodeOf(raw: string): string | undefined {
  if (!raw.startsWith('system')) return undefined
  if (raw === 'system:migration-000292') return 'upgrade_wildcard_split'
  return 'system'
}

export function toActorRef(actor: ActorRef | string | null | undefined): ActorRef | null {
  if (!actor) return null
  if (typeof actor !== 'string') return actor
  const code = systemCodeOf(actor)
  if (code) return { kind: 'system', code }
  return { kind: 'user', id: actor }
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return '?'
  const first = parts[0][0] ?? ''
  const last = parts.length > 1 ? (parts[parts.length - 1][0] ?? '') : ''
  return (first + last).toUpperCase()
}

/**
 * Names of this organization's members by user id. Loads once per tenant
 * (cached by SWR, shared by every chip on the page).
 */
export function useMemberNames(enabled = true) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const allowed = can(Permission.MembersRead)
  // Current members (active and suspended): a person who left is not listed
  // and reads "Former member", which is what they are.
  const { members, isLoading } = useMembers(enabled && allowed ? currentTenant?.id : undefined, {
    status: 'current',
    limit: 100,
  })
  const names = useMemo(() => {
    const m = new Map<string, string>()
    for (const x of members) if (x.user_id) m.set(x.user_id, x.name || '')
    return m
  }, [members])
  return { names, allowed, isLoading }
}

interface ActorChipProps {
  actor: ActorRef | string | null | undefined
  /** Shown in the tooltip ("3 Oct 2026, 14:02"). */
  at?: string
  className?: string
  /** Hide the avatar (dense rows). */
  compact?: boolean
}

export function ActorChip({ actor, at, className, compact }: ActorChipProps) {
  const { t } = useTranslation()
  const ref = toActorRef(actor)
  const needsLookup = ref?.kind === 'user' && !ref.name && !ref.former_member
  const { names, allowed, isLoading } = useMemberNames(needsLookup)

  if (!ref) return <span className={cn('text-sm text-muted-foreground', className)}>-</span>

  let label: string
  let system = false
  if (ref.kind === 'system') {
    system = true
    const code = ref.code && SYSTEM_ACTOR_TEXT[ref.code] ? ref.code : 'system'
    label = t(`actor.system.${code}`, SYSTEM_ACTOR_TEXT[code])
  } else if (ref.name) {
    label = ref.name
  } else if (ref.former_member) {
    label = t('actor.former', 'Former member')
  } else if (ref.id && names.has(ref.id)) {
    label = names.get(ref.id) || t('actor.member', 'A team member')
  } else if (!allowed || isLoading) {
    label = t('actor.member', 'A team member')
  } else {
    label = t('actor.former', 'Former member')
  }

  const title = at ? `${label} · ${new Date(at).toLocaleString()}` : label
  return (
    <span
      className={cn('inline-flex min-w-0 items-center gap-1.5 text-sm', className)}
      title={title}
      data-actor-kind={system ? 'system' : 'user'}
    >
      {!compact && (
        <Avatar className="h-5 w-5 shrink-0">
          <AvatarFallback className="text-[10px]">{system ? 'OC' : initials(label)}</AvatarFallback>
        </Avatar>
      )}
      <span className={cn('truncate', system && 'text-muted-foreground')}>{label}</span>
    </span>
  )
}
