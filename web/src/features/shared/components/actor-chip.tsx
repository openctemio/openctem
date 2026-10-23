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

import useSWR from 'swr'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import type { MemberListResponse } from '@/features/organization/types/member.types'
import { fetcher } from '@/lib/api/client'
import { tenantEndpoints } from '@/lib/api/endpoints'
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
  upgrade_wildcard_split: '{product} upgrade (wildcard rule change)',
  seed_migration: '{product} upgrade (was a discovery seed)',
  review_rule: 'Accepted from a review rule',
  refusal_fix: 'Allowed from a refused scan',
  confirmed_asset: 'Added when an asset was confirmed as ours',
  connector: 'Synced by a connector',
  system: '{product} (automatic)',
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

/** The server accepts at most this many user ids per members request. */
const NAME_BATCH_SIZE = 100

type NameWaiter = {
  id: string
  resolve: (name: string | null) => void
  reject: (e: unknown) => void
}
const pendingNames = new Map<string, NameWaiter[]>()
const nameFlushTimers = new Map<string, ReturnType<typeof setTimeout>>()

async function flushNames(tenantId: string) {
  const waiters = pendingNames.get(tenantId) ?? []
  pendingNames.delete(tenantId)
  nameFlushTimers.delete(tenantId)
  const ids = [...new Set(waiters.map((w) => w.id))]
  const found = new Map<string, string>()
  try {
    for (let i = 0; i < ids.length; i += NAME_BATCH_SIZE) {
      const params = new URLSearchParams({
        include: 'user',
        per_page: String(NAME_BATCH_SIZE),
        user_ids: ids.slice(i, i + NAME_BATCH_SIZE).join(','),
      })
      const res = await fetcher<MemberListResponse>(
        `${tenantEndpoints.members(tenantId)}?${params.toString()}`
      )
      for (const m of res.data ?? []) if (m.user_id) found.set(m.user_id, m.name || '')
    }
    for (const w of waiters) w.resolve(found.has(w.id) ? (found.get(w.id) ?? '') : null)
  } catch (e) {
    for (const w of waiters) w.reject(e)
  }
}

/**
 * Looks one user id up by its exact id. Lookups made in the same tick, by
 * every chip on the page, leave as ONE members request filtered by user_ids,
 * so a person is found however many members the organization has (the old
 * lookup read the first 100 and called everyone else a former member).
 * Resolves null when the id is not a member of the organization.
 */
export function lookupMemberName(tenantId: string, id: string): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const list = pendingNames.get(tenantId) ?? []
    list.push({ id, resolve, reject })
    pendingNames.set(tenantId, list)
    if (!nameFlushTimers.has(tenantId)) {
      nameFlushTimers.set(
        tenantId,
        setTimeout(() => void flushNames(tenantId), 10)
      )
    }
  })
}

/**
 * The name of one organization member, by user id. Needs members:read; the
 * server answers only for members of this organization (current members:
 * active and suspended). `found` is false only after the lookup finished and
 * the id is not a member, which is when "Former member" is true.
 */
export function useMemberName(id: string | undefined, enabled = true) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const allowed = can(Permission.MembersRead)
  const tenantId = currentTenant?.id
  const { data, isLoading, error } = useSWR(
    enabled && allowed && tenantId && id ? `member-name:${tenantId}:${id}` : null,
    () => lookupMemberName(tenantId as string, id as string),
    { revalidateOnFocus: false, dedupingInterval: 60000 }
  )
  return {
    name: data ?? undefined,
    found: typeof data === 'string',
    /** The lookup finished (the id may still be unknown: data is null). */
    done: data !== undefined,
    allowed,
    isLoading,
    failed: !!error,
  }
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
  const lookup = useMemberName(ref?.id, needsLookup)

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
  } else if (lookup.found) {
    label = lookup.name || t('actor.member', 'A team member')
  } else if (!lookup.allowed || lookup.isLoading || lookup.failed || !lookup.done) {
    // No permission, still loading or the lookup failed: the person is not
    // known to be gone, so do not say so.
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
