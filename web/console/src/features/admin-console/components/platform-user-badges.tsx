'use client'

import { accountStatusLabel } from '../lib/value-labels'
import type { ComponentProps } from 'react'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { PlatformUser } from '../types'

interface Mark {
  key: string
  label: string
  variant: ComponentProps<typeof Badge>['variant']
  /** A mark drawn in a state colour rather than a badge variant. */
  tone?: 'warning' | 'success'
}

/**
 * The room a list row gives the marks (the Users list's State column, 208
 * px less its padding) and what a mark takes in it: the badge's padding and
 * border plus 6.2 px a character of its 12 px text (measured 5.3 to 5.9 in
 * en and vi). An estimate on the safe side, so the marks drawn are never cut.
 */
const ROW_ROOM = 184
const BADGE_CHROME = 18
const CHAR_PX = 6.2
const GAP = 4
const MORE_PX = 30
const markWidth = (label: string) => BADGE_CHROME + label.length * CHAR_PX

/** The marks that fit one row line, keeping room for the "+n" of the others. */
export function marksThatFit(labels: string[], room = ROW_ROOM): number {
  let used = 0
  for (let i = 0; i < labels.length; i++) {
    const next = used + (i ? GAP : 0) + markWidth(labels[i])
    const restRoom = i < labels.length - 1 ? GAP + MORE_PX : 0
    if (next + restRoom > room) return Math.max(1, i)
    used = next
  }
  return labels.length
}

/**
 * Sign-in state of one account: the state first (erased, blocked, locked,
 * suspended, active), then platform admin, unverified email and MFA.
 * `oneLine` is a list row: the marks that fit, then "+n" naming the others in
 * its tooltip; the account page shows every mark.
 */
export function PlatformUserBadges({
  user,
  oneLine = false,
}: {
  oneLine?: boolean
  user: Pick<
    PlatformUser,
    | 'erased'
    | 'is_platform_admin'
    | 'locked'
    | 'blocked'
    | 'status'
    | 'email_verified'
    | 'mfa_enabled'
  >
}) {
  const { t } = useTranslation()
  const plain =
    !user.erased &&
    !user.is_platform_admin &&
    !user.locked &&
    !user.blocked &&
    user.status === 'active' &&
    user.email_verified
  const marks: Mark[] = []
  if (user.erased)
    marks.push({
      key: 'erased',
      label: t('admin.users.badge.erased', 'Erased'),
      variant: 'outline',
    })
  if (user.blocked && !user.erased)
    marks.push({
      key: 'blocked',
      label: t('admin.users.badge.blocked', 'Blocked'),
      variant: 'destructive',
    })
  if (user.locked)
    marks.push({
      key: 'locked',
      label: t('admin.users.badge.locked', 'Locked'),
      variant: 'destructive',
    })
  if (user.status !== 'active' && !user.erased && !user.blocked)
    marks.push({ key: 'status', label: accountStatusLabel(t, user.status), variant: 'outline' })
  if (plain)
    marks.push({
      key: 'active',
      label: t('admin.users.badge.active', 'Active'),
      variant: 'outline',
    })
  if (user.is_platform_admin)
    marks.push({
      key: 'admin',
      label: t('admin.users.badge.admin', 'Platform admin'),
      variant: 'secondary',
    })
  if (!user.email_verified)
    marks.push({
      key: 'unverified',
      label: t('admin.users.badge.unverified', 'Email not verified'),
      variant: 'outline',
      tone: 'warning',
    })
  if (user.mfa_enabled)
    marks.push({
      key: 'mfa',
      label: t('admin.users.badge.mfa', 'Two-factor on'),
      variant: 'outline',
      tone: 'success',
    })

  if (!oneLine) {
    return (
      <div data-slot="platform-user-badges" className="flex flex-wrap gap-1">
        {marks.map(markBadge)}
      </div>
    )
  }
  // A list row: on a phone the card's chip (the state and "+n"), from 768 px
  // the marks that fit the column (marksThatFit). A first mark wider than its
  // room (a long translation) ends in an ellipsis.
  const group = (shown: number, className: string) => {
    const hidden = marks.slice(shown)
    return (
      <div
        data-slot="platform-user-badges"
        className={cn('min-w-0 gap-1 flex-nowrap *:shrink-0 [&>*:first-child]:shrink', className)}
      >
        {marks.slice(0, shown).map(markBadge)}
        {hidden.length > 0 && (
          <Badge variant="outline" title={hidden.map((m) => m.label).join(', ')}>
            +{hidden.length}
            <span className="sr-only">{hidden.map((m) => m.label).join(', ')}</span>
          </Badge>
        )}
      </div>
    )
  }
  return (
    <>
      {group(Math.min(1, marks.length), 'flex md:hidden')}
      {group(marksThatFit(marks.map((m) => m.label)), 'hidden md:flex')}
    </>
  )
}

function markBadge(m: Mark) {
  return m.tone === 'warning' ? (
    <Badge key={m.key} variant="outline" className="border-warning/50 text-warning">
      <span className="truncate">{m.label}</span>
    </Badge>
  ) : m.tone === 'success' ? (
    <Badge key={m.key} variant="outline" className="border-success/50 text-success">
      <span className="truncate">{m.label}</span>
    </Badge>
  ) : (
    <Badge key={m.key} variant={m.variant}>
      <span className="truncate">{m.label}</span>
    </Badge>
  )
}
