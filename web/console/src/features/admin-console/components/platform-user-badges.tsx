'use client'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { PlatformUser } from '../types'

/**
 * Sign-in state of one account: blocked, locked, unverified, MFA, platform admin, erased.
 * `oneLine` keeps the marks on one line (a table row): what does not fit ends
 * at the cell edge, and the account page shows every mark.
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
  return (
    <div
      data-slot="platform-user-badges"
      className={cn('flex gap-1', oneLine ? 'min-w-0 overflow-hidden *:shrink-0' : 'flex-wrap')}
    >
      {plain && <Badge variant="outline">{t('admin.users.badge.active', 'Active')}</Badge>}
      {user.erased && <Badge variant="outline">{t('admin.users.badge.erased', 'Erased')}</Badge>}
      {user.is_platform_admin && (
        <Badge variant="secondary">{t('admin.users.badge.admin', 'Platform admin')}</Badge>
      )}
      {user.locked && (
        <Badge variant="destructive">{t('admin.users.badge.locked', 'Locked')}</Badge>
      )}
      {user.blocked && !user.erased && (
        <Badge variant="destructive">{t('admin.users.badge.blocked', 'Blocked')}</Badge>
      )}
      {user.status !== 'active' && !user.erased && !user.blocked && (
        <Badge variant="outline" className="capitalize">
          {user.status}
        </Badge>
      )}
      {!user.email_verified && (
        <Badge variant="outline" className="border-warning/50 text-warning">
          {t('admin.users.badge.unverified', 'Email not verified')}
        </Badge>
      )}
      {user.mfa_enabled && (
        <Badge variant="outline" className="border-success/50 text-success">
          {t('admin.users.badge.mfa', 'MFA')}
        </Badge>
      )}
    </div>
  )
}
