'use client'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import type { PlatformUser } from '../types'

/** Sign-in state of one account: locked, unverified, MFA, platform admin, erased. */
export function PlatformUserBadges({ user }: { user: PlatformUser }) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-wrap gap-1">
      {user.erased && <Badge variant="outline">{t('admin.users.badge.erased', 'Erased')}</Badge>}
      {user.is_platform_admin && (
        <Badge variant="secondary">{t('admin.users.badge.admin', 'Platform admin')}</Badge>
      )}
      {user.locked && (
        <Badge variant="destructive">{t('admin.users.badge.locked', 'Locked')}</Badge>
      )}
      {user.status !== 'active' && !user.erased && (
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
