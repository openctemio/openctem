'use client'

import { ShieldAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useAdminOrNull } from './admin-console-shell'
import { useRequestElevation } from './elevation-request'
import { ADMIN_ROLE_LABELS, adminCan, type AdminRole } from '../types'

interface RoleRequiredNoticeProps {
  /** The acting role the page or action needs. */
  needed: AdminRole
  /** `page`: replaces a whole page body; `inline`: one line under a form. */
  variant?: 'page' | 'inline'
}

/**
 * What a console page shows when the session's acting role is below what it
 * needs. An administrator whose own role is high enough (a super admin acting
 * read-only until they elevate) is offered the elevation right here, instead
 * of a dead end that names a role they already hold. Anyone else is told
 * which role it takes. The API enforces the role either way.
 */
export function RoleRequiredNotice({ needed, variant = 'inline' }: RoleRequiredNoticeProps) {
  const admin = useAdminOrNull()
  const { t } = useTranslation()
  const requestElevation = useRequestElevation()
  const roleName = t(`admin.role.${needed}`, ADMIN_ROLE_LABELS[needed])
  const canElevate = !!admin && adminCan(admin.max_role ?? admin.role, needed) && !!requestElevation

  const message = canElevate
    ? t('admin.roleNotice.elevate', 'You are acting as read-only. Elevate to {role} to use this.', {
        role: roleName,
      })
    : t('admin.roleNotice.needed', 'This needs the {role} role.', { role: roleName })
  const action = canElevate ? (
    <Button size="sm" onClick={() => requestElevation?.()}>
      {t('admin.elevation.elevate', 'Elevate')}
    </Button>
  ) : undefined

  if (variant === 'page') {
    return (
      <EmptyState
        className="mt-5"
        icon={ShieldAlert}
        title={
          canElevate
            ? t('admin.roleNotice.elevateTitle', 'Elevate to see this page')
            : t('admin.roleNotice.neededTitle', '{role} only', { role: roleName })
        }
        description={message}
        action={action}
      />
    )
  }
  return (
    <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
      <span>{message}</span>
      {action}
    </div>
  )
}
