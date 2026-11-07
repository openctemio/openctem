'use client'

import { ShieldAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useAdminOrNull } from './admin-console-shell'
import { useRequestElevation } from './elevation-request'
import { adminCan, adminCanElevate, adminMayHave, type AdminRole } from '../types'

interface RoleRequiredNoticeProps {
  /** The acting role the page or action needs (an identity without permissions). */
  needed?: AdminRole
  /** The platform permission the page or action needs (RFC-134); wins over `needed`. */
  permission?: string
  /** `page`: replaces a whole page body; `inline`: one line under a form. */
  variant?: 'page' | 'inline'
}

/**
 * What a console page shows when the session does not act with what it
 * needs (a permission, or for an identity without permissions a tier). An administrator whose own role is high enough (a super admin acting
 * read-only until they elevate) is offered the elevation right here, instead
 * of a dead end that names a role they already hold. Anyone else is told
 * which role it takes. The API enforces the role either way.
 */
export function RoleRequiredNotice({
  needed = 'super_admin',
  permission,
  variant = 'inline',
}: RoleRequiredNoticeProps) {
  const admin = useAdminOrNull()
  const { t } = useTranslation()
  const requestElevation = useRequestElevation()
  const reachable =
    !!admin &&
    (permission ? adminMayHave(admin, permission) : adminCan(admin.max_role ?? admin.role, needed))
  const canElevate = reachable && adminCanElevate(admin) && !!requestElevation

  // No role is named: the elevation dialog lists the roles the
  // administrator holds, and the legacy tier names are not roles any more
  // (RFC-134).
  const message = canElevate
    ? t('admin.roleNotice.elevate', 'You are acting as read-only. Elevate to use this.')
    : t(
        'admin.roleNotice.needed',
        'Your platform roles do not include this. A platform owner can grant it under Roles.'
      )
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
            : t('admin.roleNotice.neededTitle', 'Not included in your roles')
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
