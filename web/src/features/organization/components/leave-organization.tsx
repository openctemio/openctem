'use client'

import { useState } from 'react'
import { LogOut } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { DangerZone, DangerZoneItem } from '@/features/shared'
import { post } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { removeCookie } from '@/lib/cookies'
import { env } from '@/lib/env'
import { usePermissions } from '@/lib/permissions'
import { useMemberStats } from '../api/use-members'

/**
 * My account › Profile › Organization membership: leave this organization
 * (api RFC-104). Any member, for themselves only, so it lives on the account
 * page that every member can open. The only owner sees the button disabled
 * with the reason; the API still refuses them, and someone who owns work an
 * administrator must reassign, and shows its message.
 */
export function LeaveOrganization() {
  const { t } = useTranslation()
  const { currentTenant, tenants, switchTeam, loadTenants } = useTenant()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const { isOwner } = usePermissions()
  // Only an owner can be the sole owner, and an owner may read the member
  // statistics, so the count is known exactly when it matters.
  const { stats } = useMemberStats(currentTenant?.slug)
  const soleOwner = isOwner() && stats?.role_counts?.owner === 1

  if (!currentTenant) return null
  const name = currentTenant.name

  const handleLeave = async () => {
    setBusy(true)
    try {
      await post('/api/v1/organization/leave', {})
    } catch (error) {
      toast.error(getErrorMessage(error, t('org.leave.failed')))
      setBusy(false)
      setOpen(false)
      return
    }
    toast.success(t('org.leave.done', undefined, { name: name ?? '' }))
    const next = tenants.find((x) => x.id !== currentTenant.id)
    let target = '/'
    if (next) {
      try {
        await switchTeam(next.id)
      } catch {
        removeCookie(env.cookies.tenant)
      }
    } else {
      removeCookie(env.cookies.tenant)
      target = '/onboarding/create-team'
    }
    window.location.replace(target)
  }

  return (
    <>
      <DangerZone title={t('org.leave.section')}>
        <DangerZoneItem
          title={t('org.leave.title')}
          description={soleOwner ? t('org.leave.soleOwner') : t('org.leave.desc')}
          action={
            <Button
              variant="outline"
              size="sm"
              disabled={soleOwner}
              onClick={() => {
                loadTenants()
                setOpen(true)
              }}
            >
              <LogOut className="h-4 w-4" />
              {t('org.leave.button')}
            </Button>
          }
        />
      </DangerZone>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        destructive
        title={t('org.leave.confirmTitle', undefined, { name: name ?? '' })}
        desc={t('org.leave.confirmDesc')}
        confirmText={t('org.leave.button')}
        isLoading={busy}
        handleConfirm={handleLeave}
      />
    </>
  )
}
