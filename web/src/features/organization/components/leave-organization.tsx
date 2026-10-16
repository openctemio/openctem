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

/**
 * Organization › General › Danger zone: leave this organization (api
 * RFC-104). Any member, for themselves only. The API refuses the only owner
 * and someone who still owns work an administrator must reassign; its
 * message is shown.
 */
export function LeaveOrganization() {
  const { t } = useTranslation()
  const { currentTenant, tenants, switchTeam, loadTenants } = useTenant()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

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
      <DangerZone>
        <DangerZoneItem
          title={t('org.leave.title')}
          description={t('org.leave.desc')}
          action={
            <Button
              variant="outline"
              size="sm"
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
