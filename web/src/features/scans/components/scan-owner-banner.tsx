'use client'

/**
 * A scan without an active owner (api/docs/architecture/scan-ownership.md):
 * a scheduled run acts as the scan's owner, so a scan whose owner is missing
 * (the account was deleted) or left the organization is paused at its next
 * due run. The banner says why and, for owners and administrators, offers
 * "Take ownership". Taking ownership does not resume the scan. The API is
 * the authority (owners and administrators only, act scope checked,
 * audited); the button is hidden for everyone else.
 */

import { useState } from 'react'
import { UserX } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { post } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import type { ScanConfig } from '@/lib/api/scan-types'
import { usePermissions } from '@/lib/permissions'

export interface ScanOwnerBannerProps {
  config: Pick<ScanConfig, 'id' | 'name' | 'owner_state' | 'schedule_type' | 'status'>
  onChanged?: () => void
}

export function ScanOwnerBanner({ config, onChanged }: ScanOwnerBannerProps) {
  const { t } = useTranslation()
  const { isAdmin } = usePermissions()
  const [busy, setBusy] = useState(false)
  // Taking ownership makes its scheduled runs act as you: ask first.
  const [asking, setAsking] = useState(false)

  const state = config.owner_state
  if (state !== 'missing' && state !== 'inactive') return null

  const scheduled = config.schedule_type !== 'manual'
  const reason =
    state === 'missing'
      ? t(
          'scans.owner.missing',
          'This scan has no owner: the account that created it no longer exists.'
        )
      : t('scans.owner.inactive', "This scan's owner is no longer an active member.")
  const effect = scheduled
    ? t(
        'scans.owner.scheduledEffect',
        'Its scheduled runs act as the owner, so they are refused and the scan is paused until someone takes ownership.'
      )
    : t(
        'scans.owner.manualEffect',
        'Anyone who may run it can still start it by hand; a schedule needs an owner.'
      )

  const take = async () => {
    setBusy(true)
    try {
      await post(scanEndpoints.takeOwnership(config.id), {})
      toast.success(
        t('scans.owner.taken', 'You now own "{name}". Resume it to restart its schedule.', {
          name: config.name,
        })
      )
      onChanged?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('scans.owner.takeFailed', 'Could not take ownership')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Alert variant="destructive" data-testid="scan-owner-banner">
      <UserX className="h-4 w-4" aria-hidden="true" />
      <AlertTitle>{t('scans.owner.title', 'No active owner')}</AlertTitle>
      <AlertDescription>
        <p>
          {reason} {effect}
        </p>
        {isAdmin() ? (
          <Button size="sm" className="mt-2" onClick={() => setAsking(true)} disabled={busy}>
            {busy
              ? t('scans.owner.taking', 'Taking ownership…')
              : t('scans.owner.take', 'Take ownership')}
          </Button>
        ) : (
          <p className="mt-1">
            {t('scans.owner.askAdmin', 'An owner or administrator can take ownership.')}
          </p>
        )}
      </AlertDescription>
      <ConfirmDialog
        open={asking}
        onOpenChange={setAsking}
        title={t('confirm.scan.takeOwnershipTitle', undefined, { name: config.name })}
        desc={t('confirm.scan.takeOwnershipDesc')}
        confirmText={t('confirm.scan.takeOwnershipBtn')}
        handleConfirm={async () => {
          setAsking(false)
          await take()
        }}
      />
    </Alert>
  )
}
