'use client'

import { useState } from 'react'
import { Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { DangerZone, DangerZoneItem } from '@/features/shared'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions } from '@/lib/permissions'
import { del } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { removeCookie } from '@/lib/cookies'
import { env } from '@/lib/env'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Organization › General › Danger zone: delete the organization.
 *
 * Owner only, like the API (DELETE /api/v1/tenants/{tenant} behind
 * RequireTeamOwner). The delete cascades every row of the organization
 * (assets, findings, scans, members, roles, settings and its audit log);
 * user accounts survive and keep their other organizations. Confirmation is
 * by typing the organization's name.
 *
 * Afterwards the session moves to another organization the user belongs to,
 * or to onboarding when there is none.
 */
export function DeleteOrganization() {
  const { currentTenant } = useTenant()
  const { isOwner } = usePermissions()
  if (!currentTenant || !isOwner()) return null
  return (
    <DangerZone>
      <DeleteOrganizationItem />
    </DangerZone>
  )
}

/** The delete row of a danger zone (owner only; nothing for anyone else). */
export function DeleteOrganizationItem() {
  const { t } = useTranslation()
  const { currentTenant, tenants, switchTeam, loadTenants } = useTenant()
  const { isOwner } = usePermissions()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  if (!currentTenant || !isOwner()) return null
  const name = currentTenant.name

  const handleDelete = async () => {
    setBusy(true)
    try {
      await del(`/api/v1/tenants/${currentTenant.slug}`)
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('org.danger.deleteFailed', 'Could not delete the organization'))
      )
      setBusy(false)
      return
    }
    // The delete succeeded. Anything that fails from here on is only the move
    // to another organization, so it must never be reported as a failed
    // delete (the organization is already gone).
    toast.success(t('org.danger.deleted', 'Organization "{name}" deleted', { name: name ?? '' }))
    // A full reload (not router.push) so no cached data of the deleted
    // organization survives; replace() so Back does not return here.
    const next = tenants.find((t) => t.id !== currentTenant.id)
    let target = '/'
    if (next) {
      try {
        await switchTeam(next.id)
      } catch {
        // Fall back to the root; the app picks an organization on load.
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
      <DangerZoneItem
        title={t('org.danger.deleteTitle', 'Delete this organization')}
        description={t(
          'org.danger.deleteDesc',
          'Permanently deletes the organization and everything in it: assets, findings, scans, members, roles, settings and its audit log. Member accounts are kept. This cannot be undone.'
        )}
        action={
          <Button
            variant="destructive"
            size="sm"
            onClick={() => {
              loadTenants()
              setOpen(true)
            }}
          >
            <Trash2 className="h-4 w-4" aria-hidden />
            {t('org.danger.deleteAction', 'Delete organization')}
          </Button>
        }
      />
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        destructive
        title={t('confirm.org.deleteTitle', 'Delete the organization {name}?', {
          name: name ?? '',
        })}
        desc={t(
          'confirm.org.deleteDesc',
          'The organization and all of its data are deleted for every member: assets, findings, scans, members, roles, settings and its audit log. Member accounts are kept. This cannot be undone.'
        )}
        typeToConfirm={name}
        confirmText={
          busy ? t('confirm.deleting', 'Deleting…') : t('confirm.org.delete', 'Delete organization')
        }
        isLoading={busy}
        handleConfirm={handleDelete}
      />
    </>
  )
}
