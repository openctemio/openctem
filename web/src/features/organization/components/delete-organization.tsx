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
 * RequireTeamOwner). The request schedules the deletion: the organization is
 * closed to everyone at once and deleted after the grace period (14 days),
 * with every row (assets, findings, scans, members, roles, settings and its
 * audit log); an owner can cancel from the sign-in page until then. User
 * accounts survive and keep their other organizations. Confirmation is by
 * typing the organization's name
 * (api/docs/architecture/organization-deletion.md).
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
    let due: string | undefined
    try {
      const res = await del<{ status: string; deletion_due_at?: string }>(
        `/api/v1/tenants/${currentTenant.slug}`
      )
      due = res?.deletion_due_at
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('org.danger.deleteFailed', 'Failed to delete the organization'))
      )
      setBusy(false)
      return
    }
    // The request succeeded. Anything that fails from here on is only the
    // move to another organization, so it must never be reported as a failed
    // request (the organization is already closed).
    toast.success(
      t('org.danger.scheduled', 'Organization "{name}" will be deleted on {date}.', {
        name: name ?? '',
        date: due ? new Date(due).toLocaleDateString() : '',
      }),
      {
        description: t(
          'org.danger.scheduledHint',
          'It is closed to everyone now. An owner can cancel the deletion from the sign-in page until then.'
        ),
      }
    )
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
          'Closes the organization for everyone now and deletes it with everything in it after 14 days: assets, findings, scans, members, roles, settings and its audit log. An owner can cancel until then. Member accounts are kept.'
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
          'The organization is closed for every member now and deleted with all of its data after 14 days: assets, findings, scans, members, roles, settings and its audit log. An owner can cancel the deletion from the sign-in page until then. Member accounts are kept.'
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
