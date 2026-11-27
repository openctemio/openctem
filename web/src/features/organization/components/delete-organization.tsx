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
import { navigateAfterSessionChange } from '@/lib/session-navigation'
import { useTranslation } from '@/context/i18n-provider'
import { formatDate } from '@/lib/app-locale'
import { useMemberStats } from '@/features/organization/api/use-members'
import { useDashboardStats } from '@/features/dashboard/hooks/use-dashboard-stats'

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
 * (server/docs/architecture/organization-deletion.md).
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
    // Said on the page that loads next (a toast here would go with this page).
    const scheduled = {
      kind: 'success' as const,
      title: t('org.danger.scheduled', 'Organization "{name}" will be deleted on {date}.', {
        name: name ?? '',
        date: due ? formatDate(new Date(due)) : '',
      }),
      description: t(
        'org.danger.scheduledHint',
        'It is closed to everyone now. An owner can cancel the deletion from the sign-in page until then.'
      ),
    }
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
      target = '/account/organizations'
    }
    navigateAfterSessionChange(target, { replace: true, flash: scheduled })
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
            variant="ghost"
            onClick={() => {
              loadTenants()
              setOpen(true)
            }}
          >
            <Trash2 className="text-destructive" aria-hidden />
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
          'confirm.org.deleteUndo',
          'An owner can cancel the deletion from the sign-in page for 14 days.'
        )}
        typeToConfirm={name}
        confirmText={
          busy ? t('confirm.deleting', 'Deleting…') : t('confirm.org.delete', 'Delete organization')
        }
        isLoading={busy}
        handleConfirm={handleDelete}
      >
        {open && <DeleteImpact tenantId={currentTenant.id} slug={currentTenant.slug} />}
      </ConfirmDialog>
    </>
  )
}

/**
 * Who and what the deletion affects, from counts the server already returns
 * (member stats, the dashboard summary); a count it does not return (or the
 * caller may not read) is left out of the sentence, never guessed. Read only
 * while the dialog is open.
 */
function DeleteImpact({ tenantId, slug }: { tenantId: string; slug: string }) {
  const { t } = useTranslation()
  const { stats: members } = useMemberStats(slug)
  const { stats: dash, isLoading, error } = useDashboardStats(tenantId)
  const known = !isLoading && !error
  const people = members?.active_members
  const assets = known ? dash?.assets?.total : undefined
  const findings = known ? dash?.findings?.total : undefined
  return (
    <div
      className="space-y-1.5 rounded-md border bg-muted/40 p-3 text-sm"
      data-testid="delete-impact"
    >
      <p className="font-medium">{t('confirm.org.impactTitle', 'Who and what is affected')}</p>
      <p>
        {typeof people === 'number'
          ? t(
              'confirm.org.impactNowCount',
              'Now: {count, plural, one {# member loses} other {# members lose}} access, sensors stop getting jobs, integrations stop syncing and API keys stop working.',
              { count: people }
            )
          : t(
              'confirm.org.impactNow',
              'Now: every member loses access, sensors stop getting jobs, integrations stop syncing and API keys stop working.'
            )}
      </p>
      <p>
        {typeof assets === 'number' && typeof findings === 'number'
          ? t(
              'confirm.org.impactLaterCount',
              'After 14 days: {assets} assets, {findings} findings, every scan, role and setting and the audit log are deleted. Member accounts are kept.',
              { assets, findings }
            )
          : t(
              'confirm.org.impactLater',
              'After 14 days: every asset, finding, scan, role and setting and the audit log are deleted. Member accounts are kept.'
            )}
      </p>
    </div>
  )
}
