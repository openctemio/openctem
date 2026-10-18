'use client'

import { useState } from 'react'
import { Ban, ShieldCheck, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { purgeOrganization, setOrganizationSuspended } from '../api/use-admin-organizations'
import { AdminConfirmDialog } from './admin-confirm-dialog'
import type { AdminOrganization } from '../types'

/** "Suspended" or "Deletion scheduled" next to an organization's name. */
export function OrganizationStatusBadge({ org }: { org: Pick<AdminOrganization, 'status'> }) {
  const { t } = useTranslation()
  if (org.status === 'pending_deletion')
    return (
      <Badge variant="destructive" data-testid="org-pending-deletion">
        {t('admin.org.deletion.badge', 'Deletion scheduled')}
      </Badge>
    )
  if (org.status !== 'suspended') return null
  return (
    <Badge variant="destructive" data-testid="org-suspended">
      {t('admin.org.suspension.badge', 'Suspended')}
    </Badge>
  )
}

/** The suspend / lift button (ops admin and up). */
export function OrganizationSuspensionAction({
  org,
  onDone,
}: {
  org: AdminOrganization
  onDone: () => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const suspended = org.status === 'suspended'
  // An organization waiting for its deletion is already closed; its owners
  // cancel, the console can only delete it now.
  if (org.status === 'pending_deletion') return null
  const label = suspended
    ? t('admin.org.suspension.lift', 'Lift suspension')
    : t('admin.org.suspension.suspend', 'Suspend organization')

  return (
    <>
      <Button
        size="sm"
        variant={suspended ? 'outline' : 'destructive'}
        onClick={() => setOpen(true)}
        data-testid={suspended ? 'org-unsuspend' : 'org-suspend'}
      >
        {suspended ? <ShieldCheck className="me-2 size-4" /> : <Ban className="me-2 size-4" />}
        {label}
      </Button>
      {open && (
        <AdminConfirmDialog
          open
          onOpenChange={setOpen}
          title={label}
          destructive={!suspended}
          confirmLabel={label}
          description={
            <p>
              {suspended
                ? t(
                    'admin.org.suspension.liftWhat',
                    'Every credential of {name} works again as before: sign-in, API keys, MCP tokens, sensors, SCIM, CI and webhooks. Schedules that came due run on their next tick.',
                    { name: org.name }
                  )
                : t(
                    'admin.org.suspension.suspendWhat',
                    'From the next request on, {name} is closed to every credential: sign-in, API keys, MCP tokens, sensors, SCIM, CI and webhooks. Its scheduled work stops. Nothing is deleted. Members see "This organization is suspended — contact support"; your reason stays in the admin audit log.',
                    { name: org.name }
                  )}
            </p>
          }
          onConfirm={async ({ reason }) => {
            await setOrganizationSuspended(org.id, !suspended, reason)
            toast.success(
              suspended
                ? t('admin.org.suspension.liftDone', 'Suspension lifted.')
                : t('admin.org.suspension.suspendDone', 'Organization suspended.')
            )
            onDone()
          }}
        />
      )}
    </>
  )
}

/** Delete the organization now (super admin; fresh code and reason). */
export function OrganizationPurgeAction({
  org,
  onDone,
}: {
  org: AdminOrganization
  onDone: () => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const label = t('admin.org.deletion.purge', 'Delete now')
  return (
    <>
      <Button size="sm" variant="destructive" onClick={() => setOpen(true)} data-testid="org-purge">
        <Trash2 className="me-2 size-4" />
        {label}
      </Button>
      {open && (
        <AdminConfirmDialog
          open
          onOpenChange={setOpen}
          title={t('admin.org.deletion.purgeTitle', 'Delete {name} now?', { name: org.name })}
          destructive
          requireCode
          confirmLabel={label}
          description={
            <p>
              {t(
                'admin.org.deletion.purgeWhat',
                'Deletes {name} and everything in it at once: assets, findings, scans, members, roles, settings and its audit log. Member accounts are kept. This cannot be undone.',
                { name: org.name }
              )}
            </p>
          }
          onConfirm={async ({ reason, totp_code }) => {
            await purgeOrganization(org.id, reason, totp_code)
            toast.success(t('admin.org.deletion.purgeDone', 'Organization deleted.'))
            onDone()
          }}
        />
      )}
    </>
  )
}

/** What the administrator sees on a suspended organization: when and why. */
export function OrganizationSuspendedNotice({ org }: { org: AdminOrganization }) {
  const { t } = useTranslation()
  if (org.status === 'pending_deletion')
    return (
      <Alert variant="destructive" className="mt-4" data-testid="org-pending-deletion-notice">
        <Trash2 className="size-4" />
        <AlertTitle>
          {t('admin.org.deletion.noticeTitle', 'An owner scheduled this organization for deletion')}
        </AlertTitle>
        <AlertDescription>
          <p>
            {t(
              'admin.org.deletion.noticeBody',
              'It is closed to every credential and is deleted when the grace period ends, unless an owner cancels from the sign-in page.'
            )}
          </p>
          {org.deletion_due_at && (
            <p className="mt-1 text-xs">
              {t('admin.org.deletion.due', 'Deleted on {date}', {
                date: new Date(org.deletion_due_at).toLocaleString(),
              })}
            </p>
          )}
        </AlertDescription>
      </Alert>
    )
  if (org.status !== 'suspended') return null
  return (
    <Alert variant="destructive" className="mt-4" data-testid="org-suspended-notice">
      <Ban className="size-4" />
      <AlertTitle>
        {t('admin.org.suspension.noticeTitle', 'This organization is suspended')}
      </AlertTitle>
      <AlertDescription>
        <p>
          {t(
            'admin.org.suspension.noticeBody',
            'Every credential is refused and scheduled work is skipped until the suspension is lifted.'
          )}
        </p>
        {org.suspended_reason && (
          <p className="mt-1">
            {t('admin.org.suspension.reason', 'Reason: {reason}', { reason: org.suspended_reason })}
          </p>
        )}
        {org.suspended_at && (
          <p className="mt-1 text-xs">
            {t('admin.org.suspension.since', 'Suspended')} <RelativeTime date={org.suspended_at} />
          </p>
        )}
      </AlertDescription>
    </Alert>
  )
}
