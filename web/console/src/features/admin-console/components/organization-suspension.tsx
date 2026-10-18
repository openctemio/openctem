'use client'

import { useState } from 'react'
import { Ban, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { setOrganizationSuspended } from '../api/use-admin-organizations'
import { AdminConfirmDialog } from './admin-confirm-dialog'
import type { AdminOrganization } from '../types'

/** "Suspended" next to an organization's name (list and detail). */
export function OrganizationStatusBadge({ org }: { org: Pick<AdminOrganization, 'status'> }) {
  const { t } = useTranslation()
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

/** What the administrator sees on a suspended organization: when and why. */
export function OrganizationSuspendedNotice({ org }: { org: AdminOrganization }) {
  const { t } = useTranslation()
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
