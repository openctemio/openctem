'use client'

import { useId, useState } from 'react'
import { LifeBuoy } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { recoverOrganizationOwner } from '../api/use-admin-organizations'
import { AdminConfirmDialog } from './admin-confirm-dialog'

/**
 * Owner recovery (RFC-022 revision 7): a new owner for an organization whose
 * owners are all suspended. Super admins only. The API demands a reason and a
 * fresh authenticator code, emails the set-password link and never returns
 * it, and writes the action to both audit logs.
 */
export function OwnerRecoveryDialog({
  tenantId,
  orgName,
  onRecovered,
}: {
  tenantId: string
  orgName: string
  onRecovered: () => void
}) {
  const { t } = useTranslation()
  const emailId = useId()
  const nameId = useId()
  const [open, setOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())

  return (
    <>
      <Button size="sm" variant="outline" onClick={() => setOpen(true)}>
        <LifeBuoy className="me-2 size-4" />
        {t('admin.org.recovery.open', 'Recover ownership')}
      </Button>
      <AdminConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next)
          if (!next) {
            setEmail('')
            setName('')
          }
        }}
        title={t('admin.org.recovery.title', 'Recover ownership of {name}', { name: orgName })}
        description={
          <>
            <p>
              {t(
                'admin.org.recovery.what',
                'Every owner of this organization is suspended, so nobody can manage it. This creates a new owner account; the suspended owners stay as they are for the new owner to decide.'
              )}
            </p>
            <p>
              {t(
                'admin.org.recovery.safe',
                'The set-password link goes to the new owner by email only; you never see it. The organization and every other administrator see this in their audit logs.'
              )}
            </p>
          </>
        }
        confirmLabel={t('admin.org.recovery.confirm', 'Create the new owner')}
        requireCode
        canSubmit={emailOk}
        onConfirm={async (proof) => {
          const res = await recoverOrganizationOwner(tenantId, {
            email: email.trim(),
            name: name.trim(),
            ...proof,
          })
          toast.success(
            res.email_failed
              ? t(
                  'admin.org.recovery.emailFailed',
                  'Owner created, but the email failed. They can use "Forgot password" with {email}.',
                  { email: res.user.email }
                )
              : t(
                  'admin.org.recovery.done',
                  'Owner created. The set-password link was emailed to {email}.',
                  {
                    email: res.user.email,
                  }
                )
          )
          onRecovered()
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor={emailId}>{t('admin.org.recovery.email', 'New owner email')}</Label>
            <Input
              id={emailId}
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="off"
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor={nameId}>{t('admin.org.recovery.name', 'Name (optional)')}</Label>
            <Input id={nameId} value={name} onChange={(e) => setName(e.target.value)} />
          </div>
        </div>
      </AdminConfirmDialog>
    </>
  )
}
