'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useState, type FormEvent } from 'react'
import { Loader2, UserPlus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogBody,
  DialogForm,
} from '@/components/ui/dialog'
import { DialogSubmitError } from '@/components/ui/dialog-submit-error'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { SetupLinkResult } from '@/features/shared/components/one-time-setup-link'
import { createOrganizationUser } from '../api/use-admin-organizations'
import { AdminApiError } from '@console/lib/admin-api/client'
import type { AdminCreatedOrganizationUser, AdminOwnerInvitation } from '../types'
import { OwnerInvitationSentNotice } from './owner-invitation'

/**
 * Create the FIRST owner of an organization that has none (RFC-022 rev. 5).
 * That is the only user the platform console may create in an organization:
 * once it has an owner, the owner and its administrators add people. The API
 * emails the set-password link when the organization can send email (and then
 * never returns it); only without email is a one-time link shown here, once.
 *
 * For an organization waiting for its first owner (created with an ownership
 * invitation), an email that already has an account gets the invitation
 * instead (docs/architecture/organization-ownership-invitations.md); with
 * `changeInvitee` the dialog is labelled for that.
 */
export function CreateFirstOwnerDialog({
  tenantId,
  onCreated,
  changeInvitee = false,
  emailDelivery,
}: {
  tenantId: string
  onCreated: () => void
  /** The organization has an ownership invitation: label the dialog "Change invitee". */
  changeInvitee?: boolean
  /** False: the installation cannot send email (nothing is sent; links are handed over). */
  emailDelivery?: boolean
}) {
  const noEmail = emailDelivery === false
  const { t } = useTranslation()

  const [open, setOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Held only in this component's state; dropped when the dialog closes.
  const [created, setCreated] = useState<AdminCreatedOrganizationUser | null>(null)
  const [invited, setInvited] = useState<AdminOwnerInvitation | null>(null)

  const close = () => {
    setOpen(false)
    setEmail('')
    setName('')
    setError(null)
    setCreated(null)
    setInvited(null)
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const res = await createOrganizationUser(tenantId, {
        email: email.trim(),
        name: name.trim(),
      })
      // An existing account is invited, never made the owner directly.
      if ('owner_invitation' in res && res.owner_invitation) setInvited(res.owner_invitation)
      else setCreated(res as AdminCreatedOrganizationUser)
      onCreated()
    } catch (err) {
      setError(err instanceof AdminApiError ? err.message : 'Could not create the owner')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? setOpen(true) : close())}>
      <DialogTrigger asChild>
        <Button size="sm" variant={changeInvitee ? 'outline' : 'default'}>
          <UserPlus className="me-2 size-4" />
          {changeInvitee
            ? t('admin.ownerInvitation.changeInvitee', 'Change invitee')
            : t('admin.createFirstOwnerDialog.createFirstOwner', 'Create first owner')}
        </Button>
      </DialogTrigger>
      <DialogContent size="sm">
        {invited ? (
          <>
            <DialogHeader>
              <DialogTitle>
                {noEmail
                  ? t('admin.ownerInvitation.createdTitle', 'Invitation created')
                  : t('admin.ownerInvitation.sentTitle', 'Invitation sent')}
              </DialogTitle>
            </DialogHeader>
            <DialogBody>
              <div className="py-2">
                <OwnerInvitationSentNotice
                  email={invited.invitee_email ?? email.trim()}
                  invitation={invited}
                  emailDelivery={emailDelivery}
                />
              </div>
            </DialogBody>
            <DialogFooter>
              <Button onClick={close}>{t('admin.createFirstOwnerDialog.done', 'Done')}</Button>
            </DialogFooter>
          </>
        ) : created ? (
          <>
            <DialogHeader>
              <DialogTitle>
                {t('admin.createFirstOwnerDialog.ownerCreated', 'Owner created')}
              </DialogTitle>
              <DialogDescription>
                {t(
                  'admin.createFirstOwnerDialog.ownsThisOrganization',
                  '{owner} owns this organization once they set a password. They add everyone else.',
                  { owner: created.user?.name || created.user?.email || '' }
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              <div className="py-2">
                <SetupLinkResult outcome={created} email={created.user?.email ?? email.trim()} />
              </div>
            </DialogBody>
            <DialogFooter>
              <Button onClick={close}>{t('admin.createFirstOwnerDialog.done', 'Done')}</Button>
            </DialogFooter>
          </>
        ) : (
          <DialogForm onSubmit={submit}>
            <DialogHeader>
              <DialogTitle>
                {changeInvitee
                  ? t('admin.ownerInvitation.changeInvitee', 'Change invitee')
                  : t('admin.createFirstOwnerDialog.createFirstOwner', 'Create first owner')}
              </DialogTitle>
              <DialogDescription>
                {changeInvitee && noEmail
                  ? t(
                      'admin.ownerInvitation.changeInviteeHelpNoEmail',
                      'The current invitation is canceled. This server cannot send email, so nobody is told: someone who already has an account gets a new invitation that they accept in the app after signing in (you give them the address); for a new person an account is created and you get a one-time link to give them.'
                    )
                  : changeInvitee
                    ? t(
                        'admin.ownerInvitation.changeInviteeHelp',
                        'The current invitation is canceled. Someone who already has an account gets a new invitation to become the owner; for a new person an account is created and they get a link to set their password.'
                      )
                    : t(
                        'admin.createFirstOwnerDialog.thisOrganizationHasNoOwner',
                        "This organization has no owner. Create the owner's account; they get a link to set their password, and then invite or create the organization's other users themselves."
                      )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="org-owner-name">
                    {t('admin.createFirstOwnerDialog.name', 'Name')}
                  </Label>
                  <Input
                    id="org-owner-name"
                    required
                    maxLength={255}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="org-owner-email">
                    {t('admin.createFirstOwnerDialog.email', 'Email')}
                  </Label>
                  <Input
                    id="org-owner-email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
              </div>
            </DialogBody>
            <DialogSubmitError message={error} />

            <DialogFooter>
              <Button type="button" variant="outline" onClick={close}>
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button type="submit" disabled={busy}>
                {busy && <Loader2 className="me-2 size-4 animate-spin" />}
                {changeInvitee
                  ? t('admin.ownerInvitation.invite', 'Invite')
                  : t('admin.createFirstOwnerDialog.createOwner', 'Create owner')}
              </Button>
            </DialogFooter>
          </DialogForm>
        )}
      </DialogContent>
    </Dialog>
  )
}
