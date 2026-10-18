'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useState, type FormEvent } from 'react'
import { Check, Copy, Loader2, Plus } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
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
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { copyToClipboard } from '@/lib/clipboard'
import { provisionAdministrator } from '../api/use-admin-users'
import { AdminApiError } from '@console/lib/admin-api/client'
import type { AdminRole } from '../types'

export const ADMIN_ROLE_OPTIONS: {
  value: AdminRole
  labelKey: string
  hintKey: string
}[] = [
  {
    value: 'super_admin',
    labelKey: 'admin.role.super_admin',
    hintKey: 'admin.createAdminDialog.superAdminHint',
  },
  {
    value: 'ops_admin',
    labelKey: 'admin.role.ops_admin',
    hintKey: 'admin.createAdminDialog.operationsAdminHint',
  },
  {
    value: 'readonly',
    labelKey: 'admin.role.readonly',
    hintKey: 'admin.createAdminDialog.readOnlyAdminHint',
  },
]

/**
 * Make someone a platform administrator. They sign in on the normal sign-in
 * page with their account; when the API had to create the account, its
 * temporary password is shown here once.
 */
export function CreateAdminDialog({ onCreated }: { onCreated: () => void }) {
  const { t } = useTranslation()

  const [open, setOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState<AdminRole>('readonly')
  const [breakGlass, setBreakGlass] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [created, setCreated] = useState<{ email: string; password?: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const close = () => {
    setOpen(false)
    setEmail('')
    setName('')
    setRole('readonly')
    setBreakGlass(false)
    setError(null)
    setCreated(null)
    setCopied(false)
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const res = await provisionAdministrator({
        email: email.trim(),
        name: name.trim(),
        // A break-glass account must be able to fix anything.
        role: breakGlass ? 'super_admin' : role,
        break_glass: breakGlass,
      })
      setCreated({ email: res.admin.email, password: res.temporary_password })
      onCreated()
    } catch (err) {
      setError(err instanceof AdminApiError ? err.message : 'Could not create the administrator')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? setOpen(true) : close())}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="me-2 size-4" />
          {t('admin.createAdminDialog.newAdministrator', 'New administrator')}
        </Button>
      </DialogTrigger>
      <DialogContent size="sm">
        {created ? (
          <>
            <DialogHeader>
              <DialogTitle>
                {t('admin.createAdminDialog.administratorAdded', 'Administrator added')}
              </DialogTitle>
              <DialogDescription>
                {created.password
                  ? t(
                      'admin.createAdminDialog.aSignInAccountWas',
                      'A sign-in account was created. Send these details to them securely; the password is shown only once. They sign in on the normal sign-in page, change the password, and set up two-step verification when they open the console.'
                    )
                  : t(
                      'admin.createAdminDialog.theirExistingAccountIsNow',
                      'Their existing account is now an administrator. They sign in on the normal sign-in page with their own password and set up two-step verification when they open the console.'
                    )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              <dl className="grid grid-cols-[auto_1fr] items-center gap-x-3 gap-y-2 py-4 text-sm">
                <dt className="text-muted-foreground">
                  {t('admin.createAdminDialog.email', 'Email')}
                </dt>
                <dd className="min-w-0 break-all">{created.email}</dd>
                {created.password && (
                  <>
                    <dt className="text-muted-foreground">
                      {t('admin.createAdminDialog.temporaryCredential', 'Temporary password')}
                    </dt>
                    <dd className="flex min-w-0 items-center gap-2">
                      <code className="min-w-0 flex-1 rounded bg-muted px-2 py-1.5 text-xs break-all select-all">
                        {created.password}
                      </code>
                      <Button
                        type="button"
                        size="icon"
                        variant="outline"
                        aria-label={t(
                          'admin.createAdminDialog.copyTemporaryCredential',
                          'Copy temporary password'
                        )}
                        onClick={async () => {
                          if (created.password && (await copyToClipboard(created.password))) {
                            setCopied(true)
                          }
                        }}
                      >
                        {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
                      </Button>
                    </dd>
                  </>
                )}
              </dl>
            </DialogBody>
            <DialogFooter>
              <Button onClick={close}>{t('admin.createAdminDialog.done', 'Done')}</Button>
            </DialogFooter>
          </>
        ) : (
          <DialogForm onSubmit={submit}>
            <DialogHeader>
              <DialogTitle>
                {t('admin.createAdminDialog.newAdministrator', 'New administrator')}
              </DialogTitle>
              <DialogDescription>
                {t(
                  'admin.createAdminDialog.anAdministratorSignsInOn',
                  'An administrator signs in on the normal sign-in page but belongs to no organization. Use an email that is not a member of any organization.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="adm-name">{t('admin.createAdminDialog.name', 'Name')}</Label>
                  <Input
                    id="adm-name"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="adm-email">{t('admin.createAdminDialog.email', 'Email')}</Label>
                  <Input
                    id="adm-email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('admin.createAdminDialog.role', 'Role')}</Label>
                  <Select
                    value={breakGlass ? 'super_admin' : role}
                    disabled={breakGlass}
                    onValueChange={(v) => setRole(v as AdminRole)}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {ADMIN_ROLE_OPTIONS.map((o) => (
                        <SelectItem key={o.value} value={o.value}>
                          {t(o.labelKey)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    {t(
                      ADMIN_ROLE_OPTIONS.find(
                        (o) => o.value === (breakGlass ? 'super_admin' : role)
                      )?.hintKey ?? ''
                    )}
                  </p>
                </div>
                <div className="flex items-start gap-3 rounded-md border p-3">
                  <Checkbox
                    id="adm-break-glass"
                    checked={breakGlass}
                    onCheckedChange={(v) => setBreakGlass(v === true)}
                  />
                  <div className="space-y-1">
                    <Label htmlFor="adm-break-glass">
                      {t(
                        'admin.createAdminDialog.breakGlassEmergencyAccessAccount',
                        'Break-glass (emergency access) account'
                      )}
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      {t(
                        'admin.createAdminDialog.aLocalSuperAdminFor',
                        'A local super admin for when the identity provider is down: never bound to it, allowed to use its password when the IdP is required, and every sign-in alerts all administrators. Keep its credentials offline and test it at least every 90 days.'
                      )}
                    </p>
                  </div>
                </div>
                {error && (
                  <Alert variant="destructive">
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}
              </div>
            </DialogBody>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={close}>
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button type="submit" disabled={busy}>
                {busy && <Loader2 className="me-2 size-4 animate-spin" />}
                {t('admin.createAdminDialog.createAdministrator', 'Create administrator')}
              </Button>
            </DialogFooter>
          </DialogForm>
        )}
      </DialogContent>
    </Dialog>
  )
}
