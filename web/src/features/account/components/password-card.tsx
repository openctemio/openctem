'use client'

import { useState } from 'react'
import { Key, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogForm,
  DialogBody,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { PasswordInput } from '@/components/password-input'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'

import { usePasswordPolicy } from '@/features/auth/api/use-auth-providers'
import { PasswordPolicyHint } from '@/features/auth/components/password-policy-hint'
import { passwordPolicyIssue } from '@/features/auth/lib/password-policy'

import { useChangePassword } from '../api/use-security'

const EMPTY = { current_password: '', new_password: '', confirm_password: '' }

interface PasswordCardProps {
  /** false for accounts that sign in through an identity provider */
  isLocalAccount: boolean
  /** Called after a change: the server signed out every other session. */
  onChanged?: () => void
}

export function PasswordCard({ isLocalAccount, onChanged }: PasswordCardProps) {
  const { t } = useTranslation()
  const { changePassword, isChanging } = useChangePassword()
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState(EMPTY)
  const [error, setError] = useState('')
  const passwordPolicy = usePasswordPolicy()

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    const issue = passwordPolicy && passwordPolicyIssue(form.new_password, passwordPolicy)
    if (issue) {
      setError(issue)
      return
    }
    if (form.new_password !== form.confirm_password) {
      setError(t('account.password.mismatch', 'Passwords do not match'))
      return
    }
    try {
      await changePassword(form)
      setOpen(false)
      setForm(EMPTY)
      toast.success(
        t('account.password.changed', 'Password changed. Your other sessions were signed out.')
      )
      onChanged?.()
    } catch (err) {
      setError(getErrorMessage(err, t('account.password.failed', 'Could not change the password')))
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Key className="h-5 w-5" />
          {t('account.password.title', 'Password')}
        </CardTitle>
        <CardDescription>
          {isLocalAccount
            ? t(
                'account.password.description',
                'Changing your password signs out every other session.'
              )
            : t(
                'account.password.federated',
                'You sign in through your organization’s identity provider. Change your password there.'
              )}
        </CardDescription>
      </CardHeader>
      {isLocalAccount && (
        <CardContent>
          <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
            {t('account.password.change', 'Change password')}
          </Button>
        </CardContent>
      )}

      <Dialog
        open={open}
        onOpenChange={(o) => {
          setOpen(o)
          if (!o) {
            setForm(EMPTY)
            setError('')
          }
        }}
      >
        <DialogContent>
          <DialogForm onSubmit={submit}>
            <DialogHeader>
              <DialogTitle>{t('account.password.change', 'Change password')}</DialogTitle>
              <DialogDescription>
                {t(
                  'account.password.dialogBody',
                  'Enter your current password and choose a new one. Your other sessions will be signed out.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="current-password">
                  {t('account.password.current', 'Current password')}
                </Label>
                <PasswordInput
                  id="current-password"
                  autoComplete="current-password"
                  value={form.current_password}
                  onChange={(e) => setForm({ ...form, current_password: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-password">{t('account.password.new', 'New password')}</Label>
                <PasswordInput
                  id="new-password"
                  autoComplete="new-password"
                  value={form.new_password}
                  onChange={(e) => setForm({ ...form, new_password: e.target.value })}
                />
                <PasswordPolicyHint />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirm-password">
                  {t('account.password.confirm', 'Confirm new password')}
                </Label>
                <PasswordInput
                  id="confirm-password"
                  autoComplete="new-password"
                  value={form.confirm_password}
                  onChange={(e) => setForm({ ...form, confirm_password: e.target.value })}
                />
              </div>
              {error && (
                <p role="alert" className="text-sm text-destructive">
                  {error}
                </p>
              )}
            </DialogBody>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button type="submit" disabled={isChanging || !form.current_password}>
                {isChanging && <Loader2 className="h-4 w-4 animate-spin" />}
                {t('account.password.change', 'Change password')}
              </Button>
            </DialogFooter>
          </DialogForm>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
