'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { AlertCircle, AlertTriangle, Check, Crown, Loader2, X } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'

import { startOwnershipTransfer, type PreviousOwnerRole } from '../api/use-ownership-transfer'
import { becomesInternal, transferBlocker, transferErrorKey } from '../lib/ownership-transfer'
import type { MemberWithUser } from '../types/member.types'

/**
 * The owner asks a member to take the organization (api RFC-095 §3.1). The
 * owner re-authenticates on submit (the API asks for step-up); nothing
 * changes until the member accepts.
 */
export function TransferOwnershipDialog({
  member,
  onOpenChange,
  onStarted,
}: {
  member: MemberWithUser | null
  onOpenChange: (open: boolean) => void
  onStarted?: () => void
}) {
  const { t } = useTranslation()
  const [previousRole, setPreviousRole] = useState<PreviousOwnerRole>('admin')
  const [confirmInternal, setConfirmInternal] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!member) return
    setPreviousRole('admin')
    setConfirmInternal(false)
    setError(null)
  }, [member])

  if (!member) {
    return <Dialog open={false} onOpenChange={onOpenChange} />
  }

  const name = member.name || member.email
  const blocker = transferBlocker(member)
  const outsider = becomesInternal(member)
  const canSubmit = !blocker && (!outsider || confirmInternal) && !busy

  const checks = [
    {
      ok: member.status === 'active',
      label: t('org.ownership.check.active', 'An active member'),
    },
    {
      ok: member.mfa_status === 'enabled',
      label: t('org.ownership.check.mfa', 'Two-factor authentication is on'),
    },
    {
      ok: !(member.kind === 'external' && member.home_organization),
      label: t('org.ownership.check.unmanaged', 'Not managed by another organization'),
    },
  ]

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!canSubmit) return
    setBusy(true)
    setError(null)
    try {
      await startOwnershipTransfer({
        member_id: member.id,
        previous_owner_role: previousRole,
        confirm_internal: outsider ? confirmInternal : undefined,
      })
      toast.success(t('org.ownership.toast.started', 'Asked {name} to become the owner', { name }))
      onStarted?.()
      onOpenChange(false)
    } catch (err) {
      const known = transferErrorKey(err)
      setError(
        known
          ? t(known.key, known.fallback)
          : getErrorMessage(err, t('org.ownership.error.generic', 'Could not start the transfer'))
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Crown className="h-5 w-5 text-amber-500" aria-hidden />
              {t('org.ownership.dialog.title', 'Transfer ownership')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'org.ownership.dialog.description',
                'Ask {name} to become the owner of this organization. Nothing changes until they accept, within 72 hours, after signing in again.',
                { name }
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-5 py-2">
              <section aria-labelledby="ownership-requirements" className="space-y-2">
                <h3 id="ownership-requirements" className="text-sm font-medium">
                  {t('org.ownership.check.title', 'The new owner must be')}
                </h3>
                <ul className="space-y-1.5">
                  {checks.map((c) => (
                    <li key={c.label} className="flex items-center gap-2 text-sm">
                      {c.ok ? (
                        <Check
                          className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400"
                          aria-hidden
                        />
                      ) : (
                        <X className="h-4 w-4 shrink-0 text-destructive" aria-hidden />
                      )}
                      <span className={c.ok ? undefined : 'text-destructive'}>{c.label}</span>
                      <span className="sr-only">
                        {c.ok
                          ? t('org.ownership.check.met', 'met')
                          : t('org.ownership.check.notMet', 'not met')}
                      </span>
                    </li>
                  ))}
                </ul>
                {blocker && (
                  <p className="text-sm text-destructive" role="status">
                    {t(blocker.key, blocker.fallback)}
                  </p>
                )}
              </section>

              <div className="space-y-2">
                <Label htmlFor="ownership-previous-role">
                  {t('org.ownership.previousRole.label', 'After the transfer, you become')}
                </Label>
                <Select
                  value={previousRole}
                  onValueChange={(v) => setPreviousRole(v as PreviousOwnerRole)}
                  disabled={busy || !!blocker}
                >
                  <SelectTrigger id="ownership-previous-role" className="w-full sm:w-64">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="admin">{t('org.role.admin', 'Administrator')}</SelectItem>
                    <SelectItem value="member">{t('org.role.member', 'Member')}</SelectItem>
                    <SelectItem value="viewer">{t('org.role.viewer', 'Viewer')}</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {t(
                    'org.ownership.previousRole.hint',
                    'Your custom roles and teams stay. Only the owner can delete the organization, make administrators and change security settings.'
                  )}
                </p>
              </div>

              {outsider && !blocker && (
                <div className="space-y-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
                  <p className="flex items-start gap-2 text-sm">
                    <AlertTriangle
                      className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400"
                      aria-hidden
                    />
                    {t(
                      'org.ownership.outsider.notice',
                      '{name} is outside the organization and no organization manages their address. When they accept, they become an internal member and their end of access is removed.',
                      { name }
                    )}
                  </p>
                  <div className="flex items-start gap-2">
                    <Checkbox
                      id="ownership-confirm-internal"
                      checked={confirmInternal}
                      onCheckedChange={(v) => setConfirmInternal(v === true)}
                      disabled={busy}
                    />
                    <Label htmlFor="ownership-confirm-internal" className="text-sm font-normal">
                      {t(
                        'org.ownership.outsider.confirm',
                        'I confirm that {name} becomes an internal member',
                        { name }
                      )}
                    </Label>
                  </div>
                </div>
              )}

              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
            </div>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={!canSubmit}>
              {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              {t('org.ownership.dialog.submit', 'Ask to transfer')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
