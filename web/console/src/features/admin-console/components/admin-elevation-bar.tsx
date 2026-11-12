'use client'

import { useEffect, useId, useState, type FormEvent } from 'react'
import { ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
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
import { DialogSubmitError } from '@/components/ui/dialog-submit-error'
import { Label } from '@/components/ui/label'
import { TonePill } from '@/features/shared/components/tone-pill'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { adminElevate, adminEndElevation } from '../api/use-admin-session'
import { useConsoleFactors } from '../api/use-console-factors'
import { actingRoleLabel, adminCanElevate, elevationChoices, type AdminIdentity } from '../types'
import { REASON_MAX, REASON_MIN, stepUpErrorMessage } from './admin-confirm-dialog'
import { StepUpCodeField, useReasonAndCode } from './step-up-code-hint'

const DURATIONS = [15, 30, 60] as const

/**
 * Time-boxed elevation: an administrator acts as read-only until they elevate
 * the console session to a role no higher than their own, for 15 to 60
 * minutes, with a reason and a fresh code. A compact control in the header
 * row says which role and until when, and ends it on request. Hidden for a
 * read-only administrator, and when the installation does not require
 * elevation (role already the own one).
 */
export function AdminElevationBar({
  admin,
  onChanged,
  open: openProp,
  onOpenChange,
}: {
  admin: AdminIdentity
  onChanged: () => void
  /**
   * The elevate dialog, when the shell owns it (so a page's read-only notice
   * can open it too); uncontrolled otherwise.
   */
  open?: boolean
  onOpenChange?: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const [ownOpen, setOwnOpen] = useState(false)
  const open = openProp ?? ownOpen
  const setOpen = onOpenChange ?? setOwnOpen
  const [busy, setBusy] = useState(false)
  const elevated = !!admin.elevated_until
  const canElevate = adminCanElevate(admin)

  // Refresh the identity when the elevation runs out.
  useEffect(() => {
    if (!admin.elevated_until) return
    const ms = new Date(admin.elevated_until).getTime() - Date.now()
    const timer = setTimeout(onChanged, Math.max(ms, 0) + 1000)
    return () => clearTimeout(timer)
  }, [admin.elevated_until, onChanged])

  if (!elevated && !canElevate) return null

  const end = async () => {
    setBusy(true)
    try {
      await adminEndElevation()
      onChanged()
    } catch {
      toast.error(t('admin.elevation.endFailed', 'The elevation could not be ended. Try again.'))
    } finally {
      setBusy(false)
    }
  }

  const acting = actingRoleLabel(admin)
  const until = admin.elevated_until
    ? new Date(admin.elevated_until).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : ''
  const activeText = t('admin.elevation.active', 'Acting as {role} until {until}.', {
    role: t(acting.key, acting.fallback),
    until,
  })

  return (
    <div className="flex items-center gap-2" data-testid="elevation-control">
      {elevated ? (
        <>
          {/* Full sentence for screen readers; the chip shows the short form. */}
          <span className="sr-only" role="status">
            {activeText}
          </span>
          <TonePill
            tone="warning"
            title={activeText}
            className="hidden sm:inline-flex"
            label={t('admin.elevation.chip', '{role} until {until}', {
              role: t(acting.key, acting.fallback),
              until,
            })}
          />
          <TonePill
            tone="warning"
            title={activeText}
            className="sm:hidden"
            label={t('admin.elevation.chipShort', 'Until {until}', { until })}
          />
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void end()}>
            {t('admin.elevation.end', 'End now')}
          </Button>
        </>
      ) : (
        <>
          <TonePill
            tone="muted"
            className="hidden sm:inline-flex"
            title={t(
              'admin.elevation.readonly',
              'You are acting as read-only. Elevate for a while to change anything.'
            )}
            label={t('admin.elevation.readonlyChip', 'Read-only')}
          />
          <Button size="sm" onClick={() => setOpen(true)}>
            <ShieldCheck className="size-4" aria-hidden />
            {t('admin.elevation.elevate', 'Elevate')}
          </Button>
        </>
      )}
      <ElevateDialog
        open={open}
        onOpenChange={setOpen}
        choices={elevationChoices(admin)}
        onElevated={() => {
          setOpen(false)
          onChanged()
        }}
      />
    </div>
  )
}

function ElevateDialog({
  open,
  onOpenChange,
  choices,
  onElevated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  choices: string[]
  onElevated: () => void
}) {
  const { t } = useTranslation()
  const reasonId = useId()
  const roles = choices
  const [role, setRole] = useState<string>(roles[0] ?? 'ops_admin')
  const [minutes, setMinutes] = useState<number>(30)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Reason and code: cleared every time the dialog opens or closes.
  const rc = useReasonAndCode(open)
  const { reason, setReason, code, setCode, codeError, setCodeError, codeOptional } = rc
  // A security-key-only console confirms with the key after Elevate (the
  // shared step-up dialog); everyone else types the code here, so the
  // elevation needs one dialog. An administrator with a usable key may leave
  // the code empty and confirm with the key instead.
  const { data: factors } = useConsoleFactors(open)
  const codeAllowed = factors?.totp_allowed ?? true
  const reasonOk = reason.trim().length >= REASON_MIN && reason.trim().length <= REASON_MAX
  const codeOk = !codeAllowed || rc.codeOk

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!reasonOk || !codeOk) return
    setBusy(true)
    setError(null)
    setCodeError(null)
    try {
      await adminElevate(role, minutes, reason.trim(), codeAllowed ? code.trim() : '')
      rc.reset()
      onElevated()
    } catch (err) {
      // A refused code is shown under the code field, which stays usable.
      const message = stepUpErrorMessage(err, t)
      if (codeAllowed && code.trim()) {
        rc.refuseCode(message)
      } else {
        setError(message)
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t('admin.elevation.title', 'Elevate for a while')}</DialogTitle>
            <DialogDescription>
              {t(
                'admin.elevation.description',
                'Your session acts with the chosen role until the time is up, then read-only again. Every elevation is in the administrator audit log.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>{t('admin.elevation.role', 'Role')}</Label>
                <Select value={role} onValueChange={(v) => setRole(v)}>
                  <SelectTrigger aria-label={t('admin.elevation.role', 'Role')}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {roles.map((r) => (
                      <SelectItem key={r} value={r}>
                        {r.includes('_admin') && !r.startsWith('platform_')
                          ? t(`admin.role.${r}`, r)
                          : t(`admin.platformRole.${r}`, r)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.elevation.duration', 'For')}</Label>
                <Select value={String(minutes)} onValueChange={(v) => setMinutes(Number(v))}>
                  <SelectTrigger aria-label={t('admin.elevation.duration', 'For')}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DURATIONS.map((m) => (
                      <SelectItem key={m} value={String(m)}>
                        {t('admin.elevation.minutes', '{n} minutes', { n: m })}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor={reasonId}>{t('admin.confirm.reason', 'Reason')}</Label>
              <Textarea
                id={reasonId}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={REASON_MAX}
                rows={3}
                required
              />
              <p className="text-xs text-muted-foreground">
                {t(
                  'admin.confirm.reasonHint',
                  'At least {min} characters. Kept in the administrator audit log.',
                  { min: REASON_MIN }
                )}
              </p>
            </div>
            {codeAllowed ? (
              <StepUpCodeField
                value={code}
                onChange={(v) => {
                  setCode(v)
                  setCodeError(null)
                }}
                optional={codeOptional}
                error={codeError}
              />
            ) : (
              <p className="text-sm text-muted-foreground">
                {t(
                  'admin.elevation.keyOnly',
                  'After Elevate, confirm with your security key or passkey.'
                )}
              </p>
            )}
          </DialogBody>
          <DialogSubmitError message={error} />

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={busy || !reasonOk || !codeOk}>
              {t('admin.elevation.elevate', 'Elevate')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
