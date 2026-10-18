'use client'

import { useEffect, useId, useState, type FormEvent } from 'react'
import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
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
import { Label } from '@/components/ui/label'
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
import { adminCan, type AdminIdentity, type AdminRole } from '../types'
import { REASON_MAX, REASON_MIN, stepUpErrorMessage } from './admin-confirm-dialog'

const DURATIONS = [15, 30, 60] as const

/**
 * Time-boxed elevation: an administrator acts as read-only until they elevate
 * the console session to a role no higher than their own, for 15 to 60
 * minutes, with a reason and a fresh code. The bar shows which and until
 * when, and ends it on request. Hidden for a read-only administrator, and when
 * the installation does not require elevation (role already the own one).
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
  const max = admin.max_role ?? admin.role
  const elevated = !!admin.elevated_until
  const canElevate = !elevated && admin.role === 'readonly' && max !== 'readonly'

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

  const until = admin.elevated_until
    ? new Date(admin.elevated_until).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : ''

  return (
    <div className="px-4 pt-2">
      {elevated ? (
        <Alert>
          <ShieldCheck className="size-4" />
          <AlertDescription className="flex flex-wrap items-center justify-between gap-2">
            <span>
              {t('admin.elevation.active', 'Acting as {role} until {until}.', {
                role: t(`admin.role.${admin.role}`, admin.role),
                until,
              })}
            </span>
            <Button size="sm" variant="outline" disabled={busy} onClick={() => void end()}>
              {t('admin.elevation.end', 'End now')}
            </Button>
          </AlertDescription>
        </Alert>
      ) : (
        <Alert>
          <ShieldAlert className="size-4" />
          <AlertDescription className="flex flex-wrap items-center justify-between gap-2">
            <span>
              {t(
                'admin.elevation.readonly',
                'You are acting as read-only. Elevate for a while to change anything.'
              )}
            </span>
            <Button size="sm" onClick={() => setOpen(true)}>
              {t('admin.elevation.elevate', 'Elevate')}
            </Button>
          </AlertDescription>
        </Alert>
      )}
      <ElevateDialog
        open={open}
        onOpenChange={setOpen}
        max={max}
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
  max,
  onElevated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  max: AdminRole
  onElevated: () => void
}) {
  const { t } = useTranslation()
  const reasonId = useId()
  const roles: AdminRole[] = (['ops_admin', 'super_admin'] as AdminRole[]).filter((r) =>
    adminCan(max, r)
  )
  const [role, setRole] = useState<AdminRole>(roles[roles.length - 1] ?? 'ops_admin')
  const [minutes, setMinutes] = useState<number>(30)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const reasonOk = reason.trim().length >= REASON_MIN && reason.trim().length <= REASON_MAX

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!reasonOk) return
    setBusy(true)
    setError(null)
    try {
      await adminElevate(role, minutes, reason.trim())
      setReason('')
      onElevated()
    } catch (err) {
      setError(stepUpErrorMessage(err, t))
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
                <Select value={role} onValueChange={(v) => setRole(v as AdminRole)}>
                  <SelectTrigger aria-label={t('admin.elevation.role', 'Role')}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {roles.map((r) => (
                      <SelectItem key={r} value={r}>
                        {t(`admin.role.${r}`, r)}
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
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={busy || !reasonOk}>
              {t('admin.elevation.elevate', 'Elevate')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
