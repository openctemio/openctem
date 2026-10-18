'use client'

import { useId, useState, type ReactNode } from 'react'
import { Loader2, Lock } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared'
import { AdminApiError } from '@console/lib/admin-api/client'
import type { SettingChange } from '../types'

/*
 * Shared parts of the console settings that moved from server environment
 * variables (RFC-079): the "locked by the server configuration" notice, the
 * "changed by X, when" line, the write-only secret field and the confirm
 * dialog that asks for a reason.
 */

/** "Locked by the server configuration (NAME)": the console cannot change it. */
export function LockedByEnvironment({ envVar }: { envVar: string }) {
  const { t } = useTranslation()
  return (
    <Alert>
      <Lock className="size-4" aria-hidden />
      <AlertDescription>
        {t(
          'admin.settings.lockedByEnvironment',
          'Locked by the server configuration ({name}). Change it on the server and restart, or remove the variable to manage it here.',
          { name: envVar }
        )}
      </AlertDescription>
    </Alert>
  )
}

/** Who changed the setting in this console, and when. */
export function SettingChangedLine({ change }: { change: SettingChange }) {
  const { t } = useTranslation()
  if (!change.changed_at) return null
  return (
    <p className="text-xs text-muted-foreground">
      {change.changed_by
        ? t('admin.settings.changedBy', 'Changed by {who}', { who: change.changed_by })
        : t('admin.settings.changed', 'Changed')}{' '}
      <RelativeTime date={change.changed_at} />
    </p>
  )
}

export interface SecretFieldProps {
  label: string
  /** A value is stored (it is never shown). */
  isSet: boolean
  value: string
  onChange: (v: string) => void
  /** Remove the stored value on save. */
  clear: boolean
  onClear: (clear: boolean) => void
  disabled?: boolean
  help?: ReactNode
  placeholder?: string
  /** Hide the "remove" choice (when removing is done another way). */
  noClear?: boolean
}

/**
 * A write-only secret: never shown, only replaced or removed. The field says
 * whether one is stored.
 */
export function SecretField(p: SecretFieldProps) {
  const { t } = useTranslation()
  const id = useId()
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{p.label}</Label>
      <Input
        id={id}
        type="password"
        value={p.value}
        onChange={(e) => {
          p.onChange(e.target.value)
          p.onClear(false)
        }}
        disabled={p.disabled || p.clear}
        autoComplete="new-password"
        spellCheck={false}
        placeholder={
          p.isSet
            ? t('admin.settings.secretKeep', 'Stored. Type to replace it.')
            : (p.placeholder ?? t('admin.settings.secretNone', 'Not set'))
        }
      />
      {p.help && <p className="text-xs text-muted-foreground">{p.help}</p>}
      {p.isSet && !p.disabled && !p.noClear && (
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <input
            type="checkbox"
            checked={p.clear}
            onChange={(e) => {
              p.onClear(e.target.checked)
              p.onChange('')
            }}
          />
          {t('admin.settings.secretClear', 'Remove the stored value')}
        </label>
      )}
    </div>
  )
}

/** The value of a write-only field to send: omitted keeps, "" removes. */
export function secretPatch(value: string, clear: boolean): string | undefined {
  if (clear) return ''
  return value.trim() === '' ? undefined : value.trim()
}

export interface ReasonConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  desc: string
  /** Runs the save with the reason; a rejection is shown and keeps the dialog open. */
  onConfirm: (reason: string) => Promise<void>
  destructive?: boolean
}

/**
 * Confirms a guarded change: the reason is required, recorded in the admin
 * audit log and sent to every administrator. The console's step-up dialog
 * follows when the session needs a fresh confirmation.
 */
export function ReasonConfirmDialog(p: ReasonConfirmDialogProps) {
  const { t } = useTranslation()
  const id = useId()
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const confirm = async () => {
    setBusy(true)
    setError(null)
    try {
      await p.onConfirm(reason.trim())
      setReason('')
      p.onOpenChange(false)
    } catch (e) {
      setError(
        e instanceof AdminApiError || e instanceof Error
          ? e.message
          : t('admin.settings.saveFailed', 'Could not save the setting')
      )
    } finally {
      setBusy(false)
    }
  }
  return (
    <ConfirmDialog
      open={p.open}
      onOpenChange={(open) => {
        if (!busy) {
          setError(null)
          p.onOpenChange(open)
        }
      }}
      title={p.title}
      desc={p.desc}
      destructive={p.destructive}
      disabled={reason.trim() === '' || reason.length > 500}
      isLoading={busy}
      handleConfirm={() => void confirm()}
      confirmText={
        busy ? (
          <>
            <Loader2 className="me-1.5 size-4 animate-spin" />
            {t('admin.settings.saving', 'Saving')}
          </>
        ) : (
          t('admin.settings.confirm', 'Confirm')
        )
      }
    >
      <div className="space-y-2">
        <Label htmlFor={id}>{t('admin.settings.reason', 'Reason')}</Label>
        <Textarea
          id={id}
          value={reason}
          onChange={(e) => setReason(e.target.value.replace(/[\r\n]+/g, ' '))}
          maxLength={500}
          rows={2}
          placeholder={t(
            'admin.settings.reasonPlaceholder',
            'Why this change? Recorded in the admin audit log and sent to every administrator.'
          )}
        />
        {error && <p className="text-sm text-destructive">{error}</p>}
      </div>
    </ConfirmDialog>
  )
}

/** Shows a saved-version conflict and reloads. */
export function handleSaveConflict(e: unknown, reload: () => void, conflictText: string): boolean {
  if (e instanceof AdminApiError && e.status === 409 && !e.code) {
    toast.error(conflictText)
    reload()
    return true
  }
  return false
}
