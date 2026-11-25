'use client'

import { useId, useState, type ReactNode } from 'react'
import { Loader2, Lock } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime, SecretField as SecretInput, SettingsField } from '@/features/shared'
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
 * A write-only secret: never shown, only replaced or removed. A stored value
 * reads as a status row ("Stored, never shown") with Replace and Remove, not
 * as an empty input whose placeholder looks like a value; Replace opens the
 * masked input. A viewer who cannot change it sees the status as text.
 */
export function SecretField(p: SecretFieldProps) {
  const { t } = useTranslation()
  const [replacing, setReplacing] = useState(false)
  const typing = replacing || p.value !== ''
  const stored = t('admin.settings.secretStored', 'Stored, never shown')
  return (
    <SettingsField label={p.label} hint={p.help}>
      {(control) =>
        p.disabled ? (
          <p
            id={control.id}
            aria-describedby={control['aria-describedby']}
            className="flex min-h-9 items-center gap-2 text-body text-muted-foreground"
          >
            {p.isSet && <Lock className="size-4 shrink-0" aria-hidden />}
            {p.isSet ? stored : t('admin.settings.secretNone', 'Not set')}
          </p>
        ) : p.isSet && p.clear ? (
          <div className="flex min-h-9 flex-wrap items-center gap-x-3 gap-y-1">
            <p id={control.id} className="text-body text-destructive">
              {t('admin.settings.secretRemoving', 'Removed when you save')}
            </p>
            <Button type="button" variant="ghost" size="sm" onClick={() => p.onClear(false)}>
              {t('admin.settings.secretUndo', 'Keep it')}
            </Button>
          </div>
        ) : p.isSet && !typing ? (
          <div className="flex min-h-9 flex-wrap items-center gap-x-3 gap-y-1">
            <p
              id={control.id}
              aria-describedby={control['aria-describedby']}
              className="flex items-center gap-2 text-body"
            >
              <Lock className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              {stored}
            </p>
            <span className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                aria-label={t('admin.settings.secretReplaceNamed', 'Replace {name}', {
                  name: p.label,
                })}
                onClick={() => setReplacing(true)}
              >
                {t('admin.settings.secretReplace', 'Replace')}
              </Button>
              {!p.noClear && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-label={t('admin.settings.secretRemoveNamed', 'Remove {name}', {
                    name: p.label,
                  })}
                  onClick={() => {
                    p.onChange('')
                    p.onClear(true)
                  }}
                >
                  {t('admin.settings.secretRemove', 'Remove')}
                </Button>
              )}
            </span>
          </div>
        ) : (
          <div className="flex min-w-0 items-center gap-2">
            {/* The kit field: masked, Show value for what was just typed; a
                stored value is never read back from the server. */}
            <SecretInput
              {...control}
              value={p.value}
              autoFocus={replacing}
              onChange={(e) => {
                p.onChange(e.target.value)
                p.onClear(false)
              }}
              onBlur={() => {
                if (p.value === '') setReplacing(false)
              }}
              autoComplete="new-password"
              placeholder={p.placeholder}
            />
            {p.isSet && (
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  p.onChange('')
                  setReplacing(false)
                }}
              >
                {t('admin.settings.secretKeepStored', 'Keep the stored one')}
              </Button>
            )}
          </div>
        )
      }
    </SettingsField>
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
  /** The action's own name for the confirm button (never a bare "Confirm"). */
  confirmText?: string
  /** Text the operator must type first, for a change that can never be undone. */
  typeToConfirm?: string
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
      typeToConfirm={p.typeToConfirm}
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
          (p.confirmText ?? t('admin.settings.confirm', 'Confirm'))
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
