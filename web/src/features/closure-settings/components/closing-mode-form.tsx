'use client'

import * as React from 'react'
import { toast } from 'sonner'
import { Clock, Loader2 } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Switch } from '@/components/ui/switch'
import { SettingsSection } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatLocalized } from '@/lib/format-date'
import { useTranslation } from '@/context/i18n-provider'

import { cancelPendingClosureSettings, updateClosureSettings } from '../api'
import {
  CLOSING_MODES,
  effectiveMode,
  loosens,
  type ClosingMode,
  type ClosureSettings,
} from '../types'

export interface ClosingModeFormStatus {
  dirty: boolean
  submitting: boolean
}

interface ClosingModeFormProps {
  initial: ClosureSettings
  /** The section's ETag from the organization settings read (If-Match). */
  etag?: string
  /** Only the organization owner may let scans close critical findings. */
  isOwner: boolean
  formId: string
  onSaved?: (saved: ClosureSettings) => void
  onStatusChange?: (status: ClosingModeFormStatus) => void
}

const MODE_COPY: Record<ClosingMode, [string, string]> = {
  auto: [
    'Automatic',
    'A covered scan that no longer finds an issue closes it. Critical findings wait for review in auto mode.',
  ],
  review: [
    'Review first',
    'Every close the platform would make waits in Ready to close until a person confirms it.',
  ],
  off: ['Off', 'Only a person closes findings. Scans still record what they no longer find.'],
}

function isConflict(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === 'SETTINGS_CONFLICT'
}

export function ClosingModeForm({
  initial,
  etag,
  isOwner,
  formId,
  onSaved,
  onStatusChange,
}: ClosingModeFormProps) {
  const { t, locale } = useTranslation()
  const inForce = { mode: effectiveMode(initial), critical_auto_close: initial.critical_auto_close }
  const [mode, setMode] = React.useState<ClosingMode>(inForce.mode)
  const [critical, setCritical] = React.useState(inForce.critical_auto_close)
  const [submitting, setSubmitting] = React.useState(false)
  const [canceling, setCanceling] = React.useState(false)

  const dirty = mode !== inForce.mode || critical !== inForce.critical_auto_close
  const willWait = dirty && loosens(inForce, { mode, critical_auto_close: critical })
  React.useEffect(() => {
    onStatusChange?.({ dirty, submitting })
  }, [dirty, submitting, onStatusChange])

  const pendingAt = initial.pending_at ? new Date(initial.pending_at) : null
  const whenText = (d: Date) => formatLocalized(d, locale, { time: true })

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!dirty) return
    try {
      setSubmitting(true)
      const saved = await updateClosureSettings({ mode, critical_auto_close: critical }, etag)
      toast.success(
        saved.pending_at
          ? t(
              'settings.closing.savedPending',
              'Saved. The change takes effect in 24 hours; owners and administrators were told.'
            )
          : t('settings.closing.saved', 'Closing mode saved')
      )
      onSaved?.(saved)
    } catch (err) {
      if (isConflict(err)) {
        toast.error(
          t(
            'settings.closing.conflict',
            'Someone else changed these settings since you opened the page. Reload to see their change.'
          )
        )
      } else {
        toast.error(getErrorMessage(err))
      }
    } finally {
      setSubmitting(false)
    }
  }

  const cancelPending = async () => {
    try {
      setCanceling(true)
      const saved = await cancelPendingClosureSettings()
      toast.success(t('settings.closing.pendingCanceled', 'The waiting change was canceled'))
      onSaved?.(saved)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setCanceling(false)
    }
  }

  const pendingMode = initial.pending_mode
  return (
    <form id={formId} className="space-y-8" onSubmit={save} noValidate>
      {pendingAt && pendingMode && (
        <Alert>
          <Clock className="h-4 w-4" />
          <AlertTitle>
            {t('settings.closing.pendingTitle', 'A change takes effect on {when}', {
              when: whenText(pendingAt),
            })}
          </AlertTitle>
          <AlertDescription className="space-y-3">
            <p>
              {initial.pending_critical_auto_close
                ? t(
                    'settings.closing.pendingBodyCritical',
                    'Closing mode {mode}, and covered scans may close critical findings without review. Until then the current mode stays in force.',
                    { mode: t(`settings.closing.mode.${pendingMode}`, MODE_COPY[pendingMode][0]) }
                  )
                : t(
                    'settings.closing.pendingBody',
                    'Closing mode {mode}. Until then the current mode stays in force.',
                    { mode: t(`settings.closing.mode.${pendingMode}`, MODE_COPY[pendingMode][0]) }
                  )}
            </p>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => void cancelPending()}
              disabled={canceling}
            >
              {canceling && <Loader2 className="h-4 w-4 animate-spin" />}
              {t('settings.closing.cancelPending', 'Cancel this change')}
            </Button>
          </AlertDescription>
        </Alert>
      )}

      <SettingsSection
        id="closing-mode-choice"
        title={t('settings.closing.modeTitle', 'How findings close')}
        description={t(
          'settings.closing.modeHint',
          'A finding closes only when the same check looks again and the issue is gone. Blocked, unreachable or partial scans never close anything.'
        )}
      >
        <RadioGroup
          value={mode}
          onValueChange={(v) => setMode(v as ClosingMode)}
          aria-labelledby="closing-mode-choice"
          className="gap-3"
        >
          {CLOSING_MODES.map((m) => (
            <div key={m} className="flex items-start gap-3">
              <RadioGroupItem
                id={`closing-${m}`}
                value={m}
                className="mt-0.5"
                aria-describedby={`closing-${m}-desc`}
              />
              <div>
                <Label htmlFor={`closing-${m}`}>
                  {t(`settings.closing.mode.${m}`, MODE_COPY[m][0])}
                </Label>
                <p id={`closing-${m}-desc`} className="text-sm text-muted-foreground">
                  {t(`settings.closing.modeDesc.${m}`, MODE_COPY[m][1])}
                </p>
              </div>
            </div>
          ))}
        </RadioGroup>
      </SettingsSection>

      <SettingsSection
        title={t('settings.closing.criticalTitle', 'Critical findings')}
        description={t(
          'settings.closing.criticalHint',
          'Critical, P0 and known exploited findings wait for review in auto mode: a person confirms the close in Ready to close.'
        )}
      >
        <div className="flex items-center justify-between gap-4 rounded-lg border p-4">
          <div>
            <Label htmlFor="closing-critical">
              {t(
                'settings.closing.criticalAutoClose',
                'Let a covered scan close critical findings without review'
              )}
            </Label>
            <p className="text-sm text-muted-foreground">
              {isOwner
                ? t(
                    'settings.closing.criticalAutoCloseHint',
                    'Applies in auto mode only. Turning it on takes effect after 24 hours.'
                  )
                : t(
                    'settings.closing.criticalOwnerOnly',
                    'Only the organization owner can turn this on.'
                  )}
            </p>
          </div>
          <Switch
            id="closing-critical"
            checked={critical}
            onCheckedChange={setCritical}
            disabled={(!isOwner && !critical) || mode !== 'auto'}
          />
        </div>
      </SettingsSection>

      {willWait && (
        <p className="text-sm text-muted-foreground" role="status">
          {t(
            'settings.closing.willWait',
            'This change lets the platform close more findings alone: it asks you to sign in again, takes effect in 24 hours, and owners and administrators are told.'
          )}
        </p>
      )}
    </form>
  )
}
