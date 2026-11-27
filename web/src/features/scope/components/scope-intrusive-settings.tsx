'use client'

/**
 * The owner-only scope setting (RFC-054 §12.4): how long an intrusive (T2)
 * scope entry may last. 7, 30 (default), 90 or 365 days, or permanent. A T2
 * entry still needs a verified domain and an approval. Saving asks for a
 * reason and step-up re-authentication, is audited and tells every
 * administrator. Everyone else sees the value read-only.
 *
 * The section shows the two values; an owner changes them in a dialog
 * (the change, its reason, Save), so the page's save bar never carries an
 * owner-only change that needs its own reason.
 */

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsField, SettingsRow, SettingsSection } from '@/features/shared'
import { usePermissions } from '@/lib/permissions'
import { updateScopeIntrusiveSettings } from '../api/use-scope-api'
import type { ApiScopeSettings, ScopeT2MaxDuration } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'

export const T2_DURATION_LABEL: Record<ScopeT2MaxDuration, string> = {
  '7d': '7 days',
  '30d': '30 days (default)',
  '90d': '90 days',
  '365d': '365 days',
  permanent: 'Permanent',
}

export function ScopeIntrusiveSettings({
  settings,
  onSaved,
}: {
  settings: ApiScopeSettings
  onSaved?: (s: ApiScopeSettings) => void
}) {
  const { t } = useTranslation()
  const { isOwner } = usePermissions()
  const owner = isOwner()
  const [open, setOpen] = useState(false)
  const current = (settings.t2_max_duration as ScopeT2MaxDuration) || '30d'
  const currentDays = settings.t2_attestation_days ?? 90
  const daysText = t('scope.intrusive.everyDays', '{count, plural, one {# day} other {# days}}', {
    count: currentDays,
  })

  return (
    <SettingsSection
      framed
      id="scope-intrusive"
      title={t('scope.intrusive.title', 'Intrusive (T2) entries')}
      description={
        owner
          ? t(
              'scope.intrusive.ownerHint',
              'Only an owner changes this. Saving asks for a reason and for you to confirm your identity; it is audited and every administrator is told.'
            )
          : t('scope.intrusive.readHint', 'Set by an owner of your organization.')
      }
      actions={
        owner ? (
          <Button variant="outline" onClick={() => setOpen(true)}>
            {t('scope.intrusive.change', 'Change')}
          </Button>
        ) : undefined
      }
    >
      <SettingsRow
        label={t('scope.intrusive.longest', 'Longest intrusive entry')}
        hint={t(
          'scope.intrusive.longestHint',
          'How long an entry that allows intrusive (T2) probes may last. Every T2 entry still needs a verified domain and an approval. Long and permanent T2 entries are confirmed again periodically, or they fall back to non-intrusive (T1).'
        )}
      >
        <span className="text-body font-medium" data-testid="t2-max-duration">
          {t(`scope.intrusive.duration.${current}`, T2_DURATION_LABEL[current])}
        </span>
      </SettingsRow>
      <SettingsRow
        label={t('scope.intrusive.confirmEvery', 'Confirm long T2 entries every')}
        hint={t(
          'scope.intrusive.confirmEveryHint',
          '30 to 180 days. When a confirmation is due, owners and administrators are asked "Keep T2?". Without an answer within 14 days the entry falls back to non-intrusive (T1); it is never removed.'
        )}
      >
        <span className="text-body font-medium" data-testid="t2-attestation-days">
          {daysText}
        </span>
      </SettingsRow>
      {owner && open && (
        <IntrusiveDialog
          current={current}
          currentDays={currentDays}
          onClose={() => setOpen(false)}
          onSaved={(out) => {
            setOpen(false)
            onSaved?.(out)
          }}
        />
      )}
    </SettingsSection>
  )
}

function IntrusiveDialog({
  current,
  currentDays,
  onClose,
  onSaved,
}: {
  current: ScopeT2MaxDuration
  currentDays: number
  onClose: () => void
  onSaved: (s: ApiScopeSettings) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const [value, setValue] = useState<ScopeT2MaxDuration>(current)
  const [days, setDays] = useState(currentDays)
  const [reason, setReason] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => setValue(current), [current])
  useEffect(() => setDays(currentDays), [currentDays])
  const clampedDays = Math.min(180, Math.max(30, Math.round(days) || 90))
  const dirty = value !== current || clampedDays !== currentDays

  const save = async () => {
    setSaving(true)
    setError(null)
    try {
      const out = await updateScopeIntrusiveSettings({
        t2_max_duration: value,
        t2_attestation_days: clampedDays,
        reason: reason.trim(),
      })
      toast.success(t('scope.intrusive.saved', 'Intrusive entry limit saved'), {
        description: t('scope.settings.notified', 'Every administrator was notified.'),
      })
      if (out) onSaved(out)
      else onClose()
    } catch (err) {
      setError(
        scopeErrorMessage(t, err, t('scope.intrusive.saveFailed', 'Could not save the setting.'))
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && !saving && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('scope.intrusive.title', 'Intrusive (T2) entries')}</DialogTitle>
          <DialogDescription>
            {t(
              'scope.intrusive.ownerHint',
              'Only an owner changes this. Saving asks for a reason and for you to confirm your identity; it is audited and every administrator is told.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="flex flex-col gap-4">
            <SettingsField
              id={`${id}-t2`}
              label={t('scope.intrusive.longest', 'Longest intrusive entry')}
              hint={t(
                'scope.intrusive.longestShort',
                'Every T2 entry still needs a verified domain and an approval.'
              )}
            >
              {(a) => (
                <Select
                  value={value}
                  onValueChange={(v) => setValue(v as ScopeT2MaxDuration)}
                  disabled={saving}
                >
                  <SelectTrigger {...a} className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(Object.keys(T2_DURATION_LABEL) as ScopeT2MaxDuration[]).map((k) => (
                      <SelectItem key={k} value={k}>
                        {t(`scope.intrusive.duration.${k}`, T2_DURATION_LABEL[k])}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </SettingsField>
            <SettingsField
              id={`${id}-attest`}
              label={t('scope.intrusive.confirmEvery', 'Confirm long T2 entries every')}
              hint={t('scope.intrusive.confirmEveryShort', '30 to 180 days.')}
            >
              {(a) => (
                <div className="flex items-center gap-2">
                  <Input
                    {...a}
                    type="number"
                    inputMode="numeric"
                    min={30}
                    max={180}
                    className="w-24"
                    value={days}
                    onChange={(e) => setDays(Number(e.target.value))}
                    disabled={saving}
                  />
                  <span className="text-dense text-muted-foreground">
                    {t('scope.settings.days', 'days')}
                  </span>
                </div>
              )}
            </SettingsField>
            <SettingsField
              id={`${id}-reason`}
              label={t('scope.intrusive.reason', 'Reason')}
              hint={t(
                'scope.intrusive.reasonHint',
                'Kept in the audit log and sent to every administrator.'
              )}
              error={error ?? undefined}
            >
              {(a) => (
                <Textarea
                  {...a}
                  rows={2}
                  maxLength={1000}
                  value={reason}
                  placeholder={t(
                    'scope.intrusive.reasonPlaceholder',
                    'For example: standing pentest contract, ticket SEC-42.'
                  )}
                  onChange={(e) => setReason(e.target.value)}
                  disabled={saving}
                />
              )}
            </SettingsField>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={saving}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={() => void save()} disabled={saving || !dirty || !reason.trim()}>
            {saving && <Loader2 className="animate-spin" aria-hidden="true" />}
            {t('scope.intrusive.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
