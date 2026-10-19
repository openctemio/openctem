'use client'

import * as React from 'react'
import { toast } from 'sonner'
import { useSWRConfig } from 'swr'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar, SettingsSection } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { EMERGING_SETTINGS_ENDPOINT, updateEmergingThreatsSettings } from '../api'
import {
  formatHour,
  SETTINGS_BOUNDS,
  validateSettings,
  type EmergingThreatsSettings,
} from '../types'

interface FormState {
  enabled: boolean
  immediate_threshold: string
  digest_threshold: string
  digest_hour: string
  quiet_enabled: boolean
  quiet_start: string
  quiet_end: string
  quiet_override: string
  include_possible_in_immediate: boolean
  asset_names_in_messages: boolean
}

export function toFormState(s: EmergingThreatsSettings): FormState {
  return {
    enabled: !s.disabled,
    immediate_threshold: String(s.immediate_threshold),
    digest_threshold: String(s.digest_threshold),
    digest_hour: String(s.digest_hour),
    quiet_enabled: s.quiet_hours.enabled,
    quiet_start: String(s.quiet_hours.start_hour),
    quiet_end: String(s.quiet_hours.end_hour),
    quiet_override: String(s.quiet_override),
    include_possible_in_immediate: s.include_possible_in_immediate,
    asset_names_in_messages: s.asset_names_in_messages,
  }
}

/** An empty or non-numeric field becomes NaN, which fails the bound check. */
const num = (v: string) => (v.trim() === '' ? NaN : Number(v))

export function toPayload(f: FormState): EmergingThreatsSettings {
  return {
    disabled: !f.enabled,
    immediate_threshold: num(f.immediate_threshold),
    digest_threshold: num(f.digest_threshold),
    digest_hour: num(f.digest_hour),
    quiet_hours: {
      enabled: f.quiet_enabled,
      start_hour: num(f.quiet_start),
      end_hour: num(f.quiet_end),
    },
    quiet_override: num(f.quiet_override),
    include_possible_in_immediate: f.include_possible_in_immediate,
    asset_names_in_messages: f.asset_names_in_messages,
  }
}

export function EmergingThreatsSettingsForm({
  initial,
  timezone,
  formId,
  onSaved,
}: {
  initial: EmergingThreatsSettings
  /** The organization's time zone, which the hours are read in. */
  timezone: string
  formId: string
  onSaved?: () => void
}) {
  const { t } = useTranslation()
  const { mutate } = useSWRConfig()
  const [form, setForm] = React.useState<FormState>(() => toFormState(initial))
  const [baseline, setBaseline] = React.useState<FormState>(() => toFormState(initial))
  const [submitting, setSubmitting] = React.useState(false)
  const [showErrors, setShowErrors] = React.useState(false)

  const payload = toPayload(form)
  const errors = validateSettings(payload)
  const dirty = JSON.stringify(form) !== JSON.stringify(baseline)
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) =>
    setForm((s) => ({ ...s, [k]: v }))
  const err = (k: string) => (showErrors && errors[k] ? t(errors[k] as string) : null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (Object.keys(errors).length > 0) {
      setShowErrors(true)
      toast.error(t('emergingThreats.settings.fixErrors'))
      return
    }
    try {
      setSubmitting(true)
      const saved = await updateEmergingThreatsSettings(payload)
      toast.success(t('emergingThreats.settings.saved'))
      setForm(toFormState(saved))
      setBaseline(toFormState(saved))
      setShowErrors(false)
      void mutate(EMERGING_SETTINGS_ENDPOINT, saved, false)
      onSaved?.()
    } catch (e2) {
      toast.error(getErrorMessage(e2))
    } finally {
      setSubmitting(false)
    }
  }

  const b = SETTINGS_BOUNDS
  const hourHint = t('emergingThreats.settings.hourHint', undefined, { timezone })

  return (
    <>
      <form id={formId} className="space-y-8" onSubmit={handleSubmit} noValidate>
        <SettingsSection
          title={t('emergingThreats.settings.alerts')}
          description={t('emergingThreats.settings.alertsHelp')}
        >
          <ToggleRow
            id="et-enabled"
            label={t('emergingThreats.settings.enabled')}
            description={t('emergingThreats.settings.enabledHelp')}
            checked={form.enabled}
            onChange={(v) => set('enabled', v)}
          />
          <div className="grid gap-4 sm:grid-cols-2">
            <NumberField
              id="et-immediate"
              label={t('emergingThreats.settings.immediateThreshold')}
              help={t('emergingThreats.settings.immediateThresholdHelp', undefined, {
                min: b.immediate_threshold[0],
                max: b.immediate_threshold[1],
              })}
              value={form.immediate_threshold}
              onChange={(v) => set('immediate_threshold', v)}
              error={err('immediate_threshold')}
            />
            <NumberField
              id="et-digest"
              label={t('emergingThreats.settings.digestThreshold')}
              help={t('emergingThreats.settings.digestThresholdHelp', undefined, {
                min: b.digest_threshold[0],
                max: b.digest_threshold[1],
              })}
              value={form.digest_threshold}
              onChange={(v) => set('digest_threshold', v)}
              error={err('digest_threshold')}
            />
            <NumberField
              id="et-digest-hour"
              label={t('emergingThreats.settings.digestHour')}
              help={t('emergingThreats.settings.digestHourHelp', undefined, {
                time: hourPreview(form.digest_hour),
                timezone,
              })}
              value={form.digest_hour}
              onChange={(v) => set('digest_hour', v)}
              error={err('digest_hour')}
            />
          </div>
          <ToggleRow
            id="et-possible"
            label={t('emergingThreats.settings.includePossible')}
            description={t('emergingThreats.settings.includePossibleHelp')}
            checked={form.include_possible_in_immediate}
            onChange={(v) => set('include_possible_in_immediate', v)}
          />
        </SettingsSection>

        <SettingsSection
          title={t('emergingThreats.settings.quiet')}
          description={t('emergingThreats.settings.quietHelp')}
        >
          <ToggleRow
            id="et-quiet"
            label={t('emergingThreats.settings.quietEnabled')}
            description={hourHint}
            checked={form.quiet_enabled}
            onChange={(v) => set('quiet_enabled', v)}
          />
          {form.quiet_enabled && (
            <div className="grid gap-4 sm:grid-cols-3">
              <NumberField
                id="et-quiet-start"
                label={t('emergingThreats.settings.quietStart')}
                help={hourPreview(form.quiet_start)}
                value={form.quiet_start}
                onChange={(v) => set('quiet_start', v)}
                error={err('quiet_start')}
              />
              <NumberField
                id="et-quiet-end"
                label={t('emergingThreats.settings.quietEnd')}
                help={hourPreview(form.quiet_end)}
                value={form.quiet_end}
                onChange={(v) => set('quiet_end', v)}
                error={err('quiet_end')}
              />
              <NumberField
                id="et-quiet-override"
                label={t('emergingThreats.settings.quietOverride')}
                help={t('emergingThreats.settings.quietOverrideHelp', undefined, {
                  min: b.quiet_override[0],
                  max: b.quiet_override[1],
                })}
                value={form.quiet_override}
                onChange={(v) => set('quiet_override', v)}
                error={err('quiet_override')}
              />
            </div>
          )}
        </SettingsSection>

        <SettingsSection
          title={t('emergingThreats.settings.messages')}
          description={t('emergingThreats.settings.messagesHelp')}
        >
          <ToggleRow
            id="et-asset-names"
            label={t('emergingThreats.settings.assetNames')}
            description={t('emergingThreats.settings.assetNamesHelp')}
            checked={form.asset_names_in_messages}
            onChange={(v) => set('asset_names_in_messages', v)}
          />
        </SettingsSection>
      </form>
      <SettingsSaveBar
        dirty={dirty}
        saving={submitting}
        form={formId}
        onDiscard={() => {
          setForm(baseline)
          setShowErrors(false)
        }}
      />
    </>
  )
}

/** HH:00 of a valid hour field, a dash otherwise. */
function hourPreview(v: string): string {
  const n = Number(v)
  if (v.trim() === '' || !Number.isInteger(n) || n < 0 || n > 23) return '—'
  return formatHour(n)
}

function NumberField({
  id,
  label,
  help,
  value,
  onChange,
  error,
}: {
  id: string
  label: string
  help?: string
  value: string
  onChange: (v: string) => void
  error: string | null
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        inputMode="numeric"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={error ? true : undefined}
        aria-describedby={`${id}-help`}
      />
      <p
        id={`${id}-help`}
        role={error ? 'alert' : undefined}
        className={error ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'}
      >
        {error ?? help}
      </p>
    </div>
  )
}

function ToggleRow({
  id,
  label,
  description,
  checked,
  onChange,
}: {
  id: string
  label: string
  description: string
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border p-4">
      <div>
        <Label htmlFor={id}>{label}</Label>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  )
}
