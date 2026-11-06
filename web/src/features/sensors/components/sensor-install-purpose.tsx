'use client'

/**
 * "What will this sensor scan?": the Add sensor dialog's first question
 * (research/466 D2, D5). The answer shapes the install command: internal
 * networks add SENSOR_ALLOW_PRIVATE_TARGETS=1, the host owner's consent to
 * scan private addresses, which they see in the command they run. An
 * internet-only sensor never gets it. Pinning the host to the listed
 * networks is opt-in and only for internal-only sensors (a pin would refuse
 * the public targets of a sensor that scans both).
 */

import { useId } from 'react'

import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import type { InstallIntent, InstallPurpose } from '@/lib/api/sensor-pairing-hooks'
import { cn } from '@/lib/utils'

export const INSTALL_PURPOSES: InstallPurpose[] = ['internet', 'internal', 'both']

/** What the person typed: the purpose, the networks and the pin box. */
export interface InstallPurposeDraft {
  purpose: InstallPurpose
  /** Networks, separated by commas, spaces or new lines. */
  ranges: string
  /** Also restrict the host to these networks (internal only). */
  pin: boolean
}

export const DEFAULT_INSTALL_PURPOSE: InstallPurposeDraft = {
  purpose: 'internet',
  ranges: '',
  pin: false,
}

/** The networks of a draft as a list (blank entries dropped). */
export function parseRangeList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

/** Whether the draft names private networks the sensor scans. */
export function scansInternal(p: InstallPurpose): boolean {
  return p === 'internal' || p === 'both'
}

/** The intent the install command is rendered from. */
export function installIntentOf(d: InstallPurposeDraft): InstallIntent {
  const ranges = parseRangeList(d.ranges)
  if (d.purpose === 'internal' && d.pin && ranges.length > 0) {
    return { purpose: d.purpose, allowed_ranges: ranges }
  }
  return { purpose: d.purpose }
}

/**
 * A radio group drawn as option cards: one card per choice, the selected
 * one outlined. Shared by the Add sensor questions.
 */
export function OptionCards<V extends string>({
  value,
  onChange,
  options,
  labelledBy,
  className,
}: {
  value: V
  onChange: (v: V) => void
  options: { key: V; label: string; hint?: string }[]
  labelledBy: string
  className?: string
}) {
  const id = useId()
  return (
    <RadioGroup
      value={value}
      onValueChange={(v) => onChange(v as V)}
      aria-labelledby={labelledBy}
      className={cn('grid gap-2', className)}
    >
      {options.map((o) => (
        <label
          key={o.key}
          htmlFor={`${id}-${o.key}`}
          className={cn(
            'flex min-h-11 cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 text-sm transition-colors',
            value === o.key ? 'border-primary bg-primary/5' : 'hover:bg-muted/40'
          )}
        >
          <RadioGroupItem id={`${id}-${o.key}`} value={o.key} className="mt-0.5" />
          <span className="min-w-0">
            <span className="block font-medium">{o.label}</span>
            {o.hint && <span className="block text-xs text-muted-foreground">{o.hint}</span>}
          </span>
        </label>
      ))}
    </RadioGroup>
  )
}

export function InstallPurposeStep({
  value,
  onChange,
  labelledBy,
}: {
  value: InstallPurposeDraft
  onChange: (v: InstallPurposeDraft) => void
  labelledBy: string
}) {
  const { t } = useTranslation()
  const ids = { ranges: useId(), pin: useId() }
  const internal = scansInternal(value.purpose)
  return (
    <div className="space-y-3" data-testid="install-purpose">
      <OptionCards
        value={value.purpose}
        onChange={(purpose) => onChange({ ...value, purpose })}
        labelledBy={labelledBy}
        className="sm:grid-cols-3"
        options={INSTALL_PURPOSES.map((p) => ({
          key: p,
          label: t(`sensors.onboard.purpose.${p}.label`),
          hint: t(`sensors.onboard.purpose.${p}.hint`),
        }))}
      />
      {internal && (
        <div className="space-y-3 rounded-lg border p-3">
          <div className="space-y-1.5">
            <Label htmlFor={ids.ranges}>{t('sensors.onboard.purpose.ranges')}</Label>
            <Input
              id={ids.ranges}
              value={value.ranges}
              maxLength={2000}
              placeholder="10.0.0.0/16"
              spellCheck={false}
              className="font-mono"
              onChange={(e) => onChange({ ...value, ranges: e.target.value })}
            />
            <p className="text-xs text-muted-foreground">
              {t('sensors.onboard.purpose.rangesHint')}
            </p>
          </div>
          {value.purpose === 'internal' && (
            <HintedCheckbox
              id={ids.pin}
              checked={value.pin}
              disabled={parseRangeList(value.ranges).length === 0}
              onChange={(pin) => onChange({ ...value, pin })}
              label={t('sensors.onboard.purpose.pin')}
              hint={t('sensors.onboard.purpose.pinHint')}
            />
          )}
          <p className="text-xs text-muted-foreground" data-testid="install-purpose-switch-note">
            {t('sensors.onboard.purpose.switchNote')}
          </p>
        </div>
      )}
    </div>
  )
}

/** A checkbox with its label and a one-line hint under it. */
export function HintedCheckbox({
  id,
  checked,
  onChange,
  label,
  hint,
  disabled,
}: {
  id: string
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  hint: string
  disabled?: boolean
}) {
  return (
    <div className="flex items-start gap-2">
      <Checkbox
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={(c) => onChange(c === true)}
      />
      <span className="space-y-0.5">
        <Label htmlFor={id} className="font-normal">
          {label}
        </Label>
        <span className="block text-xs text-muted-foreground">{hint}</span>
      </span>
    </div>
  )
}
