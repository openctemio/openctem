'use client'

/**
 * How long a scope entry lasts (RFC-054 §6.1, §12.4), for the add and edit
 * dialogs: a compact segmented choice (7 days, 30 days, 90 days, 1 year,
 * Permanent, Custom date) that fits a phone screen, with the date the entry
 * would expire on. Only what the organization's policy allows can be picked;
 * a forbidden Permanent is shown disabled with the reason and who can change
 * it. The server enforces the same limits.
 */

import { useId } from 'react'
import Link from '@/components/link'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import {
  daysToDay,
  expiryDateFor,
  formatDay,
  isoDay,
  presetDays,
  type DurationChoice,
  type DurationPolicy,
} from '../lib/scope-entry'

interface ScopeDurationFieldProps {
  policy: DurationPolicy
  /** The resolved choice (always one the policy allows). */
  value: DurationChoice
  onChange: (c: DurationChoice) => void
  /** Edit dialog: offer "Keep" with the current expiry as its hint. */
  keepHint?: string
  /** Shown as the reason Permanent is off (intrusive entries). */
  className?: string
}

type Option =
  | { key: string; label: string; choice: DurationChoice; disabled?: boolean }
  | { key: 'custom'; label: string; choice: null; disabled?: boolean }

export function ScopeDurationField({
  policy,
  value,
  onChange,
  keepHint,
  className,
}: ScopeDurationFieldProps) {
  const { t, locale } = useTranslation()
  const id = useId()
  const permissions = usePermissions()

  const dayLabel = (n: number) =>
    n === 365
      ? t('scope.duration.year', '1 year')
      : n === 1
        ? t('scope.duration.day1', '1 day')
        : t('scope.duration.days', '{n} days', { n })

  const options: Option[] = []
  if (keepHint !== undefined)
    options.push({ key: 'keep', label: t('scope.duration.keep', 'Keep'), choice: { kind: 'keep' } })
  if (policy.expiring) {
    for (const d of presetDays(policy.maxDays))
      options.push({ key: `d${d}`, label: dayLabel(d), choice: { kind: 'days', days: d } })
  }
  if (policy.permanent !== 'hidden')
    options.push({
      key: 'permanent',
      label: t('scope.duration.permanent', 'Permanent'),
      choice: { kind: 'permanent' },
      disabled: policy.permanent === 'forbidden',
    })
  if (policy.expiring)
    options.push({ key: 'custom', label: t('scope.duration.custom', 'Custom date'), choice: null })

  // A day count that is not a preset (from a fix's "7 days" under a 5-day
  // limit, say) shows as a custom date.
  const isCustom =
    value.kind === 'days' && (value.custom || !presetDays(policy.maxDays).includes(value.days))
  const selectedKey =
    value.kind === 'keep'
      ? 'keep'
      : value.kind === 'permanent'
        ? 'permanent'
        : isCustom
          ? 'custom'
          : `d${value.days}`

  const today = new Date()
  const minDay = isoDay(expiryDateFor(1, today))
  const maxDay = isoDay(expiryDateFor(policy.maxDays, today))

  const outcome =
    value.kind === 'keep'
      ? keepHint
      : value.kind === 'permanent'
        ? t('scope.duration.noExpiry', 'No expiry')
        : t('scope.duration.expires', 'Expires {date}', {
            date: formatDay(expiryDateFor(value.days, today), locale),
          })

  return (
    <fieldset className={cn('space-y-2', className)}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-2">
        <legend className="text-sm font-medium">{t('scope.duration.label', 'Duration')}</legend>
        <span className="text-xs text-muted-foreground" aria-live="polite" data-testid="expiry">
          {outcome}
        </span>
      </div>
      <div
        role="radiogroup"
        aria-label={t('scope.duration.label', 'Duration')}
        className="grid grid-cols-3 gap-1 sm:grid-cols-6"
      >
        {options.map((o) => {
          const checked = o.key === selectedKey
          return (
            <button
              key={o.key}
              type="button"
              role="radio"
              aria-checked={checked}
              disabled={o.disabled}
              onClick={() =>
                onChange(
                  o.choice ?? {
                    kind: 'days',
                    days: value.kind === 'days' ? value.days : Math.min(30, policy.maxDays),
                    custom: true,
                  }
                )
              }
              className={cn(
                'h-9 rounded-md border px-1 text-xs font-medium transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                checked
                  ? 'border-primary bg-primary text-primary-foreground'
                  : 'bg-background hover:bg-muted',
                o.disabled && 'cursor-not-allowed opacity-50 hover:bg-background'
              )}
            >
              {o.label}
            </button>
          )
        })}
      </div>

      {value.kind === 'days' && isCustom && (
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor={`${id}-date`} className="text-xs text-muted-foreground">
            {t('scope.duration.dateLabel', 'Expires on')}
          </label>
          <Input
            id={`${id}-date`}
            type="date"
            min={minDay}
            max={maxDay}
            value={isoDay(expiryDateFor(value.days, today))}
            onChange={(e) => {
              const n = daysToDay(e.target.value, today)
              if (n >= 1)
                onChange({ kind: 'days', days: Math.min(n, policy.maxDays), custom: true })
            }}
            className="h-8 w-40 text-xs"
          />
          <span className="text-xs text-muted-foreground">
            {t('scope.duration.limit', 'Latest {date} (your organization’s limit).', {
              date: formatDay(expiryDateFor(policy.maxDays, today), locale),
            })}
          </span>
        </div>
      )}

      {policy.permanent === 'forbidden' && (
        <p className="text-xs text-muted-foreground">
          {t(
            'scope.duration.permanentOff',
            'Permanent is off for intrusive (T2) entries in your organization.'
          )}{' '}
          <Link href="/settings/scope" className="underline underline-offset-2">
            {permissions.isOwner()
              ? t('scope.duration.changeLimit', 'Change the limit')
              : t('scope.duration.askOwner', 'Ask an owner')}
          </Link>
        </p>
      )}
    </fieldset>
  )
}
