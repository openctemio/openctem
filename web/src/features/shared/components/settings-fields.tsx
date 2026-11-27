'use client'

import { useId, type ReactNode } from 'react'
import { Lock } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * The parts inside a framed `SettingsSection` (web/docs/ui-style-contract.md,
 * "Settings pages"):
 *
 * - `SettingsRow`: one setting on one line. What it is (label, hint) at the
 *   start, its control at the end. Below 45rem (a phone, a sheet) a switch or
 *   a short button stays at the end of the label's first line; a control that
 *   does not fit beside 13rem of text, and a `wide` control (a field, a
 *   select), goes under the text.
 * - `SettingsSwitchRow`: a row whose control is a switch.
 * - `SettingsSummaryRow`: a group of settings told in one line, whose editor
 *   opens on demand (a dialog; a bottom sheet on a phone) from its button.
 * - `SettingsBlock`: a padded block for anything else (a field grid, a note).
 * - `SettingsFieldGrid` + `SettingsField`: text fields with the label above,
 *   as many columns as fit at 16.25rem each.
 *
 * Controls are the kit's (`Input`, `SelectTrigger`, `Button`) at the kit's
 * sizes: 32px, and 36px with 16px text below 768px.
 */

const DIVIDER = 'border-t border-border-subtle'

/**
 * A row whose control stays beside its text on a phone: the text and the
 * control share a wrapping line, the control at the top end (level with the
 * label's first line). The text keeps a 13rem basis, so a control wider than
 * the rest of the line (a long button) moves under the text instead of
 * squeezing it into a sliver. From 45rem the row is a two-column grid.
 */
export const SETTINGS_ROW_BESIDE = 'flex flex-wrap items-start justify-between gap-x-4 gap-y-3'

/** The text box of a row: grows, and keeps 13rem beside a control on a phone. */
export const SETTINGS_ROW_TEXT = 'min-w-0 max-w-[58ch] flex-[1_1_13rem]'

export interface SettingsRowProps {
  /** What the setting is. A string is drawn as the row label. */
  label: ReactNode
  /** One or two sentences under the label. */
  hint?: ReactNode
  /** Id of the label element (point a control's `aria-labelledby` at it). */
  labelId?: string
  /** Id of the hint element (point a control's `aria-describedby` at it). */
  hintId?: string
  /** A text field or select as the control: it gets a column of its own width. */
  wide?: boolean
  /** The control(s) at the row end. */
  children?: ReactNode
  className?: string
  id?: string
}

export function SettingsRow({
  label,
  hint,
  labelId,
  hintId,
  wide = false,
  children,
  className,
  id,
}: SettingsRowProps) {
  const besideOnPhone = !wide && children != null
  return (
    <div
      id={id}
      data-slot="settings-row"
      className={cn(
        DIVIDER,
        'min-w-0 py-3.5 @[45rem]:grid @[45rem]:items-center @[45rem]:gap-x-8',
        besideOnPhone ? SETTINGS_ROW_BESIDE : 'flex flex-col gap-3',
        wide
          ? '@[45rem]:grid-cols-[minmax(0,1fr)_minmax(20rem,40%)]'
          : '@[45rem]:grid-cols-[minmax(0,1fr)_auto]',
        className
      )}
    >
      <div className={besideOnPhone ? SETTINGS_ROW_TEXT : 'min-w-0 max-w-[58ch]'}>
        <div id={labelId} className="text-body font-medium">
          {label}
        </div>
        {hint && (
          <div id={hintId} className="mt-0.5 text-cap text-muted-foreground text-pretty">
            {hint}
          </div>
        )}
      </div>
      {children && (
        <div
          className={cn(
            'flex min-w-0 flex-wrap items-center gap-2',
            besideOnPhone && 'max-w-full shrink-0',
            wide ? '@[45rem]:justify-self-stretch' : '@[45rem]:justify-self-end'
          )}
        >
          {children}
        </div>
      )}
    </div>
  )
}

export interface SettingsSwitchRowProps {
  label: string
  hint?: ReactNode
  checked: boolean
  onCheckedChange: (checked: boolean) => void
  disabled?: boolean
  id?: string
  className?: string
}

/** A setting that is on or off: the label names the switch, the hint describes it. */
export function SettingsSwitchRow({
  label,
  hint,
  checked,
  onCheckedChange,
  disabled,
  id,
  className,
}: SettingsSwitchRowProps) {
  const auto = useId()
  const switchId = id ?? `${auto}-switch`
  const hintId = `${auto}-hint`
  return (
    <SettingsRow
      className={className}
      label={<label htmlFor={switchId}>{label}</label>}
      hint={hint}
      hintId={hintId}
    >
      <Switch
        id={switchId}
        checked={checked}
        onCheckedChange={onCheckedChange}
        disabled={disabled}
        aria-describedby={hint ? hintId : undefined}
      />
    </SettingsRow>
  )
}

export interface SettingsSummaryRowProps {
  /** What the group of settings is ("False positives"). */
  label: string
  /** What is set, in plain words. */
  summary: ReactNode
  /** A second line under the summary (a waiting change). */
  note?: ReactNode
  /** The button's text: "Change", or "View" for someone who may not change it. */
  actionLabel: string
  onAction: () => void
  /** A hook on the button (the editor it opens), for tests and in-page links. */
  editor?: string
  id?: string
  className?: string
}

/**
 * A group of settings summarised on one row, its editor opened on demand: the
 * page stays a short list of what is set, and the detail is an overlay (owner
 * rules "do not cram", "one screen one job"). The button is named after the
 * row ("Change False positives") so every row's button has its own name.
 */
export function SettingsSummaryRow({
  label,
  summary,
  note,
  actionLabel,
  onAction,
  editor,
  id,
  className,
}: SettingsSummaryRowProps) {
  const auto = useId()
  const labelId = `${auto}-label`
  const hintId = `${auto}-hint`
  return (
    <SettingsRow
      id={id}
      className={className}
      label={label}
      labelId={labelId}
      hintId={hintId}
      hint={
        <>
          <span className="block">{summary}</span>
          {note && <span className="mt-0.5 block font-medium text-foreground">{note}</span>}
        </>
      }
    >
      <Button
        type="button"
        variant="outline"
        size="sm"
        data-editor={editor}
        aria-labelledby={`${auto}-action ${labelId}`}
        aria-describedby={hintId}
        onClick={onAction}
      >
        <span id={`${auto}-action`}>{actionLabel}</span>
      </Button>
    </SettingsRow>
  )
}

/** A padded block of a framed section: a field grid, a status line, a note. */
export function SettingsBlock({
  children,
  className,
  id,
  divider = true,
}: {
  children: ReactNode
  className?: string
  id?: string
  /** False when the block continues the row above it (no line, no top padding). */
  divider?: boolean
}) {
  return (
    <div
      id={id}
      data-slot="settings-block"
      className={cn('flex min-w-0 flex-col gap-3 pb-4', divider && cn(DIVIDER, 'pt-4'), className)}
    >
      {children}
    </div>
  )
}

/** Fields side by side: as many columns as fit at 16.25rem, one below that. */
export function SettingsFieldGrid({
  children,
  className,
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'grid min-w-0 grid-cols-[repeat(auto-fit,minmax(min(100%,16.25rem),1fr))] items-start gap-x-4 gap-y-3',
        className
      )}
    >
      {children}
    </div>
  )
}

/** What a `SettingsField` hands its control: spread it on the kit input. */
export interface SettingsFieldControl {
  id: string
  'aria-describedby'?: string
  'aria-invalid'?: true
}

export interface SettingsFieldProps {
  label: string
  /** Help under the control. */
  hint?: ReactNode
  /** A validation message: shown under the control, announced, tied to it. */
  error?: ReactNode
  /** Why the field cannot be changed by this user ("Owner only"): a quiet mark beside the label. */
  lock?: string
  /** Use this id for the control instead of a generated one (in-page links, tests). */
  id?: string
  className?: string
  /** The control: spread the props it is given on the kit `Input` / `SelectTrigger`. */
  children: (control: SettingsFieldControl) => ReactNode
}

/**
 * One labelled field: label above, the control, then its hint and its error.
 * The label is tied to the control by id; the hint and the error are tied to
 * it with `aria-describedby`, and an error marks it `aria-invalid`.
 */
export function SettingsField({
  label,
  hint,
  error,
  lock,
  id,
  className,
  children,
}: SettingsFieldProps) {
  const auto = useId()
  const controlId = id ?? `${auto}-control`
  const hintId = `${controlId}-hint`
  const errorId = `${controlId}-error`
  const describedBy = [error ? errorId : null, hint ? hintId : null].filter(Boolean).join(' ')
  return (
    <div data-slot="settings-field" className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <label htmlFor={controlId} className="text-dense font-medium">
          {label}
        </label>
        {lock && (
          <span className="inline-flex items-center gap-1 text-cap text-muted-foreground">
            <Lock className="size-3 shrink-0" aria-hidden />
            {lock}
          </span>
        )}
      </div>
      {children({
        id: controlId,
        'aria-describedby': describedBy || undefined,
        'aria-invalid': error ? true : undefined,
      })}
      {error && (
        <p id={errorId} role="alert" className="text-cap font-medium text-destructive">
          {error}
        </p>
      )}
      {hint && (
        <p id={hintId} className="text-cap text-muted-foreground text-pretty">
          {hint}
        </p>
      )}
    </div>
  )
}

export interface SettingsValueProps extends Partial<SettingsFieldControl> {
  /** The saved value; empty shows "Not set". */
  value?: ReactNode
  /** Monospaced (an address, a key, a slug). */
  mono?: boolean
}

/**
 * A setting this user cannot change, shown as text in its field (the
 * `SettingsField` child for a reader): never a disabled input, which reads as
 * a control that is broken rather than a value.
 */
export function SettingsValue({
  value,
  mono,
  id,
  'aria-describedby': describedBy,
}: SettingsValueProps) {
  const { t } = useTranslation()
  const empty = value === undefined || value === null || value === ''
  return (
    <p
      id={id}
      aria-describedby={describedBy}
      data-slot="settings-value"
      className={cn(
        'flex min-h-9 min-w-0 items-center break-words text-body',
        mono && 'font-mono',
        empty && 'text-muted-foreground'
      )}
    >
      {empty ? t('settings.value.notSet', 'Not set') : value}
    </p>
  )
}
