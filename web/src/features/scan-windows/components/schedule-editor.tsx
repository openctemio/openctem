'use client'

/**
 * The windows of a policy: weekly slots (days, start and end in the
 * policy's time zone; an end not after the start runs past midnight, equal
 * times are 24 hours) and dated one-off windows.
 */

import { Plus, Trash2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'

import {
  MAX_ONE_OFFS,
  MAX_SLOTS,
  oneOffEnded,
  type OneOffDraft,
  type SlotDraft,
} from '../lib/policy-form'
import { HHMM, WEEKDAYS, dayLong, dayShort, endsNextDay } from '../lib/schedule'

interface SlotsEditorProps {
  slots: SlotDraft[]
  onChange: (slots: SlotDraft[]) => void
  errors: Record<string, string | undefined>
  disabled?: boolean
}

export function SlotsEditor({ slots, onChange, errors, disabled }: SlotsEditorProps) {
  const { t } = useTranslation()
  const update = (i: number, patch: Partial<SlotDraft>) =>
    onChange(slots.map((s, j) => (j === i ? { ...s, ...patch } : s)))
  return (
    <fieldset className="space-y-2" disabled={disabled}>
      <legend className="text-sm font-medium">
        {t('scanWindows.form.weekly', 'Weekly windows')}
      </legend>
      {slots.length === 0 && (
        <p className="text-xs text-muted-foreground">
          {t('scanWindows.form.noWeekly', 'No weekly windows.')}
        </p>
      )}
      {slots.map((s, i) => {
        const n = i + 1
        const overnight = HHMM.test(s.start) && HHMM.test(s.end) && endsNextDay(s.start, s.end)
        return (
          <div key={i} className="space-y-2 rounded-md border p-3" data-testid="slot-row">
            <div
              className="flex flex-wrap gap-1"
              role="group"
              aria-label={t('scanWindows.form.slotDays', 'Days of window {n}', { n })}
            >
              {WEEKDAYS.map((d) => {
                const on = s.days.includes(d.iso)
                return (
                  <Button
                    key={d.iso}
                    type="button"
                    size="sm"
                    variant={on ? 'default' : 'outline'}
                    className="h-8 px-2.5"
                    aria-pressed={on}
                    aria-label={dayLong(d.iso, t)}
                    onClick={() =>
                      update(i, {
                        days: on
                          ? s.days.filter((x) => x !== d.iso)
                          : [...s.days, d.iso].sort((a, b) => a - b),
                      })
                    }
                  >
                    {dayShort(d.iso, t)}
                  </Button>
                )
              })}
            </div>
            <div className="flex flex-wrap items-end gap-3">
              <div className="space-y-1">
                <Label htmlFor={`slot-start-${i}`} className="text-xs">
                  {t('scanWindows.form.from', 'From')}
                </Label>
                <Input
                  id={`slot-start-${i}`}
                  type="time"
                  className="w-32"
                  value={s.start}
                  onChange={(e) => update(i, { start: e.target.value })}
                  aria-invalid={!!errors[`slots.${i}`]}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor={`slot-end-${i}`} className="text-xs">
                  {t('scanWindows.form.until', 'Until')}
                </Label>
                <Input
                  id={`slot-end-${i}`}
                  type="time"
                  className="w-32"
                  value={s.end}
                  onChange={(e) => update(i, { end: e.target.value })}
                  aria-invalid={!!errors[`slots.${i}`]}
                />
              </div>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="ms-auto"
                aria-label={t('scanWindows.form.removeSlot', 'Remove weekly window {n}', { n })}
                onClick={() => onChange(slots.filter((_, j) => j !== i))}
              >
                <Trash2 className="h-4 w-4" aria-hidden />
              </Button>
            </div>
            {overnight && (
              <p className="text-xs text-muted-foreground" data-testid="slot-overnight">
                {s.start === s.end
                  ? t(
                      'scanWindows.form.allDay',
                      'Lasts 24 hours from the start time on each day picked.'
                    )
                  : t('scanWindows.form.overnight', 'Runs past midnight and ends the next day.')}
              </p>
            )}
            {errors[`slots.${i}`] && (
              <p className="text-xs text-destructive">{errors[`slots.${i}`]}</p>
            )}
          </div>
        )
      })}
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={slots.length >= MAX_SLOTS}
        onClick={() =>
          onChange([...slots, { days: [1, 2, 3, 4, 5], start: '09:00', end: '17:00' }])
        }
      >
        <Plus className="h-4 w-4" aria-hidden />
        {t('scanWindows.form.addSlot', 'Add weekly window')}
      </Button>
    </fieldset>
  )
}

interface OneOffsEditorProps {
  oneOffs: OneOffDraft[]
  timezone: string
  onChange: (oneOffs: OneOffDraft[]) => void
  errors: Record<string, string | undefined>
  disabled?: boolean
}

export function OneOffsEditor({
  oneOffs,
  timezone,
  onChange,
  errors,
  disabled,
}: OneOffsEditorProps) {
  const { t } = useTranslation()
  const update = (i: number, patch: Partial<OneOffDraft>) =>
    onChange(oneOffs.map((o, j) => (j === i ? { ...o, ...patch } : o)))
  return (
    <fieldset className="space-y-2" disabled={disabled}>
      <legend className="text-sm font-medium">
        {t('scanWindows.form.dated', 'Dated windows')}
      </legend>
      <p className="text-xs text-muted-foreground">
        {t(
          'scanWindows.form.datedHint',
          'One-off windows, at most 31 days each, in the time zone above.'
        )}
      </p>
      {oneOffs.map((o, i) => {
        const n = i + 1
        return (
          <div key={i} className="space-y-1 rounded-md border p-3" data-testid="one-off-row">
            <div className="flex flex-wrap items-end gap-3">
              <div className="space-y-1">
                <Label htmlFor={`oneoff-start-${i}`} className="text-xs">
                  {t('scanWindows.form.starts', 'Starts')}
                </Label>
                <Input
                  id={`oneoff-start-${i}`}
                  type="datetime-local"
                  value={o.startsLocal}
                  onChange={(e) => update(i, { startsLocal: e.target.value })}
                  aria-invalid={!!errors[`oneOffs.${i}`]}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor={`oneoff-end-${i}`} className="text-xs">
                  {t('scanWindows.form.ends', 'Ends')}
                </Label>
                <Input
                  id={`oneoff-end-${i}`}
                  type="datetime-local"
                  value={o.endsLocal}
                  onChange={(e) => update(i, { endsLocal: e.target.value })}
                  aria-invalid={!!errors[`oneOffs.${i}`]}
                />
              </div>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="ms-auto"
                aria-label={t('scanWindows.form.removeOneOff', 'Remove dated window {n}', { n })}
                onClick={() => onChange(oneOffs.filter((_, j) => j !== i))}
              >
                <Trash2 className="h-4 w-4" aria-hidden />
              </Button>
            </div>
            {errors[`oneOffs.${i}`] ? (
              <p className="text-xs text-destructive">{errors[`oneOffs.${i}`]}</p>
            ) : (
              oneOffEnded(o, timezone) && (
                <p className="text-xs text-muted-foreground">
                  {t('scanWindows.form.ended', 'This window has ended; it no longer applies.')}
                </p>
              )
            )}
          </div>
        )
      })}
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={oneOffs.length >= MAX_ONE_OFFS}
        onClick={() => onChange([...oneOffs, { startsLocal: '', endsLocal: '' }])}
      >
        <Plus className="h-4 w-4" aria-hidden />
        {t('scanWindows.form.addOneOff', 'Add dated window')}
      </Button>
    </fieldset>
  )
}
