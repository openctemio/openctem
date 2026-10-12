/**
 * Schedule Step
 *
 * When the scan runs: now, or later — once at a date and time, or daily,
 * weekly or monthly — in a timezone (the viewer's by default). The next runs
 * come from the API's own schedule code (SchedulePreview).
 */

'use client'

import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { Input } from '@/components/ui/input'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import type { NewScanFormData, ScanSchedule, ScheduleFrequency } from '../../types'
import { FREQUENCY_OPTIONS, DAY_OPTIONS } from '../../types'
import { schedulePreviewRequestFromForm } from '../../lib/schedule-preview'
import { scheduleError } from '../../lib/scan-form'
import { viewerTimeZone } from '../../lib/zoned-time'
import { SchedulePreview } from '../schedule-preview'
import { TimezoneSelect } from '../timezone-select'

interface ScheduleStepProps {
  data: NewScanFormData
  onChange: (data: Partial<NewScanFormData>) => void
  /** A new one-off run must be ahead; an edit may keep one that has run. */
  requireFutureRun?: boolean
  /** Offer "Save without running" (a new scan). */
  offerSaveOnly?: boolean
}

const DAY_OF_MONTH_OPTIONS = Array.from({ length: 31 }, (_, i) => i + 1)

function todayIn(timeZone: string): string {
  try {
    return new Intl.DateTimeFormat('en-CA', { timeZone }).format(new Date())
  } catch {
    return new Date().toISOString().slice(0, 10)
  }
}

export function ScheduleStep({
  data,
  onChange,
  requireFutureRun = true,
  offerSaveOnly = false,
}: ScheduleStepProps) {
  const { t } = useTranslation()
  const schedule = data.schedule
  const timezone = schedule.timezone || viewerTimeZone()
  const set = (patch: Partial<ScanSchedule>) => onChange({ schedule: { ...schedule, ...patch } })
  const frequency = schedule.frequency ?? 'weekly'
  const problem = scheduleError(data, { requireFuture: requireFutureRun }, t)
  const later = !schedule.runImmediately && !schedule.saveOnly

  return (
    <div className="space-y-6 p-4">
      <div className="space-y-3">
        <Label>{t('scans.schedule.whenToRun')}</Label>
        <RadioGroup
          value={schedule.runImmediately ? 'now' : schedule.saveOnly ? 'save' : 'later'}
          onValueChange={(value) =>
            set({ runImmediately: value === 'now', saveOnly: value === 'save' })
          }
          className="space-y-3"
        >
          <label
            htmlFor="run-now"
            className={cn(
              'flex cursor-pointer items-center gap-3 rounded-lg border p-4 transition-colors',
              schedule.runImmediately
                ? 'border-primary bg-primary/5'
                : 'border-border hover:border-primary/50'
            )}
          >
            <RadioGroupItem value="now" id="run-now" />
            <span className="font-medium">{t('scans.schedule.now')}</span>
          </label>

          <div
            className={cn(
              'space-y-4 rounded-lg border p-4 transition-colors',
              !schedule.runImmediately && !schedule.saveOnly
                ? 'border-primary bg-primary/5'
                : 'border-border hover:border-primary/50'
            )}
          >
            <label htmlFor="run-later" className="flex cursor-pointer items-center gap-3">
              <RadioGroupItem value="later" id="run-later" />
              <span className="font-medium">{t('scans.schedule.later')}</span>
            </label>

            {later && (
              <div className="ms-6 grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="frequency" className="text-sm">
                    {t('scans.schedule.frequency')}
                  </Label>
                  <Select
                    value={frequency}
                    onValueChange={(value: ScheduleFrequency) => set({ frequency: value })}
                  >
                    <SelectTrigger id="frequency" className="w-full">
                      <SelectValue placeholder={t('scans.schedule.frequencyPlaceholder')} />
                    </SelectTrigger>
                    <SelectContent>
                      {FREQUENCY_OPTIONS.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {t(`scans.frequency.${option.value}`, option.label)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="schedule-timezone" className="text-sm">
                    {t('scans.schedule.timezone')}
                  </Label>
                  <TimezoneSelect
                    id="schedule-timezone"
                    value={timezone}
                    onChange={(zone) => set({ timezone: zone })}
                  />
                </div>

                {frequency === 'once' && (
                  <>
                    <div className="space-y-2">
                      <Label htmlFor="run-at-date" className="text-sm">
                        {t('scans.schedule.date')}
                      </Label>
                      <Input
                        id="run-at-date"
                        type="date"
                        min={todayIn(timezone)}
                        value={schedule.runAtDate ?? ''}
                        onChange={(e) => set({ runAtDate: e.target.value })}
                        aria-invalid={problem ? true : undefined}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="run-at-time" className="text-sm">
                        {t('scans.schedule.time')}
                      </Label>
                      <Input
                        id="run-at-time"
                        type="time"
                        value={schedule.runAtTime ?? ''}
                        onChange={(e) => set({ runAtTime: e.target.value })}
                        aria-invalid={problem ? true : undefined}
                      />
                    </div>
                  </>
                )}

                {frequency === 'weekly' && (
                  <div className="space-y-2">
                    <Label htmlFor="day" className="text-sm">
                      {t('scans.schedule.day')}
                    </Label>
                    <Select
                      value={schedule.dayOfWeek?.toString()}
                      onValueChange={(v) => set({ dayOfWeek: parseInt(v, 10) })}
                    >
                      <SelectTrigger id="day" className="w-full">
                        <SelectValue placeholder={t('scans.schedule.dayPlaceholder')} />
                      </SelectTrigger>
                      <SelectContent>
                        {DAY_OPTIONS.map((option) => (
                          <SelectItem key={option.value} value={option.value.toString()}>
                            {t(`scans.day.${option.value}`, option.label)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}

                {frequency === 'monthly' && (
                  <div className="space-y-2">
                    <Label htmlFor="day-of-month" className="text-sm">
                      {t('scans.schedule.dayOfMonth')}
                    </Label>
                    <Select
                      value={(schedule.dayOfMonth ?? 1).toString()}
                      onValueChange={(v) => set({ dayOfMonth: parseInt(v, 10) })}
                    >
                      <SelectTrigger id="day-of-month" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {DAY_OF_MONTH_OPTIONS.map((d) => (
                          <SelectItem key={d} value={d.toString()}>
                            {d}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {(schedule.dayOfMonth ?? 1) > 28 && (
                      <p className="text-xs text-muted-foreground">
                        {t('scans.schedule.shortMonth')}
                      </p>
                    )}
                  </div>
                )}

                {frequency !== 'once' && (
                  <div className="space-y-2">
                    <Label htmlFor="time" className="text-sm">
                      {t('scans.schedule.time')}
                    </Label>
                    <Input
                      id="time"
                      type="time"
                      step={900}
                      value={schedule.time ?? ''}
                      onChange={(e) => set({ time: e.target.value })}
                    />
                  </div>
                )}
              </div>
            )}

            {later && problem && (
              <p role="alert" className="ms-6 text-sm text-destructive">
                {problem}
              </p>
            )}
          </div>
          {offerSaveOnly && (
            <label
              htmlFor="run-save"
              className={cn(
                'flex cursor-pointer items-start gap-3 rounded-lg border p-4 transition-colors',
                schedule.saveOnly
                  ? 'border-primary bg-primary/5'
                  : 'border-border hover:border-primary/50'
              )}
            >
              <RadioGroupItem value="save" id="run-save" className="mt-0.5" />
              <span>
                <span className="block font-medium">{t('scans.schedule.saveOnly')}</span>
                <span className="text-muted-foreground block text-xs">
                  {t('scans.schedule.saveOnlyHint')}
                </span>
              </span>
            </label>
          )}
        </RadioGroup>
        {later && !problem && (
          <div className="mt-4 rounded-lg border p-4">
            <SchedulePreview
              request={schedulePreviewRequestFromForm(data)}
              title={frequency === 'once' ? t('scans.schedule.runsOnce') : undefined}
            />
          </div>
        )}
      </div>
    </div>
  )
}
