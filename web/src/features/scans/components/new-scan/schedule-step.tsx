/**
 * Schedule Step
 *
 * When the scan runs: now, or later — once at a date and time, or daily,
 * weekly or monthly — in a timezone (the viewer's by default). The next runs
 * come from the API's own schedule code (SchedulePreview).
 */

'use client'

import { useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { FormField, FormRow, FormStack } from '@/features/shared/components/forms'
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
import { Permission, useHasPermission } from '@/lib/permissions'
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
  // Creating a scan needs scans:write, running it needs scans:execute. Without
  // the second, "Run now" would always end as created-but-refused, so it is
  // off and the scan is saved without running.
  const canExecute = useHasPermission(Permission.ScansExecute)
  const runNowBlocked = !canExecute
  const { runImmediately } = schedule
  useEffect(() => {
    if (runNowBlocked && runImmediately) {
      onChange({ schedule: { ...schedule, runImmediately: false, saveOnly: offerSaveOnly } })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the blocked default needs correcting
  }, [runNowBlocked, runImmediately, offerSaveOnly])

  // A stored cron or RRULE schedule: shown as it is and kept, unless the
  // user replaces it with one of the frequencies.
  if (schedule.custom) {
    return (
      <FormStack className="px-4 py-4 sm:px-6" data-testid="custom-schedule">
        <FormField group label={t('scans.schedule.whenToRun')}>
          <div className="space-y-2 rounded-lg border border-primary bg-primary/5 p-4">
            <p className="font-medium">
              {t(
                schedule.custom.type === 'crontab'
                  ? 'scans.schedule.customCron'
                  : 'scans.schedule.customRRule'
              )}
            </p>
            <code className="block break-all rounded bg-muted px-2 py-1 text-xs">
              {schedule.custom.expression}
            </code>
            <p className="text-xs text-muted-foreground">
              {t('scans.schedule.customKept', undefined, { timezone })}
            </p>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => set({ custom: undefined, frequency: 'weekly' })}
            >
              {t('scans.schedule.customReplace')}
            </Button>
          </div>
        </FormField>
      </FormStack>
    )
  }

  return (
    <FormStack className="px-4 py-4 sm:px-6">
      <FormField group label={t('scans.schedule.whenToRun')}>
        <RadioGroup
          value={schedule.runImmediately ? 'now' : schedule.saveOnly ? 'save' : 'later'}
          onValueChange={(value) =>
            set({ runImmediately: value === 'now', saveOnly: value === 'save' })
          }
          className="grid grid-cols-1 gap-2 sm:grid-cols-[repeat(auto-fit,minmax(13rem,1fr))]"
        >
          <label
            htmlFor="run-now"
            className={cn(
              'flex items-start gap-2.5 rounded-lg border border-input p-3 has-[[data-state=checked]]:border-foreground has-[[data-state=checked]]:bg-foreground/5',
              runNowBlocked ? 'cursor-not-allowed opacity-60' : 'cursor-pointer hover:bg-muted/50'
            )}
          >
            <RadioGroupItem value="now" id="run-now" disabled={runNowBlocked} className="mt-0.5" />
            <span className="min-w-0">
              <span className="block text-body font-medium">{t('scans.schedule.now')}</span>
              {runNowBlocked && (
                <span className="block text-dense text-muted-foreground">
                  {t(
                    'scanDetail.newScan.runNowNeedsExecute',
                    'You can create scans but not run them. Ask an administrator for the scans:execute permission.'
                  )}
                </span>
              )}
            </span>
          </label>

          <label
            htmlFor="run-later"
            className="flex cursor-pointer items-start gap-2.5 rounded-lg border border-input p-3 hover:bg-muted/50 has-[[data-state=checked]]:border-foreground has-[[data-state=checked]]:bg-foreground/5"
          >
            <RadioGroupItem value="later" id="run-later" className="mt-0.5" />
            <span className="min-w-0 text-body font-medium">{t('scans.schedule.later')}</span>
          </label>

          {offerSaveOnly && (
            <label
              htmlFor="run-save"
              className="flex cursor-pointer items-start gap-2.5 rounded-lg border border-input p-3 hover:bg-muted/50 has-[[data-state=checked]]:border-foreground has-[[data-state=checked]]:bg-foreground/5"
            >
              <RadioGroupItem value="save" id="run-save" className="mt-0.5" />
              <span className="min-w-0">
                <span className="block text-body font-medium">{t('scans.schedule.saveOnly')}</span>
                <span className="block text-dense text-muted-foreground">
                  {t('scans.schedule.saveOnlyHint')}
                </span>
              </span>
            </label>
          )}
        </RadioGroup>

        {later && (
          <FormRow>
            <FormField id="frequency" label={t('scans.schedule.frequency')}>
              {(control) => (
                <Select
                  value={frequency}
                  onValueChange={(value: ScheduleFrequency) => set({ frequency: value })}
                >
                  <SelectTrigger {...control} className="w-full">
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
              )}
            </FormField>

            <FormField id="schedule-timezone" label={t('scans.schedule.timezone')}>
              {(control) => (
                <TimezoneSelect
                  {...control}
                  value={timezone}
                  onChange={(zone) => set({ timezone: zone })}
                />
              )}
            </FormField>

            {frequency === 'once' && (
              <>
                <FormField id="run-at-date" label={t('scans.schedule.date')}>
                  {(control) => (
                    <Input
                      {...control}
                      aria-describedby={problem ? 'schedule-problem' : undefined}
                      type="date"
                      min={todayIn(timezone)}
                      value={schedule.runAtDate ?? ''}
                      onChange={(e) => set({ runAtDate: e.target.value })}
                      aria-invalid={problem ? true : undefined}
                    />
                  )}
                </FormField>
                <FormField id="run-at-time" label={t('scans.schedule.time')}>
                  {(control) => (
                    <Input
                      {...control}
                      aria-describedby={problem ? 'schedule-problem' : undefined}
                      type="time"
                      value={schedule.runAtTime ?? ''}
                      onChange={(e) => set({ runAtTime: e.target.value })}
                      aria-invalid={problem ? true : undefined}
                    />
                  )}
                </FormField>
              </>
            )}

            {frequency === 'weekly' && (
              <FormField id="day" label={t('scans.schedule.day')}>
                {(control) => (
                  <Select
                    value={schedule.dayOfWeek?.toString()}
                    onValueChange={(v) => set({ dayOfWeek: parseInt(v, 10) })}
                  >
                    <SelectTrigger {...control} className="w-full">
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
                )}
              </FormField>
            )}

            {frequency === 'monthly' && (
              <FormField
                id="day-of-month"
                label={t('scans.schedule.dayOfMonth')}
                hint={(schedule.dayOfMonth ?? 1) > 28 ? t('scans.schedule.shortMonth') : undefined}
              >
                {(control) => (
                  <Select
                    value={(schedule.dayOfMonth ?? 1).toString()}
                    onValueChange={(v) => set({ dayOfMonth: parseInt(v, 10) })}
                  >
                    <SelectTrigger {...control} className="w-full">
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
                )}
              </FormField>
            )}

            {frequency !== 'once' && (
              <FormField id="time" label={t('scans.schedule.time')}>
                <Input
                  type="time"
                  step={900}
                  value={schedule.time ?? ''}
                  onChange={(e) => set({ time: e.target.value })}
                />
              </FormField>
            )}
          </FormRow>
        )}

        {later && problem && (
          <p id="schedule-problem" role="alert" className="text-dense font-medium text-destructive">
            {problem}
          </p>
        )}
        {later && !problem && (
          <div className="rounded-lg border p-4">
            <SchedulePreview
              request={schedulePreviewRequestFromForm(data)}
              title={frequency === 'once' ? t('scans.schedule.runsOnce') : undefined}
            />
          </div>
        )}
      </FormField>
    </FormStack>
  )
}
