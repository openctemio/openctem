'use client'

import { useEffect, useMemo, useState } from 'react'
import { AlertCircle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogForm,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  createFreezeWindow,
  invalidateFreezeWindowsCache,
  updateFreezeWindow,
} from '../api/use-freeze-windows'
import {
  WEEKDAYS,
  browserTimeZone,
  endsNextDay,
  timeZoneOptions,
  utcToZonedLocal,
  zonedLocalToUtc,
} from '../lib/schedule'
import type { FreezeRecurrence, FreezeWindow } from '../types'

export const MAX_FREEZE_NAME_LENGTH = 100
export const MAX_FREEZE_DESCRIPTION_LENGTH = 1000
const MAX_ONCE_MS = 31 * 24 * 60 * 60 * 1000

interface FreezeWindowDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Edit this window; omit to create one. */
  window?: FreezeWindow | null
  /** A new window freezes this zone; omit for the whole organization. */
  zoneId?: string
  /** The zone's name, for the description. */
  zoneName?: string
}

/** The form's validation errors; exported for tests. */
export function freezeFormErrors(f: {
  name: string
  description: string
  recurrence: FreezeRecurrence
  timezone: string
  startsLocal: string
  endsLocal: string
  days: number[]
  startTime: string
  endTime: string
  now?: Date
  creating: boolean
}): Record<string, string> {
  const errors: Record<string, string> = {}
  if (!f.name.trim()) errors.name = 'Name is required.'
  else if (f.name.trim().length > MAX_FREEZE_NAME_LENGTH)
    errors.name = `Name must be at most ${MAX_FREEZE_NAME_LENGTH} characters.`
  if (f.description.length > MAX_FREEZE_DESCRIPTION_LENGTH)
    errors.description = `Description must be at most ${MAX_FREEZE_DESCRIPTION_LENGTH} characters.`
  if (!f.timezone) errors.timezone = 'Pick a time zone.'
  if (f.recurrence === 'once') {
    const start = zonedLocalToUtc(f.startsLocal, f.timezone)
    const end = zonedLocalToUtc(f.endsLocal, f.timezone)
    if (!start) errors.starts = 'Pick when the window starts.'
    if (!end) errors.ends = 'Pick when the window ends.'
    if (start && end) {
      if (end.getTime() <= start.getTime()) errors.ends = 'The end must be after the start.'
      else if (end.getTime() - start.getTime() > MAX_ONCE_MS)
        errors.ends = 'A one-off window can last at most 31 days.'
      else if (f.creating && end.getTime() <= (f.now ?? new Date()).getTime())
        errors.ends = 'The window has already ended.'
    }
  } else {
    if (f.days.length === 0) errors.days = 'Pick at least one day.'
    if (!/^\d{2}:\d{2}$/.test(f.startTime)) errors.startTime = 'Pick a start time.'
    if (!/^\d{2}:\d{2}$/.test(f.endTime)) errors.endTime = 'Pick an end time.'
  }
  return errors
}

export function FreezeWindowDialog({
  open,
  onOpenChange,
  window: editWindow,
  zoneId,
  zoneName,
}: FreezeWindowDialogProps) {
  const editing = !!editWindow
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [timezone, setTimezone] = useState('UTC')
  const [recurrence, setRecurrence] = useState<FreezeRecurrence>('weekly')
  const [startsLocal, setStartsLocal] = useState('')
  const [endsLocal, setEndsLocal] = useState('')
  const [days, setDays] = useState<number[]>([6, 7])
  const [startTime, setStartTime] = useState('22:00')
  const [endTime, setEndTime] = useState('06:00')
  const [enabled, setEnabled] = useState(true)
  const [touched, setTouched] = useState(false)
  const [saving, setSaving] = useState(false)
  const [serverError, setServerError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    const tz = editWindow?.timezone ?? browserTimeZone()
    setName(editWindow?.name ?? '')
    setDescription(editWindow?.description ?? '')
    setTimezone(tz)
    setRecurrence((editWindow?.recurrence as FreezeRecurrence) ?? 'weekly')
    setStartsLocal(editWindow?.starts_at ? utcToZonedLocal(editWindow.starts_at, tz) : '')
    setEndsLocal(editWindow?.ends_at ? utcToZonedLocal(editWindow.ends_at, tz) : '')
    setDays(editWindow?.days?.length ? editWindow.days : [6, 7])
    setStartTime(editWindow?.start_time ?? '22:00')
    setEndTime(editWindow?.end_time ?? '06:00')
    setEnabled(editWindow?.enabled ?? true)
    setTouched(false)
    setServerError(null)
  }, [open, editWindow])

  const zones = useMemo(() => timeZoneOptions(timezone), [timezone])
  const errors = freezeFormErrors({
    name,
    description,
    recurrence,
    timezone,
    startsLocal,
    endsLocal,
    days,
    startTime,
    endTime,
    creating: !editing,
  })
  const show = (k: string) => (touched ? errors[k] : undefined)

  const toggleDay = (iso: number) =>
    setDays((d) => (d.includes(iso) ? d.filter((x) => x !== iso) : [...d, iso].sort()))

  const handleSave = async () => {
    setTouched(true)
    setServerError(null)
    if (Object.keys(errors).length > 0) return
    setSaving(true)
    try {
      const common = {
        name: name.trim(),
        description,
        timezone,
        recurrence,
        enabled,
      }
      const schedule =
        recurrence === 'once'
          ? {
              starts_at: zonedLocalToUtc(startsLocal, timezone)?.toISOString(),
              ends_at: zonedLocalToUtc(endsLocal, timezone)?.toISOString(),
            }
          : { days, start_time: startTime, end_time: endTime }
      if (editWindow) {
        await updateFreezeWindow(editWindow.id ?? '', { ...common, ...schedule })
        toast.success(`Freeze window "${common.name}" saved`)
      } else {
        await createFreezeWindow({ ...common, ...schedule, scan_zone_id: zoneId })
        toast.success(`Freeze window "${common.name}" created`)
      }
      await invalidateFreezeWindowsCache()
      onOpenChange(false)
    } catch (err) {
      setServerError(
        getErrorMessage(err, editing ? 'Failed to save the window' : 'Failed to create the window')
      )
    } finally {
      setSaving(false)
    }
  }

  const scopeText = zoneId
    ? `Active scans of zone ${zoneName ? `"${zoneName}"` : ''} are not dispatched while the window is active.`
    : 'No active scan of the organization is dispatched while the window is active.'

  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{editing ? 'Edit freeze window' : 'New freeze window'}</DialogTitle>
          <DialogDescription>
            {scopeText} Scheduled runs wait until it ends; passive discovery and imports continue.
          </DialogDescription>
        </DialogHeader>

        <DialogForm
          onSubmit={(e) => {
            e.preventDefault()
            void handleSave()
          }}
        >
          <DialogBody className="space-y-4">
            {serverError && (
              <Alert variant="destructive" role="alert" data-testid="freeze-server-error">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>{serverError}</AlertTitle>
              </Alert>
            )}

            <div className="space-y-1.5">
              <Label htmlFor="freeze-name">Name</Label>
              <Input
                id="freeze-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Weekend patching"
                aria-invalid={!!show('name')}
              />
              {show('name') && <p className="text-sm text-destructive">{show('name')}</p>}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="freeze-description">Description</Label>
              <Textarea
                id="freeze-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                aria-invalid={!!show('description')}
              />
              {show('description') && (
                <p className="text-sm text-destructive">{show('description')}</p>
              )}
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="freeze-recurrence">Repeats</Label>
                <Select
                  value={recurrence}
                  onValueChange={(v) => setRecurrence(v as FreezeRecurrence)}
                >
                  <SelectTrigger id="freeze-recurrence">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="weekly">Every week</SelectItem>
                    <SelectItem value="once">Once</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="freeze-timezone">Time zone</Label>
                <Select value={timezone} onValueChange={setTimezone}>
                  <SelectTrigger id="freeze-timezone" aria-invalid={!!show('timezone')}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="max-h-72">
                    {zones.map((z) => (
                      <SelectItem key={z} value={z}>
                        {z}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {recurrence === 'once' ? (
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="freeze-starts">Starts</Label>
                  <Input
                    id="freeze-starts"
                    type="datetime-local"
                    value={startsLocal}
                    onChange={(e) => setStartsLocal(e.target.value)}
                    aria-invalid={!!show('starts')}
                  />
                  {show('starts') && <p className="text-sm text-destructive">{show('starts')}</p>}
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="freeze-ends">Ends</Label>
                  <Input
                    id="freeze-ends"
                    type="datetime-local"
                    value={endsLocal}
                    onChange={(e) => setEndsLocal(e.target.value)}
                    aria-invalid={!!show('ends')}
                  />
                  {show('ends') && <p className="text-sm text-destructive">{show('ends')}</p>}
                </div>
              </div>
            ) : (
              <>
                <fieldset className="space-y-1.5">
                  <legend className="text-sm font-medium">Days</legend>
                  <div className="flex flex-wrap gap-1.5">
                    {WEEKDAYS.map((d) => (
                      <Button
                        key={d.iso}
                        type="button"
                        size="sm"
                        variant={days.includes(d.iso) ? 'default' : 'outline'}
                        aria-pressed={days.includes(d.iso)}
                        aria-label={d.long}
                        onClick={() => toggleDay(d.iso)}
                      >
                        {d.short}
                      </Button>
                    ))}
                  </div>
                  {show('days') && <p className="text-sm text-destructive">{show('days')}</p>}
                </fieldset>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label htmlFor="freeze-start-time">From</Label>
                    <Input
                      id="freeze-start-time"
                      type="time"
                      value={startTime}
                      onChange={(e) => setStartTime(e.target.value)}
                      aria-invalid={!!show('startTime')}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="freeze-end-time">Until</Label>
                    <Input
                      id="freeze-end-time"
                      type="time"
                      value={endTime}
                      onChange={(e) => setEndTime(e.target.value)}
                      aria-invalid={!!show('endTime')}
                    />
                  </div>
                </div>
                {/^\d{2}:\d{2}$/.test(startTime) &&
                  /^\d{2}:\d{2}$/.test(endTime) &&
                  endsNextDay(startTime, endTime) && (
                    <p className="text-sm text-muted-foreground" data-testid="freeze-next-day">
                      {startTime === endTime
                        ? 'The window lasts 24 hours from the start time on each day picked.'
                        : 'The window runs past midnight and ends the next day.'}
                    </p>
                  )}
              </>
            )}

            <div className="flex items-center justify-between rounded-md border p-3">
              <div>
                <Label htmlFor="freeze-enabled">Enabled</Label>
                <p className="text-sm text-muted-foreground">
                  A disabled window holds nothing and releases what it held.
                </p>
              </div>
              <Switch id="freeze-enabled" checked={enabled} onCheckedChange={setEnabled} />
            </div>
          </DialogBody>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={saving}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={saving}>
              {saving && <Loader2 className="h-4 w-4 animate-spin" />}
              {editing ? 'Save' : 'Create window'}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
