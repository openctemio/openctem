'use client'

import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import { Ban, Loader2, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogHeader,
  DialogBody,
  DialogFooter,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { DangerZone, DangerZoneItem } from '@/features/shared/components/danger-zone'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  assignSensorToZone,
  invalidateScanZonesCache,
  unassignSensorFromZone,
  useScanZones,
} from '@/lib/api/scan-zone-hooks'
import {
  invalidateSensorsCache,
  useDeleteSensor,
  useRevokeSensor,
  useUpdateSensor,
} from '@/lib/api/sensor-hooks'
import type { Sensor } from '@/lib/api/sensor-types'
import { Permission, useHasPermission } from '@/lib/permissions'
import { sensorActions } from '../lib/sensor-actions'

import { sensorCapacity } from '../lib/capabilities'
import { agoShort, type Tr } from '../lib/format'
import {
  isSensorEditDirty,
  MAX_JOBS_LIMIT,
  reportedToolNames,
  sensorEditDraft,
  sensorUpdateBody,
  validateSensorEdit,
  zoneChanges,
  type SensorEditDraft,
} from '../lib/sensor-edit'
import { normalizeSensorVersion } from '../lib/sensor-version'

import { ToggleChip } from './toggle-chip'

interface EditSensorDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  sensor: Sensor
  onSuccess?: () => void
  /** After the sensor was deleted from the danger zone. */
  onDeleted?: () => void
}

type Draft = Omit<SensorEditDraft, 'zoneIds'> & {
  /** null until the zones are edited: the sensor's current zones. */
  zoneIds: string[] | null
}

const EXECUTION_MODE_KEYS: Record<Sensor['execution_mode'], 'daemon' | 'standalone'> = {
  daemon: 'daemon',
  standalone: 'standalone',
}

function Section({
  title,
  description,
  children,
}: {
  title: string
  description?: string
  children: ReactNode
}) {
  const id = useId()
  return (
    <section aria-labelledby={id} className="space-y-4">
      <div className="space-y-0.5">
        <h3 id={id} className="text-base font-semibold">
          {title}
        </h3>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      {children}
    </section>
  )
}

function FieldError({ id, message }: { id: string; message?: string }) {
  if (!message) return null
  return (
    <p id={id} className="text-xs text-destructive">
      {message}
    </p>
  )
}

function lastSeen(at: string | undefined, tr: Tr): string {
  if (!at) return tr('sensors.edit.neverConnected')
  return agoShort(at, Date.now(), tr)
}

/** Read-only facts the sensor reports about itself. */
function AboutSensor({ sensor }: { sensor: Sensor }) {
  const { t } = useTranslation()
  const version = normalizeSensorVersion(sensor.version)
  const p = sensor.protocol
  const platform = [sensor.reported?.os, sensor.reported?.arch].filter(Boolean).join('/')
  const facts: { label: string; value: string }[] = [
    {
      label: t('sensors.edit.about.version'),
      value: version ?? t('sensors.edit.about.notReported'),
    },
    {
      label: t('sensors.edit.about.sdk'),
      value: normalizeSensorVersion(sensor.sdk_version) ?? '—',
    },
    {
      label: t('sensors.edit.about.protocol'),
      value: p
        ? `v${p.version}${p.deprecated || p.version < 2 ? ` (${t('sensors.edit.about.deprecated')})` : ''}`
        : '—',
    },
    { label: t('sensors.edit.about.platform'), value: platform || '—' },
    {
      label: t('sensors.edit.about.lastSeen'),
      value: lastSeen(sensor.last_seen_at, t),
    },
  ]
  return (
    <dl
      aria-label={t('sensors.edit.about.label')}
      className="flex flex-wrap gap-x-8 gap-y-3 rounded-lg border px-4 py-3"
    >
      {facts.map((f) => (
        <div key={f.label} className="min-w-0">
          <dt className="text-xs text-muted-foreground">{f.label}</dt>
          <dd className="text-sm font-medium break-words">{f.value}</dd>
        </div>
      ))}
    </dl>
  )
}

export function EditSensorDialog({
  open,
  onOpenChange,
  sensor,
  onSuccess,
  onDeleted,
}: EditSensorDialogProps) {
  const ids = {
    name: useId(),
    description: useId(),
    enabled: useId(),
    maxJobs: useId(),
    form: useId(),
  }
  const canDelete = useHasPermission(Permission.SensorsDelete)
  const canWrite = useHasPermission(Permission.SensorsWrite)
  const canRevoke = useHasPermission(Permission.SensorsRevoke)
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  const canWriteZones = useHasPermission(Permission.ScanZonesWrite)
  const { data: zonesData } = useScanZones(open && canReadZones)
  const zones = useMemo(() => zonesData?.data ?? [], [zonesData?.data])
  const sensorZoneIds = useMemo(
    () =>
      zones
        .filter((z) => z.sensor_ids.includes(sensor.id))
        .map((z) => z.id)
        .sort(),
    [zones, sensor.id]
  )

  const { trigger: updateSensor } = useUpdateSensor(sensor.id)
  const { trigger: revokeSensor, isMutating: isRevoking } = useRevokeSensor()
  const { trigger: deleteSensor, isMutating: isDeleting } = useDeleteSensor()

  const [base, setBase] = useState<Draft>(() => ({ ...sensorEditDraft(sensor), zoneIds: null }))
  const [draft, setDraft] = useState<Draft>(base)
  const [saving, setSaving] = useState(false)
  const [discardOpen, setDiscardOpen] = useState(false)
  const { t } = useTranslation()
  const [revokeOpen, setRevokeOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  // Reset when the dialog opens or another sensor is edited, but not when the
  // same sensor is refetched while open (that would wipe the user's edits).
  const latest = useRef(sensor)
  useEffect(() => {
    latest.current = sensor
  })
  const sensorId = sensor.id
  useEffect(() => {
    if (!open) return
    const next: Draft = { ...sensorEditDraft(latest.current), zoneIds: null }
    setBase(next)
    setDraft(next)
  }, [open, sensorId])

  const initial: SensorEditDraft = { ...base, zoneIds: sensorZoneIds }
  const current: SensorEditDraft = { ...draft, zoneIds: draft.zoneIds ?? sensorZoneIds }
  const dirty = isSensorEditDirty(current, initial)
  const errors = validateSensorEdit(current, initial, t)
  const hasErrors = Object.keys(errors).length > 0

  const reported = reportedToolNames(sensor)
  const reportedVersions = new Map(
    (sensor.reported?.tools ?? []).filter((x) => x.installed).map((x) => [x.name, x.version])
  )
  const capacity = sensorCapacity(sensor)
  const revoked = sensor.status === 'revoked'
  const can = sensorActions(sensor, { write: canWrite, revoke: canRevoke, delete: canDelete })
  const modeKey = EXECUTION_MODE_KEYS[sensor.execution_mode] ?? 'daemon'
  const busy = saving || isRevoking || isDeleting

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) =>
    setDraft((d) => ({ ...d, [key]: value }))

  const close = () => onOpenChange(false)
  const requestClose = () => {
    if (busy) return
    if (dirty && !revoked) setDiscardOpen(true)
    else close()
  }

  const handleSave = async () => {
    if (!dirty || hasErrors || revoked) return
    setSaving(true)
    try {
      const body = sensorUpdateBody(current, initial)
      if (Object.keys(body).length > 0) await updateSensor(body)
      const { join, leave } = zoneChanges(current, initial)
      if (join.length || leave.length) {
        await Promise.all([
          ...join.map((z) => assignSensorToZone(z, sensor.id)),
          ...leave.map((z) => unassignSensorFromZone(z, sensor.id)),
        ])
        await invalidateScanZonesCache()
      }
      toast.success(t('sensors.edit.updated', undefined, { name: current.name.trim() }))
      await invalidateSensorsCache()
      close()
      onSuccess?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.edit.updateFailed')))
    } finally {
      setSaving(false)
    }
  }

  const handleRevoke = async () => {
    try {
      await revokeSensor(sensor.id)
      toast.success(t('sensors.edit.revoked', undefined, { name: sensor.name }))
      await invalidateSensorsCache()
      setRevokeOpen(false)
      close()
      onSuccess?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.edit.revokeFailed')))
    }
  }

  const handleDelete = async () => {
    try {
      await deleteSensor(sensor.id)
      toast.success(t('sensors.edit.deleted', undefined, { name: sensor.name }))
      await invalidateSensorsCache()
      setDeleteOpen(false)
      close()
      onDeleted?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.edit.deleteFailed')))
    }
  }

  const descriptionCleared = !!base.description && current.description.trim() === ''

  return (
    <>
      <Dialog open={open} onOpenChange={(o) => (o ? onOpenChange(true) : requestClose())}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>{t('sensors.edit.title')}</DialogTitle>
            <DialogDescription className="truncate">{sensor.name}</DialogDescription>
          </DialogHeader>

          <DialogBody className="py-5">
            <form
              id={ids.form}
              className="space-y-8"
              onSubmit={(e) => {
                e.preventDefault()
                void handleSave()
              }}
            >
              <AboutSensor sensor={sensor} />

              {revoked ? (
                <Alert>
                  <Ban className="h-4 w-4" aria-hidden />
                  <AlertTitle>{t('sensors.edit.revokedTitle')}</AlertTitle>
                  <AlertDescription>{t('sensors.edit.revokedBody')}</AlertDescription>
                </Alert>
              ) : (
                <>
                  <Section title={t('sensors.edit.general')}>
                    <div className="space-y-1.5">
                      <Label htmlFor={ids.name}>{t('sensors.edit.name')}</Label>
                      <Input
                        id={ids.name}
                        value={draft.name}
                        onChange={(e) => set('name', e.target.value)}
                        autoComplete="off"
                        aria-invalid={!!errors.name}
                        aria-describedby={errors.name ? `${ids.name}-error` : undefined}
                      />
                      <FieldError id={`${ids.name}-error`} message={errors.name} />
                    </div>

                    <div className="space-y-1.5">
                      <Label htmlFor={ids.description}>
                        {t('sensors.edit.description')}{' '}
                        <span className="font-normal text-muted-foreground">
                          ({t('sensors.edit.optional')})
                        </span>
                      </Label>
                      <Textarea
                        id={ids.description}
                        value={draft.description}
                        onChange={(e) => set('description', e.target.value)}
                        placeholder={t('sensors.edit.descriptionPlaceholder')}
                        className="resize-none"
                        rows={2}
                        aria-invalid={!!errors.description}
                      />
                      <FieldError id={`${ids.description}-error`} message={errors.description} />
                      {descriptionCleared && (
                        <p className="text-xs text-muted-foreground">
                          {t('sensors.edit.descriptionCleared')}
                        </p>
                      )}
                    </div>

                    <div className="flex items-start justify-between gap-4 rounded-lg border p-3">
                      <div className="space-y-0.5">
                        <Label htmlFor={ids.enabled}>{t('sensors.edit.enabled')}</Label>
                        <p className="text-sm text-muted-foreground">
                          {t('sensors.edit.enabledHelp')}
                        </p>
                      </div>
                      <Switch
                        id={ids.enabled}
                        checked={draft.enabled}
                        onCheckedChange={(v) => set('enabled', v)}
                      />
                    </div>
                  </Section>

                  <Section title={t('sensors.edit.work')} description={t('sensors.edit.workHelp')}>
                    <div className="space-y-1">
                      <p className="text-sm font-medium">{t('sensors.edit.executionMode')}</p>
                      <p className="text-sm text-muted-foreground">
                        <span className="text-foreground">
                          {t(`sensors.edit.mode.${modeKey}.label`)}
                        </span>
                        : {t(`sensors.edit.mode.${modeKey}.text`)}. {t('sensors.edit.modeSetBy')}
                      </p>
                    </div>

                    <div className="space-y-2">
                      <p className="text-sm font-medium">{t('sensors.edit.tools')}</p>
                      {reported == null ? (
                        <p className="text-sm text-muted-foreground">
                          {t('sensors.edit.toolsNotReported')}
                        </p>
                      ) : reported.length === 0 ? (
                        <p className="text-sm text-muted-foreground">
                          {t('sensors.edit.toolsNone')}
                        </p>
                      ) : (
                        <>
                          <p className="text-sm text-muted-foreground">
                            {t('sensors.edit.toolsHelp')}
                          </p>
                          <ul
                            className="flex flex-wrap gap-2 pt-1"
                            aria-label={t('sensors.edit.toolsReported')}
                          >
                            {reported.map((tool) => {
                              const v = reportedVersions.get(tool)
                              return (
                                <li
                                  key={tool}
                                  className="rounded-full border bg-muted/50 px-3 py-1 text-sm"
                                >
                                  {v ? `${tool} ${v}` : tool}
                                </li>
                              )
                            })}
                          </ul>
                        </>
                      )}
                    </div>

                    <div className="space-y-1.5">
                      <Label htmlFor={ids.maxJobs}>{t('sensors.edit.maxJobs')}</Label>
                      <p className="text-sm text-muted-foreground">
                        {capacity.reported != null
                          ? t(
                              capacity.reported === 1
                                ? 'sensors.edit.slotsReported.one'
                                : 'sensors.edit.slotsReported.other',
                              undefined,
                              { count: capacity.reported }
                            )
                          : t('sensors.edit.slotsUnknown')}{' '}
                        {t('sensors.edit.maxJobsHelp')}
                      </p>
                      <div className="flex items-center gap-3">
                        <Input
                          id={ids.maxJobs}
                          type="number"
                          inputMode="numeric"
                          min={1}
                          max={MAX_JOBS_LIMIT}
                          value={draft.maxJobs}
                          onChange={(e) => set('maxJobs', e.target.value)}
                          className="w-24 tabular-nums"
                          aria-invalid={!!errors.maxJobs}
                          aria-describedby={errors.maxJobs ? `${ids.maxJobs}-error` : undefined}
                        />
                        <span className="text-sm text-muted-foreground tabular-nums">
                          {t('sensors.edit.nowAtOnce', undefined, { count: capacity.effective })}
                        </span>
                      </div>
                      <FieldError id={`${ids.maxJobs}-error`} message={errors.maxJobs} />
                    </div>

                    {canReadZones && zones.length > 0 && (
                      <fieldset className="space-y-2">
                        <legend className="text-sm font-medium">{t('sensors.edit.zones')}</legend>
                        <p className="text-sm text-muted-foreground">
                          {t('sensors.edit.zonesHelp')}
                        </p>
                        <div className="flex flex-wrap gap-2">
                          {zones.map((z) => {
                            const on = current.zoneIds.includes(z.id)
                            return (
                              <ToggleChip
                                key={z.id}
                                pressed={on}
                                disabled={!canWriteZones}
                                onToggle={() =>
                                  set(
                                    'zoneIds',
                                    on
                                      ? current.zoneIds.filter((x) => x !== z.id)
                                      : [...current.zoneIds, z.id].sort()
                                  )
                                }
                              >
                                {z.name}
                              </ToggleChip>
                            )
                          })}
                        </div>
                      </fieldset>
                    )}
                  </Section>
                </>
              )}

              {(can.revoke || can.delete) && (
                <DangerZone as="h3">
                  {can.revoke && (
                    <DangerZoneItem
                      title={t('sensors.edit.revokeAccess')}
                      description={t('sensors.edit.revokeAccessHelp')}
                      action={
                        <Button
                          type="button"
                          variant="destructive"
                          size="sm"
                          onClick={() => setRevokeOpen(true)}
                          disabled={busy}
                        >
                          <Ban className="h-4 w-4" aria-hidden />
                          {t('sensors.edit.revoke')}
                        </Button>
                      }
                    />
                  )}
                  {can.delete && (
                    <DangerZoneItem
                      title={t('sensors.edit.deleteSensor')}
                      description={t('sensors.edit.deleteSensorHelp')}
                      action={
                        <Button
                          type="button"
                          variant="destructive"
                          size="sm"
                          onClick={() => setDeleteOpen(true)}
                          disabled={busy}
                        >
                          <Trash2 className="h-4 w-4" aria-hidden />
                          {t('sensors.edit.delete')}
                        </Button>
                      }
                    />
                  )}
                </DangerZone>
              )}
            </form>
          </DialogBody>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={requestClose} disabled={busy}>
              {revoked ? t('sensors.edit.close') : t('common.cancel')}
            </Button>
            {!revoked && (
              <Button type="submit" form={ids.form} disabled={!dirty || hasErrors || busy}>
                {saving && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
                {t('sensors.edit.save')}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={discardOpen}
        onOpenChange={setDiscardOpen}
        title={t('confirm.discardTitle', 'Discard your changes?')}
        desc={t('confirm.sensor.discardDesc', 'Your changes to this sensor have not been saved.')}
        cancelBtnText={t('confirm.keepEditing', 'Keep editing')}
        confirmText={t('confirm.discard', 'Discard')}
        destructive
        handleConfirm={() => {
          setDiscardOpen(false)
          close()
        }}
      />

      <ConfirmDialog
        open={revokeOpen}
        onOpenChange={setRevokeOpen}
        title={t('confirm.sensor.revokeTitle', 'Revoke the sensor {name}?', { name: sensor.name })}
        desc={
          <div className="space-y-2">
            <p>
              {t(
                'confirm.sensor.revokeDesc',
                'It loses access at once and for good: its key is revoked and it cannot be re-enabled. To use the machine again, enroll a new sensor. This cannot be undone.'
              )}
            </p>
            <p>{t('confirm.sensor.revokePauseHint', 'To pause it instead, turn off Enabled.')}</p>
          </div>
        }
        confirmText={t('confirm.revoke', 'Revoke')}
        destructive
        isLoading={isRevoking}
        typeToConfirm={sensor.name}
        handleConfirm={handleRevoke}
      />

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={t('confirm.sensor.deleteTitle', 'Delete the sensor {name}?', { name: sensor.name })}
        desc={t(
          'confirm.sensor.deleteDesc',
          'Its API key stops working at once and it can no longer claim jobs or send results. Findings it reported stay. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        isLoading={isDeleting}
        typeToConfirm={sensor.name}
        handleConfirm={handleDelete}
      />
    </>
  )
}
