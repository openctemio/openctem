'use client'

/**
 * System > Platform scanning: instance scan zones (RFC-100 §6.1). A zone is
 * a set of private ranges, the shared sensors that serve it and the
 * organizations it is assigned to: an organization's internal targets go to
 * shared sensors only inside a zone assigned to it, and only while "Shared
 * sensors may scan internal zones" is on. Any administrator sees the zones;
 * a super admin changes them with a reason and an authenticator code.
 */

import { useId, useState, type FormEvent } from 'react'
import { Loader2, Plus } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '@console/lib/admin-api/client'
import {
  createInstanceScanZone,
  deleteInstanceScanZone,
  setInstanceScanZoneOrganizations,
  setInstanceScanZoneSensors,
  updateInstanceScanZone,
  type InstanceScanZone,
} from '../api/use-instance-scan-zones'

/** Splits a textarea into trimmed, non-empty, distinct lines. */
export function lines(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean)
    )
  )
}

function sameSet(a: string[], b: string[]) {
  return a.length === b.length && a.every((v) => b.includes(v))
}

export interface InstanceScanZonesCardProps {
  zones: InstanceScanZone[]
  canEdit: boolean
  onChanged: () => Promise<unknown> | void
}

export function InstanceScanZonesCard({ zones, canEdit, onChanged }: InstanceScanZonesCardProps) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState<InstanceScanZone | 'new' | null>(null)

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 space-y-1.5">
            <CardTitle>{t('admin.instanceZones.title')}</CardTitle>
            <CardDescription>{t('admin.instanceZones.desc')}</CardDescription>
          </div>
          {canEdit && (
            <Button size="sm" onClick={() => setEditing('new')}>
              <Plus className="me-2 size-4" />
              {t('admin.instanceZones.add')}
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {zones.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('admin.instanceZones.empty')}</p>
        ) : (
          <ul className="divide-y rounded-md border">
            {zones.map((z) => (
              <li key={z.id} className="flex flex-wrap items-center justify-between gap-3 p-3">
                <div className="min-w-0 space-y-1">
                  <p className="font-medium break-words">{z.name}</p>
                  <p className="text-sm break-all text-muted-foreground">{z.ranges.join(', ')}</p>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="secondary">
                      {t('admin.instanceZones.sensorCount', undefined, {
                        count: z.sensor_ids.length,
                      })}
                    </Badge>
                    <Badge variant="secondary">
                      {t('admin.instanceZones.orgCount', undefined, {
                        count: z.organization_ids.length,
                      })}
                    </Badge>
                  </div>
                </div>
                {canEdit && (
                  <Button size="sm" variant="outline" onClick={() => setEditing(z)}>
                    {t('admin.instanceZones.edit')}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
        <p className="text-sm text-muted-foreground">{t('admin.instanceZones.signedHint')}</p>
        {!canEdit && (
          <p className="text-sm text-muted-foreground">{t('admin.scanPolicy.superOnly')}</p>
        )}
      </CardContent>
      {editing && (
        <ZoneDialog
          zone={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null)
            await onChanged()
          }}
        />
      )}
    </Card>
  )
}

function ZoneDialog({
  zone,
  onClose,
  onSaved,
}: {
  zone: InstanceScanZone | null
  onClose: () => void
  onSaved: () => Promise<void>
}) {
  const { t } = useTranslation()
  const id = useId()
  const [name, setName] = useState(zone?.name ?? '')
  const [description, setDescription] = useState(zone?.description ?? '')
  const [ranges, setRanges] = useState((zone?.ranges ?? []).join('\n'))
  const [sensors, setSensors] = useState((zone?.sensor_ids ?? []).join('\n'))
  const [orgs, setOrgs] = useState((zone?.organization_ids ?? []).join('\n'))
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const ready =
    name.trim() !== '' &&
    lines(ranges).length > 0 &&
    reason.trim() !== '' &&
    code.trim().length >= 6

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true)
    setError(null)
    try {
      await action()
      toast.success(t('admin.instanceZones.saved'))
      await onSaved()
    } catch (e) {
      setError(
        e instanceof AdminApiError || e instanceof Error
          ? e.message
          : t('admin.instanceZones.saveFailed')
      )
      if (e instanceof AdminApiError && e.status === 401) setCode('')
    } finally {
      setBusy(false)
    }
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const confirm = { reason: reason.trim(), totp_code: code.trim() }
    void run(async () => {
      const body = {
        name: name.trim(),
        description: description.trim(),
        ranges: lines(ranges),
        ...confirm,
      }
      const saved = zone
        ? await updateInstanceScanZone(zone.id, body)
        : await createInstanceScanZone(body)
      // The first request confirmed the code; the next ones run in the
      // console session's step-up window.
      if (!sameSet(lines(sensors), saved.sensor_ids)) {
        await setInstanceScanZoneSensors(saved.id, { ids: lines(sensors), ...confirm })
      }
      if (!sameSet(lines(orgs), saved.organization_ids)) {
        await setInstanceScanZoneOrganizations(saved.id, { ids: lines(orgs), ...confirm })
      }
    })
  }

  const remove = () => {
    if (!zone) return
    void run(() =>
      deleteInstanceScanZone(zone.id, { reason: reason.trim(), totp_code: code.trim() })
    )
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent size="lg">
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>
              {zone ? t('admin.instanceZones.editTitle') : t('admin.instanceZones.addTitle')}
            </DialogTitle>
            <DialogDescription>{t('admin.instanceZones.dialogDesc')}</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor={`${id}-name`}>{t('admin.instanceZones.name')}</Label>
              <Input
                id={`${id}-name`}
                value={name}
                maxLength={100}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-desc`}>{t('admin.instanceZones.description')}</Label>
              <Input
                id={`${id}-desc`}
                value={description}
                maxLength={1000}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-ranges`}>{t('admin.instanceZones.ranges')}</Label>
              <Textarea
                id={`${id}-ranges`}
                rows={3}
                value={ranges}
                onChange={(e) => setRanges(e.target.value)}
              />
              <p className="text-sm text-muted-foreground">{t('admin.instanceZones.rangesHint')}</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-sensors`}>{t('admin.instanceZones.sensors')}</Label>
              <Textarea
                id={`${id}-sensors`}
                rows={2}
                value={sensors}
                onChange={(e) => setSensors(e.target.value)}
              />
              <p className="text-sm text-muted-foreground">
                {t('admin.instanceZones.sensorsHint')}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-orgs`}>{t('admin.instanceZones.organizations')}</Label>
              <Textarea
                id={`${id}-orgs`}
                rows={2}
                value={orgs}
                onChange={(e) => setOrgs(e.target.value)}
              />
              <p className="text-sm text-muted-foreground">
                {t('admin.instanceZones.organizationsHint')}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-reason`}>{t('admin.scanPolicy.reason')}</Label>
              <Textarea
                id={`${id}-reason`}
                rows={2}
                maxLength={1000}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-code`}>{t('admin.scanPolicy.code')}</Label>
              <Input
                id={`${id}-code`}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={8}
              />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </DialogBody>
          <DialogFooter className="flex-wrap gap-2">
            {zone && (
              <Button
                type="button"
                variant="destructive"
                disabled={busy || reason.trim() === '' || code.trim().length < 6}
                onClick={remove}
              >
                {t('admin.instanceZones.delete')}
              </Button>
            )}
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              {t('admin.instanceZones.cancel')}
            </Button>
            <Button type="submit" disabled={busy || !ready}>
              {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
              {t('admin.scanPolicy.save')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
