'use client'

/**
 * System > Platform scanning: the anomaly alert thresholds of shared sensor
 * use (RFC-100 §9). Per organization per UTC day: distinct registrable
 * domains sent to shared sensors, failed shared jobs, deny-list hits.
 * Reaching one raises one alert that day (admin audit row, email, metric);
 * 0 turns a signal off. The counts keep no target. A change needs a super
 * admin, a reason and a fresh authenticator code; it is audited.
 */

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { AdminApiError } from '@console/lib/admin-api/client'
import type { SharedSensorAnomalyThresholds } from '../api/use-scan-policy'
import { ReasonAndCodeFields, useReasonAndCode } from './step-up-code-hint'
import { RoleRequiredNotice } from './role-required-notice'

const FIELDS = [
  ['distinct_domains_per_day', 'domains'],
  ['failures_per_day', 'failures'],
  ['deny_list_hits_per_day', 'denyHits'],
] as const

const MAX_THRESHOLD = 1_000_000

export interface SharedSensorAnomalyFormProps {
  thresholds: SharedSensorAnomalyThresholds
  canEdit: boolean
  onSave: (next: SharedSensorAnomalyThresholds, reason: string, code: string) => Promise<void>
}

export function SharedSensorAnomalyForm({
  thresholds,
  canEdit,
  onSave,
}: SharedSensorAnomalyFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [value, setValue] = useState(thresholds)
  const [open, setOpen] = useState(false)
  const rc = useReasonAndCode(open)
  const [busy, setBusy] = useState(false)

  useEffect(() => setValue(thresholds), [thresholds])
  const reset = () => setValue(thresholds)
  const dirty = FIELDS.some(([key]) => value[key] !== thresholds[key])
  const valid = FIELDS.every(
    ([key]) => Number.isInteger(value[key]) && value[key] >= 0 && value[key] <= MAX_THRESHOLD
  )

  const save = async () => {
    setBusy(true)
    rc.setCodeError(null)
    try {
      await onSave(value, rc.reason.trim(), rc.code.trim())
      setOpen(false)
      toast.success(t('admin.anomaly.saved'))
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        rc.refuseCode(e.message)
        return
      }
      setOpen(false)
      toast.error(e instanceof Error ? e.message : t('admin.anomaly.saveFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.anomaly.title')}</CardTitle>
          <CardDescription>{t('admin.anomaly.desc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-3">
            {FIELDS.map(([key, label]) => (
              <div key={key} className="space-y-2">
                <Label htmlFor={`${id}-${key}`}>{t(`admin.anomaly.${label}`)}</Label>
                <Input
                  id={`${id}-${key}`}
                  type="number"
                  inputMode="numeric"
                  min={0}
                  max={MAX_THRESHOLD}
                  step={1}
                  value={Number.isNaN(value[key]) ? '' : value[key]}
                  onChange={(e) => setValue({ ...value, [key]: e.target.valueAsNumber })}
                  disabled={!canEdit || busy}
                />
              </div>
            ))}
          </div>
          <p className="text-sm text-muted-foreground">{t('admin.anomaly.zeroOff')}</p>
          <p className="text-sm text-muted-foreground">{t('admin.anomaly.aggregate')}</p>
          {canEdit ? (
            <SettingsSaveBar
              className="basis-full"
              dirty={dirty}
              saving={busy}
              saveDisabled={!valid}
              onSave={() => setOpen(true)}
              onDiscard={reset}
            />
          ) : (
            <RoleRequiredNotice needed="super_admin" />
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={open}
        onOpenChange={(o) => {
          if (!busy) setOpen(o)
        }}
        title={t('admin.anomaly.confirmTitle')}
        desc={<p>{t('admin.anomaly.confirmDesc')}</p>}
        disabled={!rc.codeOk || !rc.reasonOk}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('admin.scanPolicy.saving')}
            </>
          ) : (
            t('admin.scanPolicy.confirm')
          )
        }
      >
        <ReasonAndCodeFields id={id} state={rc} />
      </ConfirmDialog>
    </>
  )
}
