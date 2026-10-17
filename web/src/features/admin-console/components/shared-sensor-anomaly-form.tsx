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
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '../api/admin-client'
import type { SharedSensorAnomalyThresholds } from '../api/use-scan-policy'

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
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => setValue(thresholds), [thresholds])
  const dirty = FIELDS.some(([key]) => value[key] !== thresholds[key])
  const valid = FIELDS.every(
    ([key]) => Number.isInteger(value[key]) && value[key] >= 0 && value[key] <= MAX_THRESHOLD
  )

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      await onSave(value, reason.trim(), code.trim())
      setOpen(false)
      setReason('')
      setCode('')
      toast.success(t('admin.anomaly.saved'))
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
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
            <div className="flex justify-end">
              <Button onClick={() => setOpen(true)} disabled={!dirty || !valid || busy}>
                {t('admin.scanPolicy.save')}
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t('admin.scanPolicy.superOnly')}</p>
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
        disabled={code.trim().length < 6 || !reason.trim()}
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
        <div className="space-y-4">
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
              aria-invalid={!!codeError}
            />
            {codeError && <p className="text-sm text-destructive">{codeError}</p>}
          </div>
        </div>
      </ConfirmDialog>
    </>
  )
}
