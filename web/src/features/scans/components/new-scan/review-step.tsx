'use client'

/**
 * Review: everything the scan will do, on one page, before it is created.
 * Every verdict here is the server's (scope check, workflow preview, zone
 * routing, schedule preview); Start stays disabled while one says no.
 */

import { AlertTriangle, CheckCircle2, Pencil, ShieldAlert, XCircle } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ScopeCheckList } from '@/features/scope'
import { ScanRoutingSection } from '@/features/scan-zones'
import type { ScanZone, ScanZonePreviewRequest } from '@/lib/api/scan-zone-types'
import type { NewScanFormData } from '../../types'
import { enTranslate, type Translate } from '../../lib/translate'
import { SENSOR_PREFERENCE_CONFIG } from '../../types'
import { onceRunAt } from '../../lib/scan-form'
import { schedulePreviewRequestFromForm } from '../../lib/schedule-preview'
import { viewerTimeZone } from '../../lib/zoned-time'
import { parsePastedTargets } from '../../lib/target-format'
import { SchedulePreview } from '../schedule-preview'
import type { ScanReview } from '../../hooks/use-scan-review'
import type { ScanWizardStep } from './scan-stepper'
import { WorkflowPreviewBody } from './workflow-preview'

interface ReviewStepProps {
  data: NewScanFormData
  onChange: (data: Partial<NewScanFormData>) => void
  review: ScanReview
  onEdit: (step: ScanWizardStep) => void
  /** What the scan runs, for display (scanner or workflow name). */
  whatLabel: string
  zones: ScanZone[]
  canReadZones: boolean
  zoneRequest: ScanZonePreviewRequest
  /** Scan approval (RFC-073): what the organization's rules ask, if anything. */
  approvalBlock?: React.ReactNode
}

function Row({
  title,
  step,
  onEdit,
  children,
}: {
  title: string
  step?: ScanWizardStep
  onEdit: (step: ScanWizardStep) => void
  children: React.ReactNode
}) {
  const { t } = useTranslation()
  return (
    <div className="grid gap-1 border-b py-3 last:border-b-0 sm:grid-cols-[7rem_1fr_auto] sm:gap-3">
      <dt className="text-muted-foreground text-sm">{title}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
      {step && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-7 justify-self-start px-2 text-xs sm:justify-self-end"
          onClick={() => onEdit(step)}
          aria-label={t('scans.review.editRow', undefined, { title: title.toLowerCase() })}
        >
          <Pencil className="me-1 h-3 w-3" aria-hidden />
          {t('scans.review.edit')}
        </Button>
      )}
    </div>
  )
}

export function scheduleSummary(data: NewScanFormData, t: Translate = enTranslate): string {
  const s = data.schedule
  if (s.runImmediately) return t('scans.review.sumNow')
  if (s.saveOnly) return t('scans.review.sumSave')
  const zone = s.timezone || viewerTimeZone()
  switch (s.frequency) {
    case 'once': {
      const at = onceRunAt(data)
      return at
        ? t('scans.review.sumOnce', undefined, {
            date: s.runAtDate ?? '',
            time: s.runAtTime ?? '',
            zone,
          })
        : t('scans.review.sumOnceIncomplete')
    }
    case 'daily':
      return t('scans.review.sumDaily', undefined, { time: s.time ?? '00:00', zone })
    case 'weekly':
      return t('scans.review.sumWeekly', undefined, {
        day: t(`scans.day.${s.dayOfWeek ?? 1}`),
        time: s.time ?? '00:00',
        zone,
      })
    case 'monthly':
      return t('scans.review.sumMonthly', undefined, {
        day: s.dayOfMonth ?? 1,
        time: s.time ?? '00:00',
        zone,
      })
    default:
      return t('scans.review.sumDemand')
  }
}

export function ReviewStep({
  data,
  onChange,
  review,
  onEdit,
  whatLabel,
  zones,
  canReadZones,
  zoneRequest,
  approvalBlock,
}: ReviewStepProps) {
  const { t } = useTranslation()
  const tgt = data.targets
  const typed = parsePastedTargets(tgt.customTargets).targets.length
  const expanded = tgt.coverage && tgt.coverage !== 'host' ? (tgt.expandedTargets ?? []).length : 0
  const results = review.scope.results ?? []
  const allowed = results.filter((r) => r.allowed).length
  const refused = review.refused

  const removeRefused = () => {
    const bad = new Set(refused.map((r) => r.toLowerCase()))
    const keepIds = tgt.assetIds.filter((id) => !bad.has((tgt.assetNames[id] ?? '').toLowerCase()))
    const names = Object.fromEntries(keepIds.map((id) => [id, tgt.assetNames[id]]))
    onChange({
      targets: {
        ...tgt,
        assetIds: keepIds,
        assetNames: names,
        customTargets: [
          ...parsePastedTargets(tgt.customTargets).targets.filter((x) => !bad.has(x.toLowerCase())),
          ...parsePastedTargets(tgt.customTargets).invalid.map((i) => i.input),
        ],
        expandedTargets: (tgt.expandedTargets ?? []).filter((e) => !bad.has(e.toLowerCase())),
      },
    })
  }

  const parts = [
    tgt.assetIds.length > 0 &&
      t(
        tgt.assetIds.length === 1 ? 'scans.review.partAssetOne' : 'scans.review.partAssetMany',
        undefined,
        { count: tgt.assetIds.length }
      ),
    typed > 0 && t('scans.review.partTyped', undefined, { count: typed }),
    expanded > 0 && t('scans.review.partCoverage', undefined, { count: expanded }),
    tgt.assetGroupIds.length > 0 &&
      t(
        tgt.assetGroupIds.length === 1 ? 'scans.review.partGroupOne' : 'scans.review.partGroupMany',
        undefined,
        { count: tgt.assetGroupIds.length }
      ),
  ].filter(Boolean)

  return (
    <div className="space-y-4 p-4">
      <div className="space-y-2">
        <Label htmlFor="review-name">
          {t('scans.review.scanName')} <span className="text-destructive">*</span>
        </Label>
        <Input
          id="review-name"
          value={data.name}
          onChange={(e) => onChange({ name: e.target.value })}
          placeholder={t('scans.review.namePlaceholder')}
        />
      </div>

      <dl className="rounded-lg border px-3">
        <Row title={t('scans.review.rowWhat')} step="basic" onEdit={onEdit}>
          <span className="font-medium">{whatLabel}</span>{' '}
          <span className="text-muted-foreground">
            (
            {data.mode === 'workflow'
              ? t('scans.review.workflowKind')
              : t('scans.review.singleKind')}
            )
          </span>
        </Row>
        <Row title={t('scans.review.rowTargets')} step="targets" onEdit={onEdit}>
          <span className="font-medium">
            {t(
              review.targets.length === 1
                ? 'scans.summary.targetsOne'
                : 'scans.summary.targetsMany',
              undefined,
              { count: review.targets.length.toLocaleString() }
            )}
          </span>
          {parts.length > 0 && <span className="text-muted-foreground"> · {parts.join(', ')}</span>}
          {review.scope.available && review.targets.length > 0 && (
            <span className="mt-1 flex items-center gap-1 text-xs">
              {review.scope.isLoading && results.length === 0 ? (
                <span className="text-muted-foreground">{t('scans.scope.checking')}</span>
              ) : refused.length > 0 ? (
                <>
                  <ShieldAlert className="h-3.5 w-3.5 text-warning" aria-hidden />
                  {t('scans.summary.inScope', undefined, { count: allowed })} ·{' '}
                  <span className="text-warning">
                    {t('scans.summary.mayNotScan', undefined, { count: refused.length })}
                  </span>
                </>
              ) : results.length > 0 ? (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5 text-success" aria-hidden />{' '}
                  {t('scans.summary.allInScope')}
                </>
              ) : null}
            </span>
          )}
        </Row>
        <Row title={t('scans.review.rowRunsOn')} step="basic" onEdit={onEdit}>
          {t(
            `scans.sensorPref.${data.sensorPreference in SENSOR_PREFERENCE_CONFIG ? data.sensorPreference : 'auto'}.label`
          )}
          {data.scanZoneId && (
            <span className="text-muted-foreground">
              {' '}
              ·{' '}
              {t('scans.review.zone', undefined, {
                name: zones.find((z) => z.id === data.scanZoneId)?.name ?? data.scanZoneId,
              })}
            </span>
          )}
        </Row>
        <Row title={t('scans.review.rowWhen')} step="schedule" onEdit={onEdit}>
          {scheduleSummary(data, t)}
          {!data.schedule.runImmediately && !data.schedule.saveOnly && (
            <div className="mt-2">
              <SchedulePreview request={schedulePreviewRequestFromForm(data, 3)} />
            </div>
          )}
        </Row>
      </dl>

      {refused.length > 0 && (
        <section
          aria-label={t('scans.review.refusedLabel')}
          className="space-y-2 rounded-lg border border-warning/50 p-3"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-sm font-medium">
              {t(
                refused.length === 1 ? 'scans.scope.refusedOne' : 'scans.scope.refusedMany',
                undefined,
                { count: refused.length }
              )}
            </p>
            <Button type="button" variant="outline" size="sm" onClick={removeRefused}>
              {refused.length === 1 ? t('scans.review.removeIt') : t('scans.review.removeThem')}
            </Button>
          </div>
          <ScopeCheckList
            results={results}
            onApplied={() => void review.scope.recheck()}
            limit={20}
          />
        </section>
      )}

      {data.mode === 'workflow' && review.workflow.data && (
        <section aria-label={t('scans.review.workflow')} className="rounded-lg border p-3">
          <h3 className="mb-2 text-sm font-semibold">{t('scans.review.workflow')}</h3>
          <WorkflowPreviewBody preview={review.workflow.data} />
        </section>
      )}

      {canReadZones && zones.length > 0 && (
        <div className="rounded-lg border">
          <ScanRoutingSection
            zones={zones}
            value={data.scanZoneId}
            onChange={(scanZoneId) => onChange({ scanZoneId })}
            request={zoneRequest}
          />
        </div>
      )}

      {(review.blockers.length > 0 || review.warnings.length > 0) && (
        <ul className="space-y-1.5" aria-label={t('scans.review.beforeStart')}>
          {review.blockers.map((b) => (
            <li key={b} className="flex items-start gap-2 text-sm text-destructive">
              <XCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
              {b}
            </li>
          ))}
          {review.warnings.map((w) => (
            <li key={w} className="flex items-start gap-2 text-sm text-muted-foreground">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
              {w}
            </li>
          ))}
        </ul>
      )}
      {approvalBlock}
    </div>
  )
}
