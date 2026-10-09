'use client'

/**
 * Review: everything the scan will do, on one page, before it is created.
 * Every verdict here is the server's (scope check, workflow preview, zone
 * routing, schedule preview); Start stays disabled while one says no.
 */

import { AlertTriangle, CheckCircle2, Pencil, ShieldAlert, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ScopeCheckList } from '@/features/scope'
import { ScanRoutingSection } from '@/features/scan-zones'
import type { ScanZone, ScanZonePreviewRequest } from '@/lib/api/scan-zone-types'
import type { NewScanFormData } from '../../types'
import { SENSOR_PREFERENCE_CONFIG } from '../../types'
import { onceRunAt } from '../../lib/scan-form'
import { schedulePreviewRequestFromForm } from '../../lib/schedule-preview'
import { viewerTimeZone } from '../../lib/zoned-time'
import { parsePastedTargets } from '../../lib/target-format'
import { SchedulePreview } from '../schedule-preview'
import type { ScanReview } from '../../hooks/use-scan-review'
import type { ScanWizardStep } from './scan-stepper'
import { WorkflowPreviewBody } from './workflow-preview'

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']

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
          aria-label={`Edit ${title.toLowerCase()}`}
        >
          <Pencil className="me-1 h-3 w-3" aria-hidden />
          Edit
        </Button>
      )}
    </div>
  )
}

export function scheduleSummary(data: NewScanFormData): string {
  const s = data.schedule
  if (s.runImmediately) return 'Runs now, once'
  if (s.saveOnly) return 'Saved without running: start it from the scan page'
  const zone = s.timezone || viewerTimeZone()
  switch (s.frequency) {
    case 'once': {
      const at = onceRunAt(data)
      return at
        ? `Once, on ${s.runAtDate} at ${s.runAtTime} (${zone})`
        : 'Once (choose the date and time)'
    }
    case 'daily':
      return `Daily at ${s.time ?? '00:00'} (${zone})`
    case 'weekly':
      return `Weekly on ${DAY_NAMES[s.dayOfWeek ?? 1]} at ${s.time ?? '00:00'} (${zone})`
    case 'monthly':
      return `Monthly on day ${s.dayOfMonth ?? 1} at ${s.time ?? '00:00'} (${zone})`
    default:
      return 'On demand'
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
}: ReviewStepProps) {
  const t = data.targets
  const typed = parsePastedTargets(t.customTargets).targets.length
  const expanded = t.coverage && t.coverage !== 'host' ? (t.expandedTargets ?? []).length : 0
  const results = review.scope.results ?? []
  const allowed = results.filter((r) => r.allowed).length
  const refused = review.refused

  const removeRefused = () => {
    const bad = new Set(refused.map((r) => r.toLowerCase()))
    const keepIds = t.assetIds.filter((id) => !bad.has((t.assetNames[id] ?? '').toLowerCase()))
    const names = Object.fromEntries(keepIds.map((id) => [id, t.assetNames[id]]))
    onChange({
      targets: {
        ...t,
        assetIds: keepIds,
        assetNames: names,
        customTargets: t.customTargets.filter((line) => !bad.has(line.trim().toLowerCase())),
        expandedTargets: (t.expandedTargets ?? []).filter((e) => !bad.has(e.toLowerCase())),
      },
    })
  }

  const parts = [
    t.assetIds.length > 0 && `${t.assetIds.length} ${t.assetIds.length === 1 ? 'asset' : 'assets'}`,
    typed > 0 && `${typed} typed`,
    expanded > 0 && `${expanded} from coverage`,
    t.assetGroupIds.length > 0 &&
      `${t.assetGroupIds.length} ${t.assetGroupIds.length === 1 ? 'group' : 'groups'}`,
  ].filter(Boolean)

  return (
    <div className="space-y-4 p-4">
      <div className="space-y-2">
        <Label htmlFor="review-name">
          Scan name <span className="text-destructive">*</span>
        </Label>
        <Input
          id="review-name"
          value={data.name}
          onChange={(e) => onChange({ name: e.target.value })}
          placeholder="e.g., Production weekly scan"
        />
      </div>

      <dl className="rounded-lg border px-3">
        <Row title="What" step="basic" onEdit={onEdit}>
          <span className="font-medium">{whatLabel}</span>{' '}
          <span className="text-muted-foreground">
            ({data.mode === 'workflow' ? 'workflow' : 'single check'})
          </span>
        </Row>
        <Row title="Targets" step="targets" onEdit={onEdit}>
          <span className="font-medium">
            {review.targets.length.toLocaleString()}{' '}
            {review.targets.length === 1 ? 'target' : 'targets'}
          </span>
          {parts.length > 0 && <span className="text-muted-foreground"> · {parts.join(', ')}</span>}
          {review.scope.available && review.targets.length > 0 && (
            <span className="mt-1 flex items-center gap-1 text-xs">
              {review.scope.isLoading && results.length === 0 ? (
                <span className="text-muted-foreground">Checking scope…</span>
              ) : refused.length > 0 ? (
                <>
                  <ShieldAlert className="h-3.5 w-3.5 text-warning" aria-hidden />
                  {allowed} in scope ·{' '}
                  <span className="text-warning">{refused.length} may not be scanned</span>
                </>
              ) : results.length > 0 ? (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5 text-success" aria-hidden /> all in scope
                </>
              ) : null}
            </span>
          )}
        </Row>
        <Row title="Runs on" step="basic" onEdit={onEdit}>
          {SENSOR_PREFERENCE_CONFIG[data.sensorPreference]?.label ?? 'Auto'}
          {data.scanZoneId && (
            <span className="text-muted-foreground">
              {' '}
              · zone {zones.find((z) => z.id === data.scanZoneId)?.name ?? data.scanZoneId}
            </span>
          )}
        </Row>
        <Row title="When" step="schedule" onEdit={onEdit}>
          {scheduleSummary(data)}
          {!data.schedule.runImmediately && !data.schedule.saveOnly && (
            <div className="mt-2">
              <SchedulePreview request={schedulePreviewRequestFromForm(data, 3)} />
            </div>
          )}
        </Row>
      </dl>

      {refused.length > 0 && (
        <section
          aria-label="Refused targets"
          className="space-y-2 rounded-lg border border-warning/50 p-3"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-sm font-medium">
              {refused.length} {refused.length === 1 ? 'target' : 'targets'} may not be scanned
            </p>
            <Button type="button" variant="outline" size="sm" onClick={removeRefused}>
              Remove {refused.length === 1 ? 'it' : 'them'}
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
        <section aria-label="Workflow" className="rounded-lg border p-3">
          <h3 className="mb-2 text-sm font-semibold">Workflow</h3>
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
        <ul className="space-y-1.5" aria-label="Before you start">
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
    </div>
  )
}
