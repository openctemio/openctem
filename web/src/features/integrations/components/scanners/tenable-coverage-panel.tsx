'use client'

/**
 * Rolling coverage through the Tenable.sc connector (api RFC-047 §9): the
 * license Tenable.sc reports (used / limit), whether a batch is running, what
 * the next batch may use, the coverage cycle (license rotation, research/143
 * §4) and how fresh the inventory's scans are. A number that cannot be
 * computed yet says so instead of showing 0. A stalled recycle rotation shows
 * its reason and, for integrations:manage, Resume rotation.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { AlertTriangle, RotateCcw } from 'lucide-react'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Meter, MetricStrip, type MetricStripItem } from '@/features/shared'
import { useResumeCoverageRotationApi } from '@/features/integrations/api/use-integrations-api'
import {
  coverageNumbers,
  rotationProgress,
  type CoverageRotation,
} from '@/features/integrations/lib/tenable-sc'
import type { Integration } from '@/features/integrations/types/integration.types'
import { useScanCoverage } from '@/lib/api/scan-coverage-hooks'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'
import { Can, Permission } from '@/lib/permissions'
import { toDisplayText } from '@/lib/untrusted-text'
import { useTranslation } from '@/context/i18n-provider'

type Translate = ReturnType<typeof useTranslation>['t']

const ROTATION_LABEL: Record<CoverageRotation, string> = {
  off: 'Off',
  aging: 'Aging',
  recycle: 'Recycle',
}

/** The API's wait reasons (tenablesc afterBatch), translated; another text is shown as sent. */
const WAIT_REASONS: Record<string, { key: string; fallback: string }> = {
  "the rotation repository's license is freed by Tenable.sc's nightly cleanup": {
    key: 'tenableSc.coverage.wait.aging',
    fallback: "Tenable.sc's nightly cleanup frees the license of the last batch",
  },
  'the Tenable.sc license capacity the batch needs is not free yet': {
    key: 'tenableSc.coverage.wait.capacity',
    fallback: 'the license capacity the batch needs is not free yet',
  },
  'the previous batch failed': {
    key: 'tenableSc.coverage.wait.failed',
    fallback: 'the previous batch failed',
  },
}

export function waitReasonText(t: Translate, reason: string | undefined): string {
  if (!reason) return ''
  const known = WAIT_REASONS[reason]
  return known ? t(known.key, known.fallback) : toDisplayText(reason, 300)
}

export function TenableCoveragePanel({
  integration,
  onChanged,
}: {
  integration: Integration
  /** Called after the integration changed here (rotation resumed). */
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const n = coverageNumbers(integration)
  const r = rotationProgress(integration)
  const { data: freshness, isLoading } = useScanCoverage(30)
  const notEnough = t('tenableSc.coverage.notEnoughData', 'Not enough data')

  if (!n.enabled) {
    return (
      <p className="text-muted-foreground text-sm">
        {t(
          'tenableSc.coverage.off',
          'Rolling coverage is off for {name}. Turn it on in the connector settings to scan the inventory in license-sized batches.',
          { name: integration.name }
        )}
      </p>
    )
  }

  const outcome = (o: string) =>
    o === 'completed'
      ? t('tenableSc.coverage.outcomeCompleted', 'completed')
      : o === 'failed'
        ? t('tenableSc.coverage.outcomeFailed', 'failed')
        : o

  const licenseKnown = n.licensed !== null && n.limit !== null && n.active !== null
  const items: MetricStripItem[] = [
    {
      key: 'license',
      label: t('tenableSc.coverage.licenseUsed', 'License used'),
      value: licenseKnown ? `${n.active} / ${n.limit}` : notEnough,
      hint: licenseKnown
        ? n.limit !== n.licensed
          ? t('tenableSc.coverage.cappedBelow', 'capped below the {licensed} licensed IPs', {
              licensed: n.licensed ?? 0,
            })
          : t('tenableSc.coverage.activeReported', 'active IPs reported by Tenable.sc')
        : t('tenableSc.coverage.firstSync', 'reported by the first successful sync'),
      detail: licenseKnown ? (
        <Meter
          value={n.active ?? 0}
          max={n.limit ?? 0}
          label={t('tenableSc.coverage.meterLabel', '{active} of {limit} licensed IPs in use', {
            active: n.active ?? 0,
            limit: n.limit ?? 0,
          })}
          tone={n.headroom === 0 ? 'destructive' : 'default'}
        />
      ) : undefined,
    },
    {
      key: 'batch',
      label: t('tenableSc.coverage.currentBatch', 'Current batch'),
      value: n.batchOpen
        ? t('tenableSc.coverage.running', 'Running')
        : t('tenableSc.coverage.noneRunning', 'None running'),
      hint: n.batchOpen
        ? t(
            'tenableSc.coverage.batchWaits',
            'the next batch waits until it is scanned and ingested'
          )
        : n.lastBatchOutcome
          ? t('tenableSc.coverage.lastBatch', 'last batch {outcome}', {
              outcome: outcome(n.lastBatchOutcome),
            })
          : t('tenableSc.coverage.noBatchYet', 'no batch dispatched yet'),
    },
    {
      key: 'next',
      label: t('tenableSc.coverage.nextBatch', 'Next batch'),
      value:
        n.headroom === null
          ? notEnough
          : n.batchOpen
            ? t('tenableSc.coverage.afterCurrent', 'After the current batch')
            : t('tenableSc.coverage.ips', '{count} IPs', { count: n.headroom }),
      hint:
        n.headroom === 0
          ? t(
              'tenableSc.coverage.licenseFull',
              'license full: waits for Tenable.sc to age data out'
            )
          : n.safetyMargin > 0
            ? t('tenableSc.coverage.keepsMargin', 'keeps a margin of {margin} IPs', {
                margin: n.safetyMargin,
              })
            : t('tenableSc.coverage.withinHeadroom', 'within the license headroom'),
      tone: n.headroom === 0 ? 'warning' : 'default',
    },
    {
      key: 'cycle',
      label: t('tenableSc.coverage.cycle', 'Coverage cycle'),
      value:
        r.cycle > 0
          ? t('tenableSc.coverage.cycleValue', 'Cycle {cycle}: {assessed} / {eligible}', {
              cycle: r.cycle,
              assessed: r.assessed,
              eligible: r.eligible,
            })
          : notEnough,
      hint:
        r.cycle > 0
          ? r.eta
            ? t('tenableSc.coverage.cycleEta', 'assets assessed; done about {eta}', {
                eta: formatDateSafe(r.eta, 'PPp'),
              })
            : t('tenableSc.coverage.cycleAssessed', 'assets assessed in this cycle')
          : t('tenableSc.coverage.cycleFirstBatch', 'starts with the first batch'),
      detail:
        r.cycle > 0 && r.eligible > 0 ? (
          <Meter
            value={r.assessed}
            max={r.eligible}
            label={t(
              'tenableSc.coverage.cycleMeterLabel',
              '{assessed} of {eligible} assets assessed in this cycle',
              { assessed: r.assessed, eligible: r.eligible }
            )}
          />
        ) : undefined,
    },
    {
      key: 'fresh',
      label: t('tenableSc.coverage.scannedIn30Days', 'Scanned in 30 days'),
      value: isLoading
        ? '…'
        : freshness && freshness.total_scannable > 0
          ? `${freshness.coverage_percent.toFixed(1)}%`
          : notEnough,
      hint: freshness
        ? t(
            'tenableSc.coverage.freshnessHint',
            '{covered} of {total} hosts, {never} never scanned',
            {
              covered: freshness.covered_in_window,
              total: freshness.total_scannable,
              never: freshness.never_scanned,
            }
          )
        : undefined,
      tone: freshness && freshness.critical_never_scanned > 0 ? 'danger' : 'default',
    },
  ]

  return (
    <div className="space-y-3">
      <MetricStrip items={items} loading={false} />
      <p className="text-muted-foreground text-sm" data-testid="tsc-rotation-line">
        {t('tenableSc.coverage.rotation', 'License rotation: {mode}', {
          mode: t(`tenableSc.dialog.rotationMode.${r.rotation}`, ROTATION_LABEL[r.rotation]),
        })}
        {r.nextBatchAt &&
          `, ${t('tenableSc.coverage.nextBatchAt', 'next batch from {at}', {
            at: formatDateSafe(r.nextBatchAt, 'PPp'),
          })}`}
        {r.waitReason && `: ${waitReasonText(t, r.waitReason)}`}
      </p>
      {r.stalled && (
        <RotationStalled integration={integration} message={r.stalled} onChanged={onChanged} />
      )}
    </div>
  )
}

const STALLED_MESSAGE =
  'rotation stalled: the previous batch failed after it launched, so its results may not be ingested; an administrator resumes rotation to recycle the rotation repository'

/** A stalled recycle rotation: why, and Resume rotation for integrations:manage. */
function RotationStalled({
  integration,
  message,
  onChanged,
}: {
  integration: Integration
  message: string
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const [confirmOpen, setConfirmOpen] = useState(false)
  const { trigger, isMutating } = useResumeCoverageRotationApi(integration.id)
  const text =
    message === STALLED_MESSAGE
      ? t(
          'tenableSc.coverage.stalled',
          'Rotation stalled: the previous batch failed after it launched, so its results may not be ingested. Resuming recycles the rotation repository before the next batch.'
        )
      : toDisplayText(message, 500)

  const resume = async () => {
    try {
      await trigger()
      toast.success(t('tenableSc.coverage.resumed', 'Rotation resumed'))
      setConfirmOpen(false)
      onChanged?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('tenableSc.coverage.resumeFailed', 'Could not resume')))
    }
  }

  return (
    <div
      role="alert"
      className="flex flex-col gap-3 rounded-lg border border-warning/40 bg-warning/5 p-3 sm:flex-row sm:items-center"
    >
      <AlertTriangle className="h-4 w-4 shrink-0 text-warning" aria-hidden />
      <p className="flex-1 text-sm">{text}</p>
      <Can permission={Permission.IntegrationsManage}>
        <Button size="sm" variant="outline" onClick={() => setConfirmOpen(true)}>
          <RotateCcw className="me-1.5 h-3.5 w-3.5" aria-hidden />
          {t('tenableSc.coverage.resume', 'Resume rotation')}
        </Button>
        <ConfirmDialog
          open={confirmOpen}
          onOpenChange={setConfirmOpen}
          title={t('tenableSc.coverage.resumeTitle', 'Resume license rotation?')}
          desc={t(
            'tenableSc.coverage.resumeDesc',
            'The next batch deletes and recreates the rotation repository in Tenable.sc. Results of the failed batch that were not ingested are lost; its assets are due again and are scanned anew.'
          )}
          confirmText={t('tenableSc.coverage.resume', 'Resume rotation')}
          handleConfirm={resume}
          isLoading={isMutating}
        />
      </Can>
    </div>
  )
}
