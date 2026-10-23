'use client'

import { useCallback } from 'react'
import { toast } from 'sonner'
import { ShieldCheck, RefreshCw, Loader2, Eye, EyeOff, Unplug, type LucideIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { SEVERITY_BADGE_SOFT } from '@/lib/severity-colors'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions } from '@/context/permission-provider'
import { useTranslation } from '@/context/i18n-provider'
import { planMethod, useFindingVerificationPlan } from '../../api/use-finding-verification'
import {
  useRequestValidationApi,
  useFindingValidationEvidenceApi,
  type ValidationEvidenceItem,
} from '../../api/use-findings-api'

interface ValidationEvidencePanelProps {
  findingId: string
}

const OUTCOME_STYLES: Record<string, string> = {
  not_detected: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400',
  detected: 'bg-red-500/15 text-red-600 dark:text-red-400',
  inconclusive: 'bg-amber-500/15 text-amber-600 dark:text-amber-400',
  error: 'bg-red-500/15 text-red-600 dark:text-red-400',
  skipped: 'bg-muted text-muted-foreground',
}

type TFn = ReturnType<typeof useTranslation>['t']

function outcomeText(outcome: string, t: TFn): string | undefined {
  switch (outcome) {
    case 'not_detected':
      return t('findings.validationEvidence.outNotDetected', 'Not detected')
    case 'detected':
      return t('findings.validationEvidence.outDetected', 'Detected (still exploitable)')
    case 'inconclusive':
      return t('findings.validationEvidence.outInconclusive', 'Inconclusive')
    case 'error':
      return t('findings.validationEvidence.outError', 'Error')
    case 'skipped':
      return t('findings.validationEvidence.outSkipped', 'Skipped')
    default:
      return undefined
  }
}

/**
 * A safe-check is a reachability probe: it says whether the host answers, not
 * whether the vulnerability is there, and it never changes the finding's status
 * (RFC-039 D3). Label it as what it is.
 */
function reachabilityText(outcome: string, t: TFn): string | undefined {
  switch (outcome) {
    case 'detected':
      return t('findings.validationEvidence.reachable', 'Reachable')
    case 'not_detected':
      return t('findings.validationEvidence.notReachable', 'Not reachable')
    default:
      return undefined
  }
}

export function outcomeLabel(
  item: Pick<ValidationEvidenceItem, 'executor_kind' | 'outcome'>,
  t: TFn
) {
  if (item.executor_kind === 'safe-check') {
    const reach = reachabilityText(item.outcome, t)
    if (reach) return reach
  }
  return outcomeText(item.outcome, t) ?? item.outcome
}

/**
 * Detection-correlation verdict → how to render it. This answers a DIFFERENT
 * question from `outcome`: "did any control observe this validation?" — not "is
 * the exposure still reachable?". Deliberately NOT a pass/fail chip: only
 * `not_observed` is a genuine detection gap. `no_telemetry_source` means no
 * telemetry is reaching the platform (UNKNOWN, never a control miss), and
 * `observed` is the good case. `not_applicable` / `not_evaluated` carry no
 * signal and render nothing.
 */
const DETECTION_META: Record<
  string,
  {
    labelKey: string
    label: string
    titleKey: string
    title: string
    className: string
    Icon: LucideIcon
  }
> = {
  observed: {
    labelKey: 'findings.validationEvidence.obsLabel',
    label: 'Observed by controls',
    titleKey: 'findings.validationEvidence.obsTitle',
    title: 'A security control observed this validation activity.',
    className: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400', // palette-ok: success accent — the theme has no semantic "success" token
    Icon: Eye,
  },
  not_observed: {
    labelKey: 'findings.validationEvidence.gapLabel',
    label: 'Detection gap',
    titleKey: 'findings.validationEvidence.gapTitle',
    title: 'No control observed this validation — a detection gap worth closing.',
    className: SEVERITY_BADGE_SOFT.medium,
    Icon: EyeOff,
  },
  no_telemetry_source: {
    labelKey: 'findings.validationEvidence.noTelLabel',
    label: 'No telemetry connected',
    titleKey: 'findings.validationEvidence.noTelTitle',
    title:
      'No telemetry source is connected for this asset, so detection is unknown — not a control failure.',
    className: 'bg-muted text-muted-foreground',
    Icon: Unplug,
  },
}

function DetectionBadge({ item }: { item: ValidationEvidenceItem }) {
  const { t } = useTranslation()
  if (!item.detection_status) return null
  const meta = DETECTION_META[item.detection_status]
  if (!meta) return null
  const { className, Icon } = meta
  return (
    <Badge
      variant="secondary"
      className={cn('gap-1 font-medium', className)}
      title={t(meta.titleKey, meta.title)}
    >
      <Icon className="h-3 w-3" />
      {t(meta.labelKey, meta.label)}
    </Badge>
  )
}

function formatTimestamp(value: string | undefined, locale: string): string {
  if (!value) return ''
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString(locale)
}

function EvidenceRow({ item }: { item: ValidationEvidenceItem }) {
  const { t, locale } = useTranslation()
  return (
    <li className="flex flex-col gap-1 rounded-md border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge
          variant="secondary"
          className={cn(
            'font-medium',
            item.executor_kind === 'safe-check'
              ? OUTCOME_STYLES.skipped
              : (OUTCOME_STYLES[item.outcome] ?? OUTCOME_STYLES.skipped)
          )}
        >
          {outcomeLabel(item, t)}
        </Badge>
        <DetectionBadge item={item} />
        <span className="text-muted-foreground text-xs">{item.executor_kind}</span>
        {item.technique ? (
          <span className="text-muted-foreground text-xs">· {item.technique}</span>
        ) : null}
        <span className="text-muted-foreground ms-auto text-xs">
          {formatTimestamp(item.created_at, locale)}
        </span>
      </div>
      {item.summary ? <p className="text-sm">{item.summary}</p> : null}
    </li>
  )
}

/**
 * ValidationEvidencePanel shows CTEM Stage-4 validation evidence for a finding
 * and lets an operator trigger a fresh safe-check re-validation (RFC-011).
 */
export function ValidationEvidencePanel({ findingId }: ValidationEvidencePanelProps) {
  const { data, isLoading, mutate } = useFindingValidationEvidenceApi(findingId)
  const { trigger: requestValidation, isMutating } = useRequestValidationApi(findingId)
  const { hasPermission } = usePermissions()
  const { t } = useTranslation()
  // The reachability check is offered only where the server says it can run
  // (an active network asset, not a secret); it is advisory, so it needs the
  // same permission as a retest.
  const { data: plan } = useFindingVerificationPlan(findingId)
  const safeCheck = planMethod(plan, 'safe_check')

  const handleValidate = useCallback(async () => {
    try {
      await requestValidation()
      toast.success(t('findings.validationEvidence.requested', 'Validation requested'), {
        description: t(
          'findings.validationEvidence.requestedDesc',
          'A safe-check job was dispatched. Evidence appears here once a sensor reports back.'
        ),
      })
      // Give the async completion a moment, then refresh the evidence list.
      setTimeout(() => {
        void mutate()
      }, 1500)
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('findings.validationEvidence.requestFailed', 'Failed to request validation')
        )
      )
    }
  }, [requestValidation, mutate, t])

  const evidence = data?.evidence ?? []
  // Nothing recorded and nothing to run here: the Verification panel says why.
  if (!isLoading && evidence.length === 0 && !safeCheck?.available) return null

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="text-muted-foreground h-4 w-4" />
          <h3 className="text-sm font-semibold">
            {t('findings.validationEvidence.heading', 'Validation')}
          </h3>
          {evidence.length > 0 ? <Badge variant="secondary">{evidence.length}</Badge> : null}
        </div>
        {hasPermission('findings:verify') && safeCheck?.available ? (
          <Button size="sm" variant="outline" onClick={handleValidate} disabled={isMutating}>
            {isMutating ? (
              <Loader2 className="me-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="me-1.5 h-3.5 w-3.5" />
            )}
            {t('findings.validationEvidence.checkReachability', 'Check reachability')}
          </Button>
        ) : null}
      </div>

      {isLoading ? (
        <p className="text-muted-foreground text-sm">
          {t('findings.validationEvidence.loading', 'Loading validation evidence…')}
        </p>
      ) : evidence.length === 0 ? (
        <p className="text-muted-foreground text-sm">
          {t(
            'findings.validationEvidence.empty',
            'No validation evidence yet. A reachability check shows whether the target still answers; it does not prove a fix.'
          )}
        </p>
      ) : (
        <ul className="space-y-2">
          {evidence.map((item) => (
            <EvidenceRow key={item.id} item={item} />
          ))}
        </ul>
      )}
    </section>
  )
}
