'use client'

/**
 * Retest section (RFC-039) — one component for the finding page rail and the
 * finding drawer, on the shared detail frame (DetailSection).
 *
 *   Retest                                   [Retest now]
 *   ● Verified fixed — awaiting confirmation · 3 min ago   View evidence
 *     https://h/admin answered 404 and the check did not match
 *   Earlier: Still present · 2 d ago, Unknown · 9 d ago
 *
 * "Retest now" re-runs the check that produced the finding against the origin
 * of its matched-at URL. A verified fix (the endpoint answered and the check
 * did not match) marks the finding not reproducible, or resolves it when the
 * organization auto-resolves; still vulnerable keeps it (or reopens a resolved
 * one); not reproduced and inconclusive change nothing. Each attempt's
 * request and response are shown under "View evidence". Needs
 * findings:verify (the API is the authority; this only hides a button the API
 * would refuse).
 */

import { useEffect, useRef, useState } from 'react'
import Link from '@/components/link'
import { useSWRConfig } from 'swr'
import { toast } from 'sonner'
import { Loader2, RefreshCw } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { SEVERITY_BADGE_SOFT } from '@/lib/severity-colors'
import { getErrorMessage } from '@/lib/api/error-handler'
import { cn } from '@/lib/utils'
import { toDisplayText } from '@/lib/untrusted-text'
import { runHref } from '@/features/scans/lib/run-display'
import { safeHref } from '@/lib/safe-href'
import { usePermissions } from '@/context/permission-provider'
import { useTranslation } from '@/context/i18n-provider'
import {
  hasRetestHistory,
  isRetestable,
  useFindingRetests,
  useRequestRetest,
  type FindingRetest,
} from '../../api/use-finding-retests'
import { useFindingEvidenceItems } from '../../api/use-finding-evidence-items'
import { FindingEvidenceItems } from './finding-evidence-items'

interface RetestMeta {
  label: string
  className: string
}

const SUCCESS_SOFT = 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400' // palette-ok: success accent — the theme has no semantic "success" token

type Translate = ReturnType<typeof useTranslation>['t']

/** Used when a caller passes no `t`: the English fallback with {vars} filled in. */
const englishOnly: Translate = (_key, fallback, vars) =>
  (fallback ?? _key).replace(/\{(\w+)\}/g, (m, name: string) =>
    vars && name in vars ? String(vars[name]) : m
  )

/** Why a retest was inconclusive, in words (ids; translated at render). */
const INCONCLUSIVE_TEXT: Record<string, string> = {
  unreachable: 'target unreachable',
  blocked: 'blocked',
  auth_changed: 'authentication required',
  server_error: 'server error',
  endpoint_mismatch: 'another endpoint was checked',
  template_changed: 'template changed',
  no_result: 'no result',
  error: 'error',
}

/**
 * How a retest reads, from its status, outcome and what it did to the
 * finding. A non-match is never shown as "Fixed" on its own (RFC-057): only a
 * confirmed fix (the endpoint answered and the check did not match) is.
 */
export function retestMeta(rt: FindingRetest, t: Translate = englishOnly): RetestMeta {
  if (rt.status === 'pending') {
    return {
      label: t('findings.retestPanel.running', 'Retest running'),
      className: 'bg-muted text-muted-foreground',
    }
  }
  switch (rt.outcome) {
    case 'confirmed_fixed':
      return rt.result_status === 'resolved'
        ? {
            label: t('findings.retestPanel.fixedResolved', 'Fixed — verified and resolved'),
            className: SUCCESS_SOFT,
          }
        : {
            label: t(
              'findings.retestPanel.verifiedFixed',
              'Verified fixed — awaiting confirmation'
            ),
            className: SUCCESS_SOFT,
          }
    case 'still_vulnerable':
      return rt.prior_status === 'resolved' && rt.result_status !== 'resolved'
        ? {
            label: t('findings.retestPanel.regression', 'Regression — reopened'),
            className: SEVERITY_BADGE_SOFT.high,
          }
        : {
            label: t('findings.retestPanel.stillVulnerable', 'Still vulnerable'),
            className: SEVERITY_BADGE_SOFT.medium,
          }
    case 'not_reproduced':
      return {
        label: t('findings.retestPanel.notReproduced', 'Not reproduced — not confirmed'),
        className: 'bg-muted text-muted-foreground',
      }
    default: {
      const whyEn = INCONCLUSIVE_TEXT[rt.reason_code ?? ''] ?? ''
      const why = whyEn ? t(`findings.retestPanel.inconclusiveWhy.${rt.reason_code}`, whyEn) : ''
      return {
        label: why
          ? t('findings.retestPanel.inconclusiveWhy', 'Inconclusive: {why}', { why })
          : t('findings.retestPanel.inconclusive', 'Inconclusive'),
        className: 'bg-muted text-muted-foreground',
      }
    }
  }
}

/**
 * A retest a pentest tester recorded by hand (kind manual): passed, failed or
 * partially fixed, with the tester's notes.
 */
export function manualRetestMeta(rt: FindingRetest, t: Translate): RetestMeta {
  switch (rt.manual_result) {
    case 'passed':
      return {
        label: t('findings.retest.manual.passed', 'Tester retest: fixed'),
        className: SUCCESS_SOFT,
      }
    case 'failed':
      return {
        label: t('findings.retest.manual.failed', 'Tester retest: still vulnerable'),
        className: SEVERITY_BADGE_SOFT.medium,
      }
    case 'partial':
      return {
        label: t('findings.retest.manual.partial', 'Tester retest: partially fixed'),
        className: SEVERITY_BADGE_SOFT.low,
      }
    case 'pending':
    case 'in_progress':
      return {
        label: t('findings.retest.manual.pending', 'Tester retest pending'),
        className: 'bg-muted text-muted-foreground',
      }
    default:
      return {
        label: t('findings.retest.manual.canceled', 'Tester retest canceled'),
        className: 'bg-muted text-muted-foreground',
      }
  }
}

function metaFor(rt: FindingRetest, t: Translate): RetestMeta {
  return rt.kind === 'manual' ? manualRetestMeta(rt, t) : retestMeta(rt, t)
}

interface FindingRetestSectionProps {
  finding: { id: string; toolName?: string; ruleId?: string; status?: string; source?: string }
  className?: string
}

export function FindingRetestSection({ finding, className }: FindingRetestSectionProps) {
  const { hasPermission } = usePermissions()
  const { t } = useTranslation()
  const { mutate } = useSWRConfig()
  const mayRetest = isRetestable(finding)
  // History is shown for any finding of a tool rule, also one no longer
  // retestable (e.g. false positive), and for pentest findings, whose testers
  // retest by hand. Whether "Retest now" is offered comes from the API
  // (can_retest), which knows what the organization's sensors can re-check.
  const { data } = useFindingRetests(
    hasRetestHistory(finding) || finding.source === 'pentest' ? finding.id : null
  )
  const retestable = mayRetest && data?.can_retest === true
  const { trigger, isMutating } = useRequestRetest(finding.id)
  const list = data?.data ?? []
  const latest = list[0]
  const running = latest?.status === 'pending'

  // When the running retest settles, the finding may have moved: refresh it
  // (status, resolution) and its activity trail.
  const runningId = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (running) {
      runningId.current = latest?.id
      return
    }
    if (runningId.current && latest?.id === runningId.current) {
      runningId.current = undefined
      void mutate(`/api/v1/findings/${finding.id}`)
      void mutate(
        (key) =>
          typeof key === 'string' && key.startsWith(`/api/v1/findings/${finding.id}/activities`)
      )
    }
  }, [running, latest?.id, finding.id, mutate])

  if (!retestable && list.length === 0) return null

  const canRetest = retestable && hasPermission('findings:verify')

  const retestNow = async () => {
    try {
      await trigger()
      toast.success(t('findings.retestPanel.started', 'Retest started'), {
        description: t(
          'findings.retestPanel.startedDesc',
          'The template that found this issue is running again against its target.'
        ),
      })
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.retestPanel.startFailed', 'Could not start the retest'))
      )
    }
  }

  return (
    <DetailSection
      title={t('findings.retestPanel.title', 'Retest')}
      icon={RefreshCw}
      className={className}
      actions={
        canRetest ? (
          <Button
            variant="outline"
            size="sm"
            className="h-7"
            onClick={() => void retestNow()}
            disabled={isMutating || running}
            title={t(
              'findings.retestPanel.rerunTitle',
              'Re-run the check that found this issue against its target'
            )}
          >
            {isMutating || running ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}
            {t('findings.retestPanel.now', 'Retest now')}
          </Button>
        ) : undefined
      }
    >
      {latest ? (
        <RetestLine retest={latest} findingId={finding.id} />
      ) : (
        <p className="text-sm text-muted-foreground">
          {t(
            'findings.retestPanel.notYet',
            "Not retested yet. A retest re-runs template {rule} against this finding's target.",
            {
              rule: finding.ruleId ?? '',
            }
          )}
        </p>
      )}
      {list.length > 1 && (
        <p className="text-xs text-muted-foreground">
          {t('findings.retestPanel.earlier', 'Earlier:')}{' '}
          {list.slice(1, 4).map((rt, i) => (
            <span key={rt.id}>
              {i > 0 && ', '}
              {metaFor(rt, t).label} <RelativeTime date={rt.created_at} className="text-xs" />
            </span>
          ))}
        </p>
      )}
    </DetailSection>
  )
}

function RetestLine({ retest, findingId }: { retest: FindingRetest; findingId: string }) {
  const { t } = useTranslation()
  const meta = metaFor(retest, t)
  const manual = retest.kind === 'manual'
  const [open, setOpen] = useState(false)
  const { hasPermission } = usePermissions()
  // The run holds the retest's tasks and their logs (Scans > Runs).
  const runId = retest.run_id
  const runLink = runId && hasPermission('scans:read') ? safeHref(runHref(runId)) : undefined
  return (
    <div className="space-y-1" data-slot="retest-latest">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="secondary" className={cn('font-medium', meta.className)}>
          {retest.status === 'pending' && <Loader2 className="h-3 w-3 animate-spin" />}
          {meta.label}
        </Badge>
        <RelativeTime date={retest.completed_at ?? retest.created_at} className="text-xs" />
        {retest.trigger === 'auto' && (
          <span className="text-xs text-muted-foreground">
            · {t('findings.retestPanel.auto', 'auto')}
          </span>
        )}
        {retest.status === 'completed' && !manual && (
          <button
            type="button"
            className="text-xs text-muted-foreground underline-offset-2 hover:underline"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
          >
            {open
              ? t('findings.retestPanel.hideEvidence', 'Hide evidence')
              : t('findings.retestPanel.viewEvidence', 'View evidence')}
          </button>
        )}
        {runLink && (
          <Link
            href={runLink}
            className="text-xs text-muted-foreground underline-offset-2 hover:underline"
          >
            {t('findings.retestPanel.viewRun', 'View run')}
          </Link>
        )}
      </div>
      {retest.reason && (
        <p className="text-xs text-muted-foreground">{toDisplayText(retest.reason, 600)}</p>
      )}
      {manual && retest.notes && (
        <p className="text-xs text-muted-foreground whitespace-pre-line">
          {toDisplayText(retest.notes, 600)}
        </p>
      )}
      {open && <RetestEvidence findingId={findingId} retestId={retest.id ?? ''} />}
    </div>
  )
}

/** The attempt's proof: what the re-run requested and what came back. */
function RetestEvidence({ findingId, retestId }: { findingId: string; retestId: string }) {
  const { t } = useTranslation()
  const { data, isLoading } = useFindingEvidenceItems(findingId, retestId)
  const items = data?.data ?? []
  if (isLoading)
    return (
      <p className="text-xs text-muted-foreground">
        {t('findings.retestPanel.loadingEvidence', 'Loading evidence…')}
      </p>
    )
  if (items.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        {t(
          'findings.retestPanel.noEvidence',
          'The sensor reported no request evidence for this attempt.'
        )}
      </p>
    )
  }
  return <FindingEvidenceItems findingId={findingId} items={items} className="pt-1" />
}
