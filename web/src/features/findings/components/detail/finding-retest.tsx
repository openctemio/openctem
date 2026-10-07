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
 * did not match) moves the finding to validated_fixed, or resolves it when the
 * organization auto-resolves; still vulnerable keeps it (or reopens a resolved
 * one); not reproduced and inconclusive change nothing. Each attempt's
 * request and response are shown under "View evidence". Needs
 * findings:verify (the API is the authority; this only hides a button the API
 * would refuse).
 */

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
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
import {
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

/** Why a retest was inconclusive, in words. */
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
export function retestMeta(rt: FindingRetest): RetestMeta {
  if (rt.status === 'pending') {
    return { label: 'Retest running', className: 'bg-muted text-muted-foreground' }
  }
  switch (rt.outcome) {
    case 'confirmed_fixed':
      return rt.result_status === 'resolved'
        ? { label: 'Fixed — verified and resolved', className: SUCCESS_SOFT }
        : { label: 'Verified fixed — awaiting confirmation', className: SUCCESS_SOFT }
    case 'still_vulnerable':
      return rt.prior_status === 'resolved' && rt.result_status !== 'resolved'
        ? { label: 'Regression — reopened', className: SEVERITY_BADGE_SOFT.high }
        : { label: 'Still vulnerable', className: SEVERITY_BADGE_SOFT.medium }
    case 'not_reproduced':
      return {
        label: 'Not reproduced — not confirmed',
        className: 'bg-muted text-muted-foreground',
      }
    default: {
      const why = INCONCLUSIVE_TEXT[rt.reason_code ?? ''] ?? ''
      return {
        label: why ? `Inconclusive: ${why}` : 'Inconclusive',
        className: 'bg-muted text-muted-foreground',
      }
    }
  }
}

interface FindingRetestSectionProps {
  finding: { id: string; toolName?: string; ruleId?: string; status?: string }
  className?: string
}

export function FindingRetestSection({ finding, className }: FindingRetestSectionProps) {
  const { hasPermission } = usePermissions()
  const { mutate } = useSWRConfig()
  const retestable = isRetestable(finding)
  // History is shown for any nuclei finding, also one no longer retestable (e.g. false positive).
  const { data } = useFindingRetests(
    (finding.toolName ?? '').toLowerCase() === 'nuclei' ? finding.id : null
  )
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
      toast.success('Retest started', {
        description: 'The template that found this issue is running again against its target.',
      })
    } catch (error) {
      toast.error(getErrorMessage(error, 'Could not start the retest'))
    }
  }

  return (
    <DetailSection
      title="Retest"
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
            title="Re-run the check that found this issue against its target"
          >
            {isMutating || running ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}
            Retest now
          </Button>
        ) : undefined
      }
    >
      {latest ? (
        <RetestLine retest={latest} findingId={finding.id} />
      ) : (
        <p className="text-sm text-muted-foreground">
          Not retested yet. A retest re-runs template{' '}
          <span className="font-medium text-foreground">{finding.ruleId}</span> against this
          finding&apos;s target.
        </p>
      )}
      {list.length > 1 && (
        <p className="text-xs text-muted-foreground">
          Earlier:{' '}
          {list.slice(1, 4).map((rt, i) => (
            <span key={rt.id}>
              {i > 0 && ', '}
              {retestMeta(rt).label} <RelativeTime date={rt.created_at} className="text-xs" />
            </span>
          ))}
        </p>
      )}
    </DetailSection>
  )
}

function RetestLine({ retest, findingId }: { retest: FindingRetest; findingId: string }) {
  const meta = retestMeta(retest)
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
        {retest.trigger === 'auto' && <span className="text-xs text-muted-foreground">· auto</span>}
        {retest.status === 'completed' && (
          <button
            type="button"
            className="text-xs text-muted-foreground underline-offset-2 hover:underline"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
          >
            {open ? 'Hide evidence' : 'View evidence'}
          </button>
        )}
        {runLink && (
          <Link
            href={runLink}
            className="text-xs text-muted-foreground underline-offset-2 hover:underline"
          >
            View run
          </Link>
        )}
      </div>
      {retest.reason && (
        <p className="text-xs text-muted-foreground">{toDisplayText(retest.reason, 600)}</p>
      )}
      {open && <RetestEvidence findingId={findingId} retestId={retest.id ?? ''} />}
    </div>
  )
}

/** The attempt's proof: what the re-run requested and what came back. */
function RetestEvidence({ findingId, retestId }: { findingId: string; retestId: string }) {
  const { data, isLoading } = useFindingEvidenceItems(findingId, retestId)
  const items = data?.data ?? []
  if (isLoading) return <p className="text-xs text-muted-foreground">Loading evidence…</p>
  if (items.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        The sensor reported no request evidence for this attempt.
      </p>
    )
  }
  return <FindingEvidenceItems findingId={findingId} items={items} className="pt-1" />
}
