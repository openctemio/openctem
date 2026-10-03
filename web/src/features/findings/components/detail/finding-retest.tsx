'use client'

/**
 * Retest section (RFC-039) — one component for the finding page rail and the
 * finding drawer, on the shared detail frame (DetailSection).
 *
 *   Retest                                   [Retest now]
 *   ● Fixed — no longer detected · 3 min ago
 *     template did not match and the target answered
 *   Earlier: Still present · 2 d ago, Unknown · 9 d ago
 *
 * "Retest now" re-runs the nuclei template that produced the finding against
 * its own target, with a reachability probe. Fixed resolves the finding; still
 * present keeps it (or reopens a resolved one); an unreachable target is
 * "unknown" and changes nothing. Needs findings:verify (the API is the
 * authority; this only hides a button the API would refuse).
 */

import { useEffect, useRef } from 'react'
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
import { usePermissions } from '@/context/permission-provider'
import {
  isRetestable,
  useFindingRetests,
  useRequestRetest,
  type FindingRetest,
} from '../../api/use-finding-retests'

interface RetestMeta {
  label: string
  className: string
}

/** How a retest reads, from its status, outcome and what it did to the finding. */
export function retestMeta(rt: FindingRetest): RetestMeta {
  if (rt.status === 'pending') {
    return { label: 'Retest running', className: 'bg-muted text-muted-foreground' }
  }
  switch (rt.outcome) {
    case 'fixed':
      return {
        label: 'Fixed — no longer detected',
        className: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400', // palette-ok: success accent — the theme has no semantic "success" token
      }
    case 'still_present':
      return rt.prior_status === 'resolved' && rt.result_status !== 'resolved'
        ? { label: 'Regression — reopened', className: SEVERITY_BADGE_SOFT.high }
        : { label: 'Still present', className: SEVERITY_BADGE_SOFT.medium }
    default:
      return { label: 'Unknown', className: 'bg-muted text-muted-foreground' }
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
        <RetestLine retest={latest} />
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

function RetestLine({ retest }: { retest: FindingRetest }) {
  const meta = retestMeta(retest)
  return (
    <div className="space-y-1" data-slot="retest-latest">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="secondary" className={cn('font-medium', meta.className)}>
          {retest.status === 'pending' && <Loader2 className="h-3 w-3 animate-spin" />}
          {meta.label}
        </Badge>
        <RelativeTime date={retest.completed_at ?? retest.created_at} className="text-xs" />
        {retest.trigger === 'auto' && <span className="text-xs text-muted-foreground">· auto</span>}
      </div>
      {retest.reason && <p className="text-xs text-muted-foreground">{retest.reason}</p>}
    </div>
  )
}
