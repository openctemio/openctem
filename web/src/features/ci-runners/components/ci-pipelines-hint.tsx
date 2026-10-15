'use client'

/**
 * One quiet line on the Sensors page: "14 CI pipelines report through CI/CD
 * · 1 failing gate". CI pipelines live only on the CI/CD page (a pipeline is
 * not a sensor), so Sensors never lists them; this line is the way across.
 * It renders nothing until the organization has an active pipeline, and only
 * for a caller who may read CI (the API scopes the counts to the caller).
 */

import Link from '@/components/link'
import { ArrowRight, Workflow } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

import { useCIPipelines } from '../api/use-ci'
import { INACTIVE_PIPELINE_STATUSES } from '../lib/pipeline'
import type { CIPipelineStatus } from '../types'

/** Active and failing-gate pipelines from the list's status counts. */
export function pipelineHintCounts(counts: Record<string, number> | undefined): {
  active: number
  failing: number
} {
  const c = counts ?? {}
  const total = Object.values(c).reduce((a, b) => a + b, 0)
  const inactive = INACTIVE_PIPELINE_STATUSES.reduce(
    (sum, s: CIPipelineStatus) => sum + (c[s] ?? 0),
    0
  )
  return { active: total - inactive, failing: c.failing ?? 0 }
}

export function CIPipelinesHint({
  enabled,
  className,
}: {
  /** The caller may read CI pipelines (ci:read and the scans module). */
  enabled: boolean
  className?: string
}) {
  const { t } = useTranslation()
  // One row is enough: the counts cover every pipeline the caller may see.
  const { data } = useCIPipelines({ perPage: 1 }, { enabled })
  if (!enabled || !data) return null
  const { active, failing } = pipelineHintCounts(data.counts)
  if (active === 0) return null
  return (
    <p
      className={cn(
        'flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground',
        className
      )}
    >
      <Workflow className="h-4 w-4 shrink-0" aria-hidden />
      <Link
        href="/ci-cd"
        className="inline-flex items-center gap-1 rounded-sm hover:text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {t(
          active === 1 ? 'scans.ci.hint.pipelines.one' : 'scans.ci.hint.pipelines.other',
          undefined,
          { count: active }
        )}
        {failing === 0 && <ArrowRight className="h-3.5 w-3.5" aria-hidden />}
      </Link>
      {failing > 0 && (
        <>
          <span aria-hidden>·</span>
          <Link
            href="/ci-cd?pipeline_status=failing"
            className="inline-flex items-center gap-1 rounded-sm font-medium text-destructive hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {t('scans.ci.hint.failing', undefined, { count: failing })}
            <ArrowRight className="h-3.5 w-3.5" aria-hidden />
          </Link>
        </>
      )}
    </p>
  )
}
