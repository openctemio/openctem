'use client'

/**
 * The fix plan: the fixes that remove the most risk, whether they are
 * already tasks or still suggestions, in one ranked list.
 */

import { useMemo } from 'react'
import { ListChecks } from 'lucide-react'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { MetricStrip, type MetricStripItem } from '@/features/shared'
import { useSuggestionStats, useSuggestions, useTasks } from '../api/use-remediation-hub'
import type { TaskState } from '../api/types'
import { DeadlinePill, TaskProgress, TaskStatePill } from './task-bits'

interface PlanRow {
  id: string
  href: string
  title: string
  risk: number
  findings: number
  kind: 'task' | 'suggestion'
  task?: Parameters<typeof TaskStatePill>[0]['state']
  taskRef?: Parameters<typeof DeadlinePill>[0]['task'] & Parameters<typeof TaskProgress>[0]['task']
}

const OPEN_STATES: TaskState[] = ['open', 'in_progress', 'verifying', 'on_hold']

export function FixPlan() {
  const { t } = useTranslation()
  const tasks = useTasks({ states: OPEN_STATES, sort: 'risk', perPage: 25 })
  const sugg = useSuggestions({ perPage: 25 })
  const stats = useSuggestionStats()
  const mine = useTasks({ mine: true, states: ['open', 'in_progress', 'verifying'], perPage: 1 })
  // Counted on the server over every open task, not over the rows on screen.
  const overdue = useTasks({ states: OPEN_STATES, overdue: true, perPage: 1 })

  const rows = useMemo<PlanRow[]>(() => {
    const out: PlanRow[] = []
    for (const x of tasks.data?.data ?? []) {
      out.push({
        id: x.id,
        href: `/remediation/tasks/${x.id}`,
        title: x.title,
        risk: x.counts.risk_points,
        findings: x.counts.total,
        kind: 'task',
        task: x.state,
        taskRef: x,
      })
    }
    for (const s of sugg.data?.data ?? []) {
      if (s.kind !== 'new_group') continue
      out.push({
        id: s.id,
        href: `/remediation/suggestions?suggestion=${encodeURIComponent(s.id)}`,
        title: s.title,
        risk: s.risk_points,
        findings: s.member_count,
        kind: 'suggestion',
      })
    }
    return out.sort((a, b) => b.risk - a.risk).slice(0, 30)
  }, [tasks.data, sugg.data])

  // A number that has not arrived (or failed) is a dash, never a 0 that reads as good news.
  const num = (q: { data?: { total: number } }) => (q.data ? q.data.total : '—')
  const loading = [tasks, overdue, mine, stats].some((q) => q.isLoading && !q.data)
  const metrics: MetricStripItem[] = [
    { key: 'open', label: t('remediationHub.plan.openTasks'), value: num(tasks) },
    {
      key: 'overdue',
      label: t('remediationHub.plan.overdue'),
      value: num(overdue),
      tone: 'danger',
    },
    {
      key: 'review',
      label: t('remediationHub.plan.toReview'),
      value: stats.data ? stats.data.proposed : '—',
    },
    { key: 'mine', label: t('remediationHub.plan.mine'), value: num(mine) },
  ]

  const failed = [tasks, sugg, stats, mine, overdue].find((q) => q.error)
  if (failed) {
    return (
      <ErrorState
        title={t('remediationHub.plan.loadError')}
        error={failed.error}
        onRetry={() => {
          for (const q of [tasks, sugg, stats, mine, overdue]) void q.mutate()
        }}
      />
    )
  }

  return (
    <div className="space-y-4">
      <MetricStrip items={metrics} loading={loading} />
      {tasks.isLoading && !tasks.data ? (
        <Skeleton className="h-64 w-full" />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={ListChecks}
          title={t('remediationHub.plan.emptyTitle')}
          description={t('remediationHub.plan.emptyDescription')}
          card
        />
      ) : (
        <ol className="divide-y rounded-lg border" aria-label={t('remediationHub.plan.list')}>
          {rows.map((r, i) => (
            <li key={`${r.kind}:${r.id}`} className="flex flex-wrap items-center gap-3 p-3">
              <span className="text-muted-foreground w-6 text-end font-mono text-sm">{i + 1}</span>
              <div className="min-w-0 flex-1 basis-56">
                <Link href={r.href} className="font-medium break-words hover:underline">
                  {r.title}
                </Link>
                <div
                  className="text-muted-foreground text-xs"
                  title={t('remediationHub.risk.explain')}
                >
                  {t('remediationHub.plan.row', undefined, { findings: r.findings, risk: r.risk })}
                </div>
              </div>
              {r.kind === 'task' && r.task && r.taskRef ? (
                <div className="flex flex-wrap items-center gap-2">
                  <TaskStatePill state={r.task} />
                  <DeadlinePill task={r.taskRef} />
                  <TaskProgress task={r.taskRef} className="w-24" />
                </div>
              ) : (
                <Badge variant="outline">{t('remediationHub.plan.suggested')}</Badge>
              )}
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}
