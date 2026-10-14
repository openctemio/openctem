'use client'

/**
 * The CI/CD integration page, Coverage view (api RFC-051 §10.6): which
 * repositories are not being looked at, per capability (SAST, SCA, secrets,
 * IaC), and since when, from any executor (a CI pipeline or a daemon scan).
 * The API lists only repositories in the caller's data scope. Gaps (an
 * expected capability that is not fresh) come first.
 */

import { useState } from 'react'
import { Search, ShieldQuestion } from 'lucide-react'
import { toast } from 'sonner'
import type { ColumnDef } from '@tanstack/react-table'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  DataTable,
  EmptyState,
  ErrorState,
  MetricStrip,
  StackedCell,
  type MetricStripItem,
} from '@/features/shared'
import { TonePill } from '@/features/shared/components/tone-pill'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { Permission, usePermissions } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'

import { useCICoverage, useSetCoverageExpectation } from '../api/use-ci'
import {
  CAPABILITIES,
  CAPABILITY_LABEL,
  COVERAGE_STATE_META,
  SOURCE_KIND_LABEL,
  isCoverageFilter,
  isCoverageState,
} from '../lib/coverage'
import { repositoryPath } from '../lib/pipeline'
import type {
  CICapability,
  CICapabilityCoverage,
  CICoverageFilter,
  CIRepositoryCoverage,
} from '../types'

type TFn = ReturnType<typeof useTranslation>['t']

function capabilityTitle(c: CICapabilityCoverage, t: TFn): string {
  const state = isCoverageState(c.state)
    ? t(`scans.ci.coverage.state.${c.state}.description`, COVERAGE_STATE_META[c.state].description)
    : ''
  const parts = [state]
  if (c.source_kind) {
    const kind = SOURCE_KIND_LABEL[c.source_kind]
      ? t(`scans.ci.coverage.source.${c.source_kind}`, SOURCE_KIND_LABEL[c.source_kind])
      : c.source_kind
    parts.push(
      t('scans.ci.coverage.last', 'Last: {source}', {
        source: `${kind}${c.source_name ? ` (${c.source_name})` : ''}`,
      }) + (c.last_at ? `, ${new Date(c.last_at).toLocaleString()}` : '')
    )
  }
  if (c.expected)
    parts.push(
      t(
        'scans.ci.coverage.expectedHere',
        'Expected for this repository. Every CI run of it must report these capabilities, or the gate fails it.'
      )
    )
  return parts.filter(Boolean).join(' ')
}

/** One capability of one repository as a pill; an expected one that is not fresh is a gap. */
export function CapabilityCell({ c }: { c?: CICapabilityCoverage }) {
  const { t } = useTranslation()
  if (!c) return <span className="text-sm text-muted-foreground">—</span>
  const meta = isCoverageState(c.state)
    ? {
        label: t(`scans.ci.coverage.state.${c.state}.label`, COVERAGE_STATE_META[c.state].label),
        tone: COVERAGE_STATE_META[c.state].tone,
      }
    : { label: c.state ?? '—', tone: 'muted' as const }
  const gap = c.expected && c.state !== 'fresh'
  return (
    <TonePill
      tone={gap ? 'warning' : meta.tone}
      label={
        gap
          ? t('scans.ci.coverage.stateExpected', '{state} · expected', { state: meta.label })
          : meta.label
      }
      title={capabilityTitle(c, t)}
      state={gap ? 'gap' : c.state}
    />
  )
}

export function coverageColumns(opts: {
  canWrite: boolean
  pending: string | null
  onToggleExpected: (r: CIRepositoryCoverage) => void
  t: TFn
}): ColumnDef<CIRepositoryCoverage>[] {
  const { t } = opts
  const caps: ColumnDef<CIRepositoryCoverage>[] = CAPABILITIES.map((cap: CICapability) => ({
    id: cap,
    header: t(`scans.ci.coverage.capability.${cap}`, CAPABILITY_LABEL[cap]),
    cell: ({ row }) => (
      <CapabilityCell c={row.original.capabilities?.find((x) => x.capability === cap)} />
    ),
  }))
  return [
    {
      id: 'repository',
      header: t('scans.ci.col.repository', 'Repository'),
      cell: ({ row }) => {
        const r = row.original
        return (
          <StackedCell
            truncate
            primary={repositoryPath(r.repository)}
            secondary={[
              r.criticality
                ? t('scans.ci.coverage.criticality', '{level} criticality', {
                    level: r.criticality,
                  })
                : null,
              r.pipelines
                ? r.pipelines === 1
                  ? t('scans.ci.coverage.onePipeline', '1 pipeline')
                  : t('scans.ci.coverage.pipelines', '{count} pipelines', { count: r.pipelines })
                : t('scans.ci.coverage.noPipeline', 'no pipeline'),
            ]
              .filter(Boolean)
              .join(' · ')}
          />
        )
      },
    },
    ...caps,
    {
      id: 'expected',
      header: t('scans.ci.coverage.expected', 'Expected'),
      cell: ({ row }) => {
        const r = row.original
        if (!opts.canWrite) {
          return (
            <span className="text-sm text-muted-foreground">
              {r.expected ? t('scans.ci.coverage.expected', 'Expected') : '—'}
            </span>
          )
        }
        return (
          <Button
            size="sm"
            variant={r.expected ? 'secondary' : 'outline'}
            disabled={opts.pending === r.repository_asset_id}
            aria-pressed={!!r.expected}
            aria-label={
              r.expected
                ? t(
                    'scans.ci.coverage.stopExpectLabel',
                    'Stop expecting coverage of {repository}',
                    {
                      repository: r.repository ?? '',
                    }
                  )
                : t('scans.ci.coverage.expectLabel', 'Expect coverage of {repository}', {
                    repository: r.repository ?? '',
                  })
            }
            onClick={(e) => {
              e.stopPropagation()
              opts.onToggleExpected(r)
            }}
          >
            {r.expected
              ? t('scans.ci.coverage.expected', 'Expected')
              : t('scans.ci.coverage.expect', 'Expect')}
          </Button>
        )
      },
    },
  ]
}

export interface CICoverageViewProps {
  /** Controls placed first in the toolbar (the page's mode switch and view lens). */
  toolbarStart?: React.ReactNode
}

export function CICoverageView({ toolbarStart }: CICoverageViewProps) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  // Coverage expectations are part of the gate (scans:ci:policy).
  const canWrite = can(Permission.CIPolicy)
  const [filterParam, setFilterParam] = useUrlFilter('coverage', '')
  const filter: CICoverageFilter = isCoverageFilter(filterParam) ? filterParam : ''
  const [q, setQ] = useUrlFilter('q', '')
  const { pagination, setPagination, setPage } = useListParams({ defaultPageSize: 20 })
  const [pending, setPending] = useState<string | null>(null)
  const { data, error, isLoading, mutate } = useCICoverage({
    filter,
    search: q,
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
  })
  const { trigger } = useSetCoverageExpectation()

  const toggleExpected = async (r: CIRepositoryCoverage) => {
    if (!r.repository_asset_id) return
    setPending(r.repository_asset_id)
    try {
      await trigger({ assetId: r.repository_asset_id, expected: !r.expected })
      toast.success(
        r.expected
          ? t(
              'scans.ci.coverage.noLongerExpected',
              '{repository} is no longer expected to be covered',
              {
                repository: repositoryPath(r.repository),
              }
            )
          : t('scans.ci.coverage.nowExpected', '{repository} is expected to be covered', {
              repository: repositoryPath(r.repository),
            })
      )
      await mutate()
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('scans.ci.coverage.expectFailed', 'Could not change the expectation')
      )
    } finally {
      setPending(null)
    }
  }

  const s = data?.summary
  const setFilter = (f: CICoverageFilter) => {
    setFilterParam(filter === f ? '' : f)
    setPage(1)
  }
  const metrics: MetricStripItem[] = [
    {
      key: 'repositories',
      label: t('scans.ci.coverage.repositories', 'Repositories'),
      value: s?.repositories ?? 0,
      detail: t('scans.ci.coverage.inScope', 'in your data scope'),
    },
    {
      key: 'covered',
      label: t('scans.ci.coverage.covered', 'Covered'),
      value: s?.covered ?? 0,
      hint: t('scans.ci.metric.ofTotal', 'of {total}', { total: s?.repositories ?? 0 }),
      detail: t('scans.ci.coverage.coveredDetail', 'at least one capability fresh'),
      onClick: () => setFilter('covered'),
      active: filter === 'covered',
    },
    {
      key: 'uncovered',
      label: t('scans.ci.coverage.uncovered', 'Not looked at'),
      value: s?.uncovered ?? 0,
      tone: 'warning',
      detail: t('scans.ci.coverage.uncoveredDetail', 'no capability fresh'),
      onClick: () => setFilter('uncovered'),
      active: filter === 'uncovered',
    },
    {
      key: 'gaps',
      label: t('scans.ci.coverage.gaps', 'Gaps'),
      value: s?.gaps ?? 0,
      tone: 'danger',
      detail: t('scans.ci.coverage.gapsDetail', 'expected and not fresh · {count} expected', {
        count: s?.expected ?? 0,
      }),
      onClick: () => setFilter('gap'),
      active: filter === 'gap',
    },
  ]
  const drifted = (data?.templates ?? []).filter((d) => (d.drifted ?? 0) > 0)

  const empty = !isLoading && !error && (s?.repositories ?? 0) === 0 && !q && !filter
  return (
    <div className="mt-5 space-y-5">
      {!empty && <MetricStrip loading={isLoading && !data} items={metrics} />}
      {data?.truncated && (
        <p className="text-sm text-muted-foreground">
          {t('scans.ci.coverage.truncated', 'Only the first 5,000 repositories are counted.')}
        </p>
      )}
      {error ? (
        <ErrorState
          title={t('scans.ci.view.coverage', 'Coverage')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : empty ? (
        <>
          <div className="flex flex-wrap items-center gap-2">{toolbarStart}</div>
          <EmptyState
            icon={ShieldQuestion}
            title={t('scans.ci.coverage.emptyTitle', 'No repositories in scope')}
            description={t(
              'scans.ci.coverage.empty',
              'Coverage lists the repository assets you can see. A repository appears once it is in the inventory, and is covered once a CI pipeline or a daemon scan reports a scanner for it.'
            )}
          />
        </>
      ) : (
        <DataTable
          columns={coverageColumns({ canWrite, pending, onToggleExpected: toggleExpected, t })}
          data={data?.data ?? []}
          isLoading={isLoading}
          manualPagination
          pageCount={data?.total_pages ?? 1}
          rowCount={data?.total ?? 0}
          pagination={pagination}
          onPaginationChange={setPagination}
          getRowId={(r) => r.repository_asset_id ?? ''}
          showSearch={false}
          paginationNoun={t('scans.ci.noun.repositories', 'repositories')}
          emptyMessage={t('scans.ci.coverage.noMatch', 'No repository matches')}
          toolbarStart={
            <>
              {toolbarStart}
              <div className="relative min-w-0 flex-1 sm:max-w-xs">
                <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder={t('scans.ci.coverage.search', 'Search repository…')}
                  aria-label={t('scans.ci.coverage.searchLabel', 'Search repositories')}
                  value={q}
                  onChange={(e) => {
                    setQ(e.target.value)
                    setPage(1)
                  }}
                  className="h-9 ps-9"
                />
              </div>
            </>
          }
        />
      )}
      {drifted.length > 0 && (
        <section
          aria-label={t('scans.ci.coverage.drift', 'Template drift')}
          className="rounded-lg border p-4"
        >
          <h3 className="text-sm font-medium">{t('scans.ci.coverage.drift', 'Template drift')}</h3>
          <p className="mb-2 text-xs text-muted-foreground">
            {t(
              'scans.ci.coverage.driftDescription',
              'Reusable workflows whose pipelines run an older version than the newest run.'
            )}
          </p>
          <ul className="space-y-1 text-sm">
            {drifted.map((d) => (
              <li key={d.template} className={cn('flex flex-wrap gap-x-2')}>
                <span className="font-mono text-xs">{d.template}</span>
                <span className="text-muted-foreground">
                  {t(
                    'scans.ci.coverage.driftLine',
                    '{drifted} of {total} pipelines not on {version}',
                    {
                      drifted: d.drifted ?? 0,
                      total: d.total ?? 0,
                      version:
                        d.current || t('scans.ci.coverage.currentVersion', 'the current version'),
                    }
                  )}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}
