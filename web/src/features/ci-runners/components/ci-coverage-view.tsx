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
import { Permission, usePermissions } from '@/lib/permissions'
import { cn } from '@/lib/utils'

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

function capabilityTitle(c: CICapabilityCoverage): string {
  const state = isCoverageState(c.state) ? COVERAGE_STATE_META[c.state].description : ''
  const parts = [state]
  if (c.source_kind) {
    parts.push(
      `Last: ${SOURCE_KIND_LABEL[c.source_kind] ?? c.source_kind}${c.source_name ? ` (${c.source_name})` : ''}` +
        (c.last_at ? `, ${new Date(c.last_at).toLocaleString()}` : '')
    )
  }
  if (c.expected) parts.push('Expected for this repository.')
  return parts.filter(Boolean).join(' ')
}

/** One capability of one repository as a pill; an expected one that is not fresh is a gap. */
export function CapabilityCell({ c }: { c?: CICapabilityCoverage }) {
  if (!c) return <span className="text-sm text-muted-foreground">—</span>
  const meta = isCoverageState(c.state)
    ? COVERAGE_STATE_META[c.state]
    : { label: c.state ?? '—', tone: 'muted' as const }
  const gap = c.expected && c.state !== 'fresh'
  return (
    <TonePill
      tone={gap ? 'warning' : meta.tone}
      label={gap ? `${meta.label} · expected` : meta.label}
      title={capabilityTitle(c)}
      state={gap ? 'gap' : c.state}
    />
  )
}

export function coverageColumns(opts: {
  canWrite: boolean
  pending: string | null
  onToggleExpected: (r: CIRepositoryCoverage) => void
}): ColumnDef<CIRepositoryCoverage>[] {
  const caps: ColumnDef<CIRepositoryCoverage>[] = CAPABILITIES.map((cap: CICapability) => ({
    id: cap,
    header: CAPABILITY_LABEL[cap],
    cell: ({ row }) => (
      <CapabilityCell c={row.original.capabilities?.find((x) => x.capability === cap)} />
    ),
  }))
  return [
    {
      id: 'repository',
      header: 'Repository',
      cell: ({ row }) => {
        const r = row.original
        return (
          <StackedCell
            truncate
            primary={repositoryPath(r.repository)}
            secondary={[
              r.criticality ? `${r.criticality} criticality` : null,
              r.pipelines
                ? `${r.pipelines} pipeline${r.pipelines === 1 ? '' : 's'}`
                : 'no pipeline',
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
      header: 'Expected',
      cell: ({ row }) => {
        const r = row.original
        if (!opts.canWrite) {
          return (
            <span className="text-sm text-muted-foreground">{r.expected ? 'Expected' : '—'}</span>
          )
        }
        return (
          <Button
            size="sm"
            variant={r.expected ? 'secondary' : 'outline'}
            disabled={opts.pending === r.repository_asset_id}
            aria-pressed={!!r.expected}
            aria-label={`${r.expected ? 'Stop expecting' : 'Expect'} coverage of ${r.repository}`}
            onClick={(e) => {
              e.stopPropagation()
              opts.onToggleExpected(r)
            }}
          >
            {r.expected ? 'Expected' : 'Expect'}
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
  const { can } = usePermissions()
  const canWrite = can(Permission.CIWrite)
  const [filterParam, setFilterParam] = useUrlFilter('coverage', '')
  const filter: CICoverageFilter = isCoverageFilter(filterParam) ? filterParam : ''
  const [q, setQ] = useUrlFilter('q', '')
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 20 })
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
          ? `${repositoryPath(r.repository)} is no longer expected to be covered`
          : `${repositoryPath(r.repository)} is expected to be covered`
      )
      await mutate()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not change the expectation')
    } finally {
      setPending(null)
    }
  }

  const s = data?.summary
  const setFilter = (f: CICoverageFilter) => {
    setFilterParam(filter === f ? '' : f)
    setPagination((p) => ({ ...p, pageIndex: 0 }))
  }
  const metrics: MetricStripItem[] = [
    {
      key: 'repositories',
      label: 'Repositories',
      value: s?.repositories ?? 0,
      detail: 'in your data scope',
    },
    {
      key: 'covered',
      label: 'Covered',
      value: s?.covered ?? 0,
      hint: `of ${s?.repositories ?? 0}`,
      detail: 'at least one capability fresh',
      onClick: () => setFilter('covered'),
      active: filter === 'covered',
    },
    {
      key: 'uncovered',
      label: 'Not looked at',
      value: s?.uncovered ?? 0,
      tone: 'warning',
      detail: 'no capability fresh',
      onClick: () => setFilter('uncovered'),
      active: filter === 'uncovered',
    },
    {
      key: 'gaps',
      label: 'Gaps',
      value: s?.gaps ?? 0,
      tone: 'danger',
      detail: `expected and not fresh · ${s?.expected ?? 0} expected`,
      onClick: () => setFilter('gap'),
      active: filter === 'gap',
    },
  ]
  const drifted = (data?.templates ?? []).filter((t) => (t.drifted ?? 0) > 0)

  const empty = !isLoading && !error && (s?.repositories ?? 0) === 0 && !q && !filter
  return (
    <div className="mt-5 space-y-5">
      {!empty && <MetricStrip loading={isLoading && !data} items={metrics} />}
      {data?.truncated && (
        <p className="text-sm text-muted-foreground">
          Only the first 5,000 repositories are counted.
        </p>
      )}
      {error ? (
        <ErrorState title="Coverage" error={error} onRetry={() => mutate()} />
      ) : empty ? (
        <>
          <div className="flex flex-wrap items-center gap-2">{toolbarStart}</div>
          <EmptyState
            icon={ShieldQuestion}
            title="No repositories in scope"
            description="Coverage lists the repository assets you can see. A repository appears once it is in the inventory, and is covered once a CI pipeline or a daemon scan reports a scanner for it."
          />
        </>
      ) : (
        <DataTable
          columns={coverageColumns({ canWrite, pending, onToggleExpected: toggleExpected })}
          data={data?.data ?? []}
          isLoading={isLoading}
          manualPagination
          pageCount={data?.total_pages ?? 1}
          rowCount={data?.total ?? 0}
          pagination={pagination}
          onPaginationChange={setPagination}
          getRowId={(r) => r.repository_asset_id ?? ''}
          showSearch={false}
          paginationNoun="repositories"
          emptyMessage="No repository matches"
          toolbarStart={
            <>
              {toolbarStart}
              <div className="relative min-w-0 flex-1 sm:max-w-xs">
                <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search repository…"
                  aria-label="Search repositories"
                  value={q}
                  onChange={(e) => {
                    setQ(e.target.value)
                    setPagination((p) => ({ ...p, pageIndex: 0 }))
                  }}
                  className="h-9 ps-9"
                />
              </div>
            </>
          }
        />
      )}
      {drifted.length > 0 && (
        <section aria-label="Template drift" className="rounded-lg border p-4">
          <h3 className="text-sm font-medium">Template drift</h3>
          <p className="mb-2 text-xs text-muted-foreground">
            Reusable workflows whose pipelines run an older version than the newest run.
          </p>
          <ul className="space-y-1 text-sm">
            {drifted.map((t) => (
              <li key={t.template} className={cn('flex flex-wrap gap-x-2')}>
                <span className="font-mono text-xs">{t.template}</span>
                <span className="text-muted-foreground">
                  {t.drifted} of {t.total} pipelines not on {t.current || 'the current version'}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}
