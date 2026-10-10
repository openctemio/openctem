'use client'

/**
 * /components/{id}: one package. Versions in use with upgrade advice, where
 * each version is used (with the paths that bring it in and the asset's
 * dependency graph), and its vulnerabilities.
 */

import { useState } from 'react'
import { ArrowLeft, ChevronRight, Copy, GitBranch, Network, PackageX } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import {
  EmptyState,
  ErrorState,
  MetricStrip,
  type MetricStripItem,
  RelativeTime,
  RiskScoreBadge,
  SeverityBadge,
} from '@/features/shared'
import { TableSkeleton } from '@/components/list-page-parts'
import { assetDetailHref } from '@/features/findings/lib/asset-link'
import { useUrlFilter } from '@/hooks/use-url-param'
import {
  useComponent,
  useComponentUsages,
  useComponentVersions,
  useComponentVulnerabilities,
  useDependencyGraph,
  useDependencyPaths,
} from '../api/hooks'
import type { ComponentUsage, ComponentVersion } from '../api/types'
import {
  EcosystemBadge,
  FixPill,
  KevPill,
  LicenseList,
  RelationshipPill,
  SeverityCountsCell,
  useScopeLabel,
} from './component-cells'
import { DependencyGraphView } from './dependency-graph'

type Tab = 'versions' | 'assets' | 'vulnerabilities'

export function ComponentDetailView({ id }: { id: string }) {
  const { t } = useTranslation()
  const { data: pkg, error, isLoading } = useComponent(id)
  const [tabParam, setTabParam] = useUrlFilter('tab', 'versions')
  const tab = (
    ['versions', 'assets', 'vulnerabilities'].includes(tabParam) ? tabParam : 'versions'
  ) as Tab
  const [versionFilter, setVersionFilter] = useState<ComponentVersion | null>(null)

  const copyPurl = async () => {
    if (!pkg) return
    try {
      await navigator.clipboard.writeText(pkg.purl)
      toast.success(t('components.detail.copied', 'Package URL copied'))
    } catch {
      toast.error(t('components.detail.copyFailed', 'Could not copy'))
    }
  }

  if (error) {
    const notFound = (error as { statusCode?: number })?.statusCode === 404
    return (
      <Main>
        {notFound ? (
          <EmptyState
            card
            icon={PackageX}
            title={t('components.detail.notFound', 'Component not found')}
            description={t(
              'components.detail.notFoundHint',
              'No asset you can see uses this package.'
            )}
            action={
              <Button variant="outline" asChild>
                <Link href="/components">{t('components.detail.back', 'All components')}</Link>
              </Button>
            }
          />
        ) : (
          <ErrorState
            title={t('components.detail.loadError', 'Could not load the component')}
            error={error}
          />
        )}
      </Main>
    )
  }

  const total = pkg
    ? pkg.vulnerabilities.critical +
      pkg.vulnerabilities.high +
      pkg.vulnerabilities.medium +
      pkg.vulnerabilities.low
    : 0
  const metrics: MetricStripItem[] = [
    {
      key: 'versions',
      label: t('components.col.versions', 'Versions'),
      value: pkg?.versions_in_use ?? 0,
    },
    {
      key: 'assets',
      label: t('components.col.assets', 'Assets'),
      value: pkg?.assets ?? 0,
      hint: t('components.col.assetsHint', '{direct} direct, {transitive} transitive uses', {
        direct: pkg?.direct_links ?? 0,
        transitive: pkg?.transitive_links ?? 0,
      }),
    },
    {
      key: 'vulns',
      label: t('components.col.vulnerabilities', 'Open vulnerabilities'),
      value: total,
      tone: total ? 'warning' : 'default',
      detail: pkg ? <SeverityCountsCell counts={pkg.vulnerabilities} /> : undefined,
    },
    {
      key: 'kev',
      label: t('components.kpi.kev', 'Known exploited'),
      value: pkg?.kev ?? 0,
      tone: pkg?.kev ? 'danger' : 'default',
    },
    {
      key: 'latest',
      label: t('components.detail.latest', 'Latest version'),
      value: pkg?.health?.latest_version ?? '—',
      hint:
        pkg && !pkg.health
          ? t(
              'components.kpi.outdatedHint',
              'Needs package health data from the vulnerability feed'
            )
          : undefined,
    },
  ]

  return (
    <Main>
      <div className="mb-2">
        <Link
          href="/components"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden />
          {t('components.detail.back', 'All components')}
        </Link>
      </div>
      <header className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-1.5">
          <h1 className="flex flex-wrap items-center gap-2 text-2xl font-semibold tracking-tight">
            <span className="break-all">{pkg?.name ?? '…'}</span>
            {pkg && <EcosystemBadge ecosystem={pkg.ecosystem} />}
            {pkg && (
              <Badge variant="secondary" className="font-normal">
                {pkg.global
                  ? t('components.detail.public', 'Public package')
                  : t('components.detail.private', 'Seen in your inventory')}
              </Badge>
            )}
          </h1>
          {pkg && (
            <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
              <code className="break-all font-mono text-xs">{pkg.purl}</code>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2"
                onClick={copyPurl}
                aria-label={t('components.detail.copy', 'Copy the package URL')}
              >
                <Copy className="h-3.5 w-3.5" aria-hidden />
              </Button>
              <LicenseList licenses={pkg.licenses} max={3} />
              <KevPill count={pkg.kev} />
              <FixPill available={pkg.fix_available} />
            </div>
          )}
          {pkg?.description && (
            <p className="max-w-3xl text-sm text-muted-foreground">{pkg.description}</p>
          )}
        </div>
        {pkg && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">
              {t('components.col.risk', 'Risk')}
            </span>
            <RiskScoreBadge score={pkg.risk_score} />
          </div>
        )}
      </header>

      <MetricStrip loading={isLoading && !pkg} items={metrics} />

      <Tabs value={tab} onValueChange={setTabParam} className="mt-5">
        <TabsList className="w-full justify-start overflow-x-auto sm:w-auto">
          <TabsTrigger value="versions">{t('components.tab.versions', 'Versions')}</TabsTrigger>
          <TabsTrigger value="assets">{t('components.tab.assets', 'Where used')}</TabsTrigger>
          <TabsTrigger value="vulnerabilities">
            {t('components.tab.vulnerabilities', 'Vulnerabilities')}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="versions" className="mt-4">
          <VersionsTable
            id={id}
            onShowUsages={(v) => {
              setVersionFilter(v)
              setTabParam('assets')
            }}
          />
        </TabsContent>
        <TabsContent value="assets" className="mt-4">
          <UsagesTable
            id={id}
            version={versionFilter}
            onClearVersion={() => setVersionFilter(null)}
          />
        </TabsContent>
        <TabsContent value="vulnerabilities" className="mt-4">
          <VulnerabilitiesTable id={id} />
        </TabsContent>
      </Tabs>
    </Main>
  )
}

function VersionsTable({
  id,
  onShowUsages,
}: {
  id: string
  onShowUsages: (v: ComponentVersion) => void
}) {
  const { t } = useTranslation()
  const { versions, isLoading } = useComponentVersions(id)
  if (isLoading && !versions.length) return <TableSkeleton rows={4} />
  return (
    <div className="overflow-x-auto rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t('components.col.version', 'Version')}</TableHead>
            <TableHead>{t('components.col.assets', 'Assets')}</TableHead>
            <TableHead>{t('components.col.vulnerabilities', 'Open vulnerabilities')}</TableHead>
            <TableHead>{t('components.col.upgrade', 'Upgrade to')}</TableHead>
            <TableHead>{t('components.col.license', 'License')}</TableHead>
            <TableHead>{t('components.col.lastSeen', 'Last seen')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {versions.map((v) => (
            <TableRow key={v.id}>
              <TableCell className="font-mono text-sm">
                {v.version || t('components.version.unknown', 'unknown')}
              </TableCell>
              <TableCell>
                <Button
                  variant="link"
                  className="h-auto p-0 tabular-nums"
                  onClick={() => onShowUsages(v)}
                >
                  {v.assets}
                </Button>
              </TableCell>
              <TableCell>
                <div className="flex flex-wrap items-center gap-1.5">
                  <SeverityCountsCell counts={v.vulnerabilities} />
                  <KevPill count={v.kev} />
                </div>
              </TableCell>
              <TableCell>
                {v.upgrade ? (
                  <span className="inline-flex flex-wrap items-center gap-1.5">
                    <code className="font-mono text-sm">{v.upgrade.version}</code>
                    {v.upgrade.breaking && (
                      <Badge variant="outline" className="border-warning/50 text-warning">
                        {t('components.upgrade.breaking', 'Major version')}
                      </Badge>
                    )}
                    {!v.upgrade.complete && (
                      <span className="text-xs text-muted-foreground">
                        {t('components.upgrade.partial', 'fixes some findings')}
                      </span>
                    )}
                  </span>
                ) : (
                  <span className="text-xs text-muted-foreground">—</span>
                )}
              </TableCell>
              <TableCell>
                <LicenseList licenses={v.licenses} />
              </TableCell>
              <TableCell>
                <RelativeTime date={v.last_seen_at} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function UsagesTable({
  id,
  version,
  onClearVersion,
}: {
  id: string
  version: ComponentVersion | null
  onClearVersion: () => void
}) {
  const { t } = useTranslation()
  const scopeLabel = useScopeLabel()
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(25)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [graphFor, setGraphFor] = useState<ComponentUsage | null>(null)
  const { data, isLoading } = useComponentUsages(id, {
    version_id: version?.id,
    page,
    per_page: perPage,
  })

  return (
    <div className="space-y-3">
      {version && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {t('components.usages.versionFilter', 'Version {version}', { version: version.version })}
          <Button variant="ghost" size="sm" onClick={onClearVersion}>
            {t('components.usages.allVersions', 'Show all versions')}
          </Button>
        </div>
      )}
      {isLoading && !data ? (
        <TableSkeleton rows={4} />
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8" />
                <TableHead>{t('components.col.asset', 'Asset')}</TableHead>
                <TableHead>{t('components.col.version', 'Version')}</TableHead>
                <TableHead>{t('components.col.dependency', 'Dependency')}</TableHead>
                <TableHead>{t('components.col.scope', 'Scope')}</TableHead>
                <TableHead>{t('components.col.location', 'Manifest')}</TableHead>
                <TableHead>{t('components.col.findings', 'Open findings')}</TableHead>
                <TableHead className="text-end">{t('components.col.actions', 'Actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data?.data ?? []).map((u) => {
                const open = expanded === u.id
                return (
                  <UsageRow
                    key={u.id}
                    usage={u}
                    open={open}
                    onToggle={() => setExpanded(open ? null : u.id)}
                    onGraph={() => setGraphFor(u)}
                    scopeLabel={String(scopeLabel(u.scope))}
                  />
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}
      {data && data.total > 0 && (
        <PageControls
          page={page}
          perPage={perPage}
          total={data.total}
          onPage={setPage}
          onPerPage={(n) => {
            setPerPage(n)
            setPage(1)
          }}
        />
      )}
      <Dialog open={!!graphFor} onOpenChange={(o) => !o && setGraphFor(null)}>
        <DialogContent size="xl">
          <DialogHeader>
            <DialogTitle>
              {t('components.graph.title', 'Dependencies of {asset}', {
                asset: graphFor?.asset_name ?? '',
              })}
            </DialogTitle>
            <DialogDescription>
              {t(
                'components.graph.description',
                'Centered on {name} {version}: the packages that bring it in and the ones it brings in.',
                {
                  name: graphFor?.name ?? '',
                  version: graphFor?.version ?? '',
                }
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>{graphFor && <AssetGraph usage={graphFor} />}</DialogBody>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function UsageRow({
  usage: u,
  open,
  onToggle,
  onGraph,
  scopeLabel,
}: {
  usage: ComponentUsage
  open: boolean
  onToggle: () => void
  onGraph: () => void
  scopeLabel: string
}) {
  const { t } = useTranslation()
  return (
    <>
      <TableRow>
        <TableCell>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0"
            aria-expanded={open}
            aria-label={t('components.usages.paths', 'Show how this package is brought in')}
            onClick={onToggle}
          >
            <ChevronRight
              className={`h-4 w-4 transition-transform ${open ? 'rotate-90' : ''}`}
              aria-hidden
            />
          </Button>
        </TableCell>
        <TableCell>
          <Link href={assetDetailHref(u.asset_id)} className="font-medium hover:underline">
            {u.asset_name}
          </Link>
          <div className="text-xs text-muted-foreground">{u.asset_type}</div>
        </TableCell>
        <TableCell className="font-mono text-sm">{u.version}</TableCell>
        <TableCell>
          <RelationshipPill relationship={u.relationship} />
          {u.depth != null && u.depth > 0 && (
            <span className="ms-1 text-xs text-muted-foreground">
              {t('components.usages.depth', 'depth {depth}', { depth: u.depth })}
            </span>
          )}
        </TableCell>
        <TableCell className="text-sm">{scopeLabel}</TableCell>
        <TableCell className="max-w-[16rem] truncate font-mono text-xs" title={u.location}>
          {u.location || '—'}
        </TableCell>
        <TableCell className="tabular-nums">{u.open_findings}</TableCell>
        <TableCell className="text-end">
          <Button variant="ghost" size="sm" onClick={onGraph}>
            <Network className="me-1.5 h-4 w-4" aria-hidden />
            {t('components.usages.graph', 'Graph')}
          </Button>
        </TableCell>
      </TableRow>
      {open && (
        <TableRow>
          <TableCell />
          <TableCell colSpan={7}>
            <UsagePaths usage={u} />
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

function UsagePaths({ usage }: { usage: ComponentUsage }) {
  const { t } = useTranslation()
  const { paths, isLoading } = useDependencyPaths(usage.asset_id, usage.version_id)
  if (isLoading)
    return <p className="text-sm text-muted-foreground">{t('common.loading', 'Loading…')}</p>
  if (!paths.length || paths.every((p) => p.length <= 1)) {
    return (
      <p className="text-sm text-muted-foreground">
        {t(
          'components.usages.noPaths',
          'Declared directly by the project (no parent package recorded).'
        )}
      </p>
    )
  }
  return (
    <ul className="space-y-1.5">
      {paths.map((path, i) => (
        <li key={i} className="flex flex-wrap items-center gap-1 text-sm">
          <GitBranch className="me-1 h-3.5 w-3.5 text-muted-foreground" aria-hidden />
          {path.map((n, j) => (
            <span key={n.id} className="inline-flex items-center gap-1">
              {j > 0 && <ChevronRight className="h-3 w-3 text-muted-foreground" aria-hidden />}
              <Link href={`/components/${n.component_id}`} className="hover:underline">
                {n.name}
                <span className="ms-0.5 font-mono text-xs text-muted-foreground">{n.version}</span>
              </Link>
            </span>
          ))}
        </li>
      ))}
    </ul>
  )
}

function AssetGraph({ usage }: { usage: ComponentUsage }) {
  const { t } = useTranslation()
  const { graph, isLoading } = useDependencyGraph(usage.asset_id, usage.version_id)
  if (isLoading || !graph)
    return <p className="text-sm text-muted-foreground">{t('common.loading', 'Loading…')}</p>
  return <DependencyGraphView graph={graph} focusVersionId={usage.version_id} />
}

function VulnerabilitiesTable({ id }: { id: string }) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(25)
  const [includeResolved, setIncludeResolved] = useState(false)
  const { data, isLoading } = useComponentVulnerabilities(id, {
    include_resolved: includeResolved,
    page,
    per_page: perPage,
  })
  if (isLoading && !data) return <TableSkeleton rows={4} />
  return (
    <div className="space-y-3">
      <label className="inline-flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={includeResolved}
          onChange={(e) => setIncludeResolved(e.target.checked)}
        />
        {t('components.vulns.includeResolved', 'Include closed findings')}
      </label>
      {data && data.total === 0 ? (
        <p className="rounded-md border p-4 text-sm text-muted-foreground">
          {t(
            'components.vulns.empty',
            'No vulnerabilities recorded for this package on the assets you can see.'
          )}
        </p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('components.col.vulnerability', 'Vulnerability')}</TableHead>
                <TableHead>{t('components.col.severity', 'Severity')}</TableHead>
                <TableHead>{t('components.col.affected', 'Affected versions')}</TableHead>
                <TableHead>{t('components.col.fixedIn', 'Fixed in')}</TableHead>
                <TableHead>{t('components.col.assets', 'Assets')}</TableHead>
                <TableHead>{t('components.col.findings', 'Open findings')}</TableHead>
                <TableHead>{t('components.col.vex', 'VEX')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data?.data ?? []).map((v) => (
                <TableRow key={v.vulnerability_id}>
                  <TableCell>
                    <Link
                      href={`/findings?cve_id=${encodeURIComponent(v.cve_id)}`}
                      className="font-medium hover:underline"
                    >
                      {v.cve_id || v.title}
                    </Link>
                    <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                      {v.cvss_score != null && <span>CVSS {v.cvss_score.toFixed(1)}</span>}
                      {v.epss_score != null && <span>EPSS {(v.epss_score * 100).toFixed(1)}%</span>}
                      {v.in_cisa_kev && <KevPill count={1} />}
                    </div>
                  </TableCell>
                  <TableCell>
                    <SeverityBadge
                      severity={v.severity as Parameters<typeof SeverityBadge>[0]['severity']}
                    />
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {v.affected_versions.join(', ') || '—'}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {v.fixed_versions.join(', ') || '—'}
                  </TableCell>
                  <TableCell className="tabular-nums">{v.affected_assets_count}</TableCell>
                  <TableCell className="tabular-nums">{v.open_finding_count}</TableCell>
                  <TableCell className="text-xs">{v.vex_status || '—'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {data && data.total > perPage && (
        <PageControls
          page={page}
          perPage={perPage}
          total={data.total}
          onPage={setPage}
          onPerPage={(n) => {
            setPerPage(n)
            setPage(1)
          }}
        />
      )}
    </div>
  )
}

/** Page controls for the plain tables of this page. */
function PageControls({
  page,
  perPage,
  total,
  onPage,
  onPerPage,
}: {
  page: number
  perPage: number
  total: number
  onPage: (p: number) => void
  onPerPage: (n: number) => void
}) {
  const { t } = useTranslation()
  const pages = Math.max(1, Math.ceil(total / perPage))
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
      <span className="text-muted-foreground">
        {t('components.pager.summary', 'Page {page} of {pages} ({total} rows)', {
          page,
          pages,
          total,
        })}
      </span>
      <div className="flex items-center gap-2">
        <select
          className="h-8 rounded-md border bg-background px-2 text-sm"
          value={perPage}
          aria-label={t('components.pager.perPage', 'Rows per page')}
          onChange={(e) => onPerPage(Number(e.target.value))}
        >
          {[25, 50, 100].map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          {t('components.pager.previous', 'Previous')}
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={page >= pages}
          onClick={() => onPage(page + 1)}
        >
          {t('components.pager.next', 'Next')}
        </Button>
      </div>
    </div>
  )
}
