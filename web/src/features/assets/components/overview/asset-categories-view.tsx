'use client'

/**
 * The inventory overview (`/assets?view=categories`, research/77 §9): what
 * the organization has, where the gaps are, and where to start.
 *
 * One card per lens of the asset type registry, in registry order, with its
 * types and their counts, and what needs attention (new this week, unowned,
 * high risk, names awaiting review), each a link into the filtered
 * inventory. A lens with no assets says how to discover them. The counts
 * come from one aggregate (GET /assets/overview) over the assets the viewer
 * may list, and the totals match the inventory each link opens. No type is
 * named here: a new registry type or lens appears on its own.
 */

import { AssetsSectionTabs } from '../assets-section-tabs'
import Link from '@/components/link'
import type { ReactNode } from 'react'
import { useMemo } from 'react'
import {
  AppWindow,
  ArrowRight,
  Boxes,
  Cloud,
  Container,
  Database,
  GitBranch,
  GitMerge,
  Globe,
  Network,
  RefreshCw,
  Users,
  type LucideIcon,
} from 'lucide-react'
import { Main } from '@/components/layout'
import { EmptyState, PageHeader } from '@/features/shared'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { useAssetTypeRegistry } from '@/features/asset-types/api/use-asset-type-registry'
import { useDedupReviews } from '../../api/use-asset-dedup'
import { useInventoryOverview } from '../../api/use-inventory-overview'
import { buildOverview, type OverviewLens } from '../../lib/inventory-overview'

/** Icons of the registry's lenses; an unknown lens gets the generic one. */
const LENS_ICONS: Record<string, LucideIcon> = {
  external_surface: Globe,
  applications: AppWindow,
  cloud_infra: Cloud,
  containers_k8s: Container,
  code: GitBranch,
  identities: Users,
  data: Database,
  network: Network,
}

/** How a lens's assets get into the inventory, for an empty lens. */
const LENS_HINTS: Record<string, { text: string; action: string; href: string }> = {
  external_surface: {
    text: 'Add your domains to the scope, then run a discovery scan.',
    action: 'Open scope',
    href: '/scope',
  },
  applications: {
    text: 'Discovery finds web applications behind your domains; add an API or a mobile app by hand.',
    action: 'Run a scan',
    href: '/scans',
  },
  code: {
    text: 'Connect a source-code integration to import your repositories.',
    action: 'Connect source code',
    href: '/settings/integrations/scm',
  },
  cloud_infra: {
    text: 'Import hosts and cloud accounts from an integration, or run a network scan.',
    action: 'Open integrations',
    href: '/settings/integrations',
  },
  containers_k8s: {
    text: 'Import clusters and registries from an integration, or add them by hand.',
    action: 'Open integrations',
    href: '/settings/integrations',
  },
  identities: {
    text: 'Import users, roles and service accounts from an integration, or add them by hand.',
    action: 'Open integrations',
    href: '/settings/integrations',
  },
}
const DEFAULT_HINT = {
  text: 'Run a discovery scan, or add assets by hand.',
  action: 'Run a scan',
  href: '/scans',
}

function AttentionChip({
  count,
  label,
  href,
  tone,
}: {
  count: number
  label: string
  href: string
  tone?: 'danger'
}) {
  if (count <= 0) return null
  return (
    <Link
      href={href}
      className={cn(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-xs tabular-nums transition-colors hover:bg-accent/60',
        tone === 'danger' ? 'border-destructive/40 text-destructive' : 'text-muted-foreground'
      )}
    >
      {count.toLocaleString()} {label}
    </Link>
  )
}

function LensCard({ lens }: { lens: OverviewLens }) {
  const Icon = LENS_ICONS[lens.id] ?? Boxes
  const hint = LENS_HINTS[lens.id] ?? DEFAULT_HINT
  const empty = lens.total === 0 && lens.needsReview === 0
  return (
    <Card className={cn(empty && 'border-dashed shadow-none')}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-start gap-2.5">
            <Icon className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
            <div className="min-w-0 space-y-1">
              <CardTitle className="text-base">
                {empty ? (
                  lens.label
                ) : (
                  <Link href={lens.href} className="hover:underline">
                    {lens.label}
                  </Link>
                )}
              </CardTitle>
              {lens.description && <CardDescription>{lens.description}</CardDescription>}
            </div>
          </div>
          <span className="text-lg font-semibold tabular-nums">{lens.total.toLocaleString()}</span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 pt-0">
        {empty ? (
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-sm text-muted-foreground">{hint.text}</p>
            <Button variant="outline" size="sm" asChild>
              <Link href={hint.href}>{hint.action}</Link>
            </Button>
          </div>
        ) : (
          <>
            {(lens.new7d > 0 || lens.unowned > 0 || lens.highRisk > 0 || lens.needsReview > 0) && (
              <div className="flex flex-wrap gap-1.5">
                <AttentionChip count={lens.new7d} label="new this week" href="/assets/changes" />
                <AttentionChip
                  count={lens.unowned}
                  label="unowned"
                  href={lens.unownedHref}
                  tone="danger"
                />
                <AttentionChip
                  count={lens.highRisk}
                  label="high risk"
                  href={lens.highRiskHref}
                  tone="danger"
                />
                <AttentionChip
                  count={lens.needsReview}
                  label="awaiting review"
                  href={lens.reviewHref}
                />
              </div>
            )}
            <ul className="space-y-0.5">
              {lens.types.map((t) => (
                <li key={t.key}>
                  <Link
                    href={t.href}
                    className="group flex items-center justify-between rounded-lg p-2 transition-colors hover:bg-accent/50"
                  >
                    <span className="text-sm">{t.label}</span>
                    <span className="flex items-center gap-2">
                      <span className="text-sm tabular-nums text-muted-foreground">
                        {t.count.toLocaleString()}
                      </span>
                      <ArrowRight className="h-3 w-3 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  )
}

export function AssetCategoriesView({ viewSwitcher }: { viewSwitcher?: ReactNode }) {
  const { registry, isLoading: registryLoading } = useAssetTypeRegistry()
  const { rows, isLoading, error, mutate } = useInventoryOverview()
  const { data: dedupData } = useDedupReviews()
  const dedupCount = dedupData?.data?.length ?? 0

  const lenses = useMemo(() => buildOverview(registry, rows), [registry, rows])
  const total = lenses.reduce((n, l) => n + l.total, 0)
  const loading = isLoading || registryLoading
  // Lenses with assets first, in registry order; empty ones after, as hints.
  const ordered = [
    ...lenses.filter((l) => l.total + l.needsReview > 0),
    ...lenses.filter((l) => l.total + l.needsReview === 0),
  ]

  return (
    <Main>
      <PageHeader
        title="Assets"
        description="Everything your organization owns that can be attacked, by area: open one to work with its assets."
      >
        {viewSwitcher}
      </PageHeader>
      <AssetsSectionTabs />

      {dedupCount > 0 && (
        <Alert className="mt-5">
          <GitMerge className="h-4 w-4" />
          <AlertTitle>
            {dedupCount} duplicate {dedupCount === 1 ? 'set' : 'sets'} to review
          </AlertTitle>
          <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
            <span>
              The correlator flagged assets that look like the same thing: approve the merges or
              keep them separate.
            </span>
            <Button variant="outline" size="sm" asChild>
              <Link href="/assets/duplicates">
                Review
                <ArrowRight className="ms-2 h-4 w-4" />
              </Link>
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {error ? (
        <Alert variant="destructive" className="mt-5">
          <AlertTitle>The overview did not load</AlertTitle>
          <AlertDescription>
            <Button variant="outline" size="sm" className="mt-2" onClick={() => void mutate()}>
              <RefreshCw className="me-2 h-4 w-4" />
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      ) : loading ? (
        <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-44 w-full rounded-xl" />
          ))}
        </div>
      ) : (
        <>
          {total === 0 && (
            <EmptyState
              className="mt-5 border-dashed"
              icon={Boxes}
              title="No assets discovered yet"
              description="Add your domains to the scope and run a discovery scan, connect an integration, or add assets by hand."
              action={
                <div className="flex flex-wrap justify-center gap-2">
                  <Button size="sm" asChild>
                    <Link href="/scans">Run a discovery scan</Link>
                  </Button>
                  <Button variant="outline" size="sm" asChild>
                    <Link href="/scope">Open scope</Link>
                  </Button>
                </div>
              }
            />
          )}
          <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
            {ordered.map((l) => (
              <LensCard key={l.id || 'other'} lens={l} />
            ))}
          </div>
        </>
      )}
    </Main>
  )
}
