'use client'

import { PossiblePathLabel } from '@/components/ui/possible-path-label'
import { useMemo, useState } from 'react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import {
  EmptyState,
  ErrorState,
  FilterSelect,
  ListSearch,
  MetricStrip,
  PageHeader,
  PageStack,
} from '@/features/shared'
import {
  GraphLegend,
  GraphNote,
  GraphToolbar,
  type GraphLegendItem,
} from '@/components/graph-page/graph-page'
import { KevBadge } from '@/components/ui/kev-badge'
import { useExposureChains, PathGraph } from '@/features/attack-surface'
import { attackPathHref } from '@/features/attack-surface/lib/attack-path-model'
import type { ExposureChain, PathGraphPath, PathGraphNode } from '@/features/attack-surface'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { ShieldCheck, ArrowRight, Network, SearchX } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'

// ============================================================
// Map an exposure chain onto the generic path-graph model.
// hops[] is ordered entry → … → target; per-chain KEV/critical
// counts and criticality attach to the target node.
// ============================================================

function chainToPath(chain: ExposureChain, maxScore: number): PathGraphPath {
  const lastIdx = chain.hops.length - 1
  const nodes: PathGraphNode[] = chain.hops.map((hop, idx) => {
    const isTarget = idx === lastIdx
    return {
      id: hop.assetId,
      hidden: hop.hidden,
      name: hop.name,
      assetType: hop.assetType,
      role: idx === 0 ? 'entry' : isTarget ? 'target' : 'hop',
      exposure: hop.exposure,
      criticality: isTarget ? chain.targetCriticality : undefined,
      isCrownJewel: isTarget ? chain.isCrownJewel : undefined,
      kev: isTarget ? chain.kevCount > 0 : undefined,
      href: hop.assetId ? `/findings?asset_id=${hop.assetId}` : undefined,
    }
  })

  return {
    id: `${chain.entryPointId}-${chain.targetId}`,
    nodes,
    score: chain.score,
    scorePct: maxScore > 0 ? (chain.score / maxScore) * 100 : 0,
    kevCount: chain.kevCount,
    criticalCount: chain.criticalCount,
    detailHref: chain.targetId ? attackPathHref(chain.targetId) : undefined,
  }
}

// ============================================================
// Skeleton loading state
// ============================================================

function LoadingSkeleton() {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {[1, 2, 3].map((i) => (
          <Card key={i}>
            <CardHeader className="pb-2">
              <Skeleton className="h-4 w-24" />
            </CardHeader>
            <CardContent>
              <Skeleton className="mb-2 h-8 w-16" />
              <Skeleton className="h-3 w-20" />
            </CardContent>
          </Card>
        ))}
      </section>
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-48" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} className="h-32 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    </>
  )
}

// ============================================================
// No relationship data callout
// ============================================================

function NoRelationshipData() {
  const { t } = useTranslation()
  return (
    <EmptyState
      icon={Network}
      title={t('prioritization.noRelationships.title', 'No relationship data yet')}
      description={t(
        'prioritization.exposureChains.noRelationships',
        'Add relationships between your assets to trace paths from internet-facing entry points.'
      )}
      action={
        <Button size="sm" asChild>
          <Link href="/assets">
            {t('prioritization.goToAssets', 'Go to assets')}
            <ArrowRight className="ms-2 h-4 w-4" />
          </Link>
        </Button>
      }
    />
  )
}

type ChainFilter = 'kev' | 'crown'

// ============================================================
// Page
// ============================================================

export default function ExposureChainsPage() {
  const { t } = useTranslation()
  const { chains: data, error, isLoading, mutate } = useExposureChains()

  const summary = data?.summary
  const chains = useMemo(() => data?.chains ?? [], [data])
  const hasData = summary?.hasRelationshipData === true
  const hasHiddenStep = useMemo(() => chains.some((c) => c.hops.some((h) => h.hidden)), [chains])

  const paths = useMemo(() => {
    const maxScore = chains.length > 0 ? chains[0].score : 1
    return chains.map((chain, idx) => ({
      ...chainToPath(chain, maxScore),
      rank: idx + 1,
    }))
  }, [chains])

  // The chains arrive in one read; the search and the filter narrow what is
  // drawn, in the browser.
  const [search, setSearch] = useState('')
  const [only, setOnly] = useState<ChainFilter | ''>('')
  const shownPaths = useMemo(() => {
    const q = search.trim().toLowerCase()
    return paths.filter((p) => {
      if (only === 'kev' && !(p.kevCount && p.kevCount > 0)) return false
      if (only === 'crown' && !p.nodes[p.nodes.length - 1]?.isCrownJewel) return false
      if (!q) return true
      return p.nodes.some((n) => !n.hidden && n.name.toLowerCase().includes(q))
    })
  }, [paths, search, only])
  const filtered = search.trim() !== '' || only !== ''

  const legendItems: GraphLegendItem[] = [
    {
      key: 'asset',
      mark: <span className="h-3 w-5 rounded-sm border-2 bg-card" />,
      label: t('prioritization.exposureChains.legendAsset', 'An asset on the chain; opens its findings'),
    },
    {
      key: 'hidden',
      mark: <span className="h-3 w-5 rounded-sm border-2 border-dashed" />,
      label: t('prioritization.attackPath.hidden', 'Outside your access'),
    },
    {
      key: 'link',
      mark: <span className="h-0.5 w-5 rounded bg-border-strong" />,
      label: t('prioritization.exposureChains.legendLink', 'A relationship an attacker could follow'),
    },
    {
      key: 'linkKev',
      mark: <span className="h-0.5 w-5 rounded bg-destructive" />,
      label: t(
        'prioritization.exposureChains.legendLinkKev',
        'A chain that ends at a known exploited finding'
      ),
    },
    {
      key: 'kev',
      mark: <KevBadge />,
      label: t('prioritization.exposureChains.legendKev', 'Known exploited finding on the target'),
    },
  ]

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('prioritization.exposureChains.title', 'Exposure chains')}
          description={
            <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span>
                {t(
                  'prioritization.exposureChains.description',
                  'Possible paths from internet-facing entry points to assets with KEV or critical findings, ranked by urgency.'
                )}
              </span>
              <PossiblePathLabel />
            </span>
          }
        />

        {isLoading ? (
          <LoadingSkeleton />
        ) : error ? (
          // A failed read is not "no data": say we could not find out.
          <ErrorState
            title={t('prioritization.errorTitle.exposureChains', 'exposure chains')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : !hasData ? (
          <NoRelationshipData />
        ) : (
          <>
            <MetricStrip
              items={[
                {
                  key: 'entries',
                  label: t('prioritization.exposureChains.stat.entries', 'Entry points'),
                  value: summary?.entryPoints ?? 0,
                  hint: t(
                    'prioritization.exposureChains.stat.entriesHint',
                    'Internet-facing assets'
                  ),
                  href: '/assets?internet_facing=true',
                },
                {
                  key: 'targets',
                  label: t('prioritization.exposureChains.stat.targets', 'Targets at risk'),
                  value: summary?.targetsAtRisk ?? 0,
                  tone: 'danger',
                  hint: t(
                    'prioritization.exposureChains.stat.targetsHint',
                    'Reachable KEV/critical assets'
                  ),
                  href: '#ranked-chains',
                },
                {
                  key: 'chains',
                  label: t('prioritization.exposureChains.stat.chains', 'Exposure chains'),
                  value: summary?.totalChains ?? 0,
                  hint: t(
                    'prioritization.exposureChains.stat.chainsHint',
                    'Entry-point to dangerous asset'
                  ),
                  href: '#ranked-chains',
                },
              ]}
            />

            <GraphToolbar
              label={t('prioritization.exposureChains.toolbarLabel', 'Exposure chain filters')}
              end={
                <>
                  <GraphLegend items={legendItems} testId="exposure-chains-legend" />
                  <GraphNote
                    label={t('prioritization.exposureChains.howTitle', 'How chains are built')}
                    title={t('prioritization.exposureChains.howTitle', 'How chains are built')}
                  >
                    <p>
                      <strong className="text-foreground">
                        {t('prioritization.exposureChains.howEntryLead', 'Entry point')}
                      </strong>
                      {': '}
                      {t(
                        'prioritization.exposureChains.howEntry',
                        'any asset with public exposure, the foothold an attacker reaches directly.'
                      )}
                    </p>
                    <p>
                      <strong className="text-foreground">
                        {t('prioritization.exposureChains.howPathLead', 'Path')}
                      </strong>
                      {': '}
                      {t(
                        'prioritization.exposureChains.howPath',
                        'search over attack-path relationships (runs_on, depends_on, exposes, stores_data_in, ...) capturing the shortest route to each dangerous asset.'
                      )}
                    </p>
                    <p>
                      <strong className="text-foreground">
                        {t('prioritization.exposureChains.howTargetLead', 'Target')}
                      </strong>
                      {': '}
                      {t(
                        'prioritization.exposureChains.howTarget',
                        'an asset carrying open KEV or critical findings. A directly-exposed target (0 hops) is the most urgent.'
                      )}
                    </p>
                    <p>
                      <strong className="text-foreground">
                        {t('prioritization.exposureChains.howScoreLead', 'Score')}
                      </strong>
                      {': '}
                      {t(
                        'prioritization.exposureChains.howScore',
                        'KEV-weighted danger x criticality x crown-jewel, amplified the closer the target sits to the internet.'
                      )}
                    </p>
                    {hasHiddenStep && (
                      <p>
                        {t(
                          'prioritization.exposureChains.hiddenNote',
                          'Steps shown as "Outside your access" are assets you are not allowed to see. The path to your asset is real.'
                        )}
                      </p>
                    )}
                  </GraphNote>
                </>
              }
            >
              <ListSearch
                value={search}
                onChange={setSearch}
                placeholder={t('prioritization.exposureChains.search', 'Search chains by asset')}
              />
              <FilterSelect<ChainFilter>
                label={t('prioritization.exposureChains.filterLabel', 'Target')}
                value={only}
                onChange={setOnly}
                options={[
                  {
                    value: 'kev',
                    label: t('prioritization.exposureChains.filterKev', 'Known exploited'),
                  },
                  {
                    value: 'crown',
                    label: t('prioritization.exposureChains.filterCrown', 'Crown jewel'),
                  },
                ]}
              />
            </GraphToolbar>

            {/* The ranked list is a column of bordered chain rows, so it sits under a
                section heading rather than inside another card. */}
            <section id="ranked-chains" className="scroll-mt-20 space-y-3">
              <div>
                <h2 className="text-section">
                  {t('prioritization.exposureChains.rankedTitle', 'Chains ranked by urgency')}
                </h2>
                <p className="text-body text-muted-foreground">
                  {t(
                    'prioritization.exposureChains.rankedHint',
                    'Each chain is the shortest path. Click a node to open its findings.'
                  )}
                </p>
              </div>
              <PathGraph
                paths={shownPaths}
                empty={
                  filtered ? (
                    <EmptyState
                      icon={SearchX}
                      title={t('prioritization.exposureChains.noMatchTitle', 'No chain matches')}
                      description={t(
                        'prioritization.exposureChains.noMatchDescription',
                        'No chain passes through an asset with that name or filter.'
                      )}
                      action={
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setSearch('')
                            setOnly('')
                          }}
                        >
                          {t('prioritization.exposureChains.clearFilters', 'Clear filters')}
                        </Button>
                      }
                    />
                  ) : (
                    <EmptyState
                      icon={ShieldCheck}
                      title={t('prioritization.exposureChains.emptyTitle', 'No exposure chains')}
                      description={t(
                        'prioritization.exposureChains.emptyDescription',
                        'No internet-facing entry point reaches an asset with KEV or critical findings.'
                      )}
                    />
                  )
                }
              />
            </section>
          </>
        )}
      </PageStack>
    </Main>
  )
}
