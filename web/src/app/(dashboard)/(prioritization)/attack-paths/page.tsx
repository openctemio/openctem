'use client'

/**
 * Attack paths: how the internet reaches one asset (research/229
 * mockups/attack-path.html). A flow canvas from the internet through entry
 * points and hops to the asset, a list view of the same routes (the default on
 * a phone), choke points ("fix this to cut N paths") and the score of the
 * selected path as a breakdown of step weights. Data:
 * GET /api/v1/attack-surface/attack-paths/{id}, in the viewer's data scope
 * (api/docs/architecture/attack-paths.md); the targets come from the exposure
 * chains.
 */

import { useCallback, useMemo, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { ArrowRight, Crown, GitBranch, List, Network, Route } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useIsMobile } from '@/hooks/use-mobile'
import { usePermissions, Permission } from '@/lib/permissions'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { AddFindingsToTaskDialog } from '@/features/remediation-hub/components/add-findings-to-task-dialog'
import {
  EmptyState,
  ErrorState,
  FilterSelect,
  PageHeader,
  PageStack,
  ViewSwitcher,
} from '@/features/shared'
import { useExposureChains } from '@/features/attack-surface'
import { useAttackPathDetail } from '@/features/attack-surface/hooks/use-attack-path-detail'
import { AttackPathCanvas } from '@/features/attack-surface/components/attack-path-canvas'
import {
  AttackPathLegend,
  AttackPathList,
  ChokePointsCard,
  PathScoreCard,
} from '@/features/attack-surface/components/attack-path-panels'
import {
  assetFindingsHref,
  chokeRows,
  formatWeight,
  nodeByKey,
  shownPaths,
  stepText,
  type Focus,
  type PathMode,
} from '@/features/attack-surface/lib/attack-path-model'

type View = 'canvas' | 'list'

function BodySkeleton() {
  return (
    <div
      className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px]"
      data-testid="attack-path-loading"
    >
      <Skeleton className="h-[560px] w-full rounded-lg" />
      <div className="grid content-start gap-4">
        <Skeleton className="h-48 w-full rounded-lg" />
        <Skeleton className="h-40 w-full rounded-lg" />
      </div>
    </div>
  )
}

export default function AttackPathsPage() {
  const { t, locale } = useTranslation()
  const router = useRouter()
  const params = useSearchParams()
  const isMobile = useIsMobile()
  const { can } = usePermissions()
  const remediationOn = useModuleEnabled('remediation')
  const {
    chains,
    error: chainsError,
    isLoading: chainsLoading,
    mutate: reloadChains,
  } = useExposureChains()

  // Targets: assets at the end of an exposure chain, crown jewels first, then
  // in the chains' urgency order. A target from the URL (a link from an asset
  // or the chains page) is honoured even if it is not in that list.
  const targets = useMemo(() => {
    const seen = new Set<string>()
    const out: { id: string; name: string; crown: boolean }[] = []
    for (const c of chains?.chains ?? []) {
      if (!c.targetId || seen.has(c.targetId)) continue
      seen.add(c.targetId)
      out.push({ id: c.targetId, name: c.targetName, crown: c.isCrownJewel })
    }
    return [...out.filter((o) => o.crown), ...out.filter((o) => !o.crown)]
  }, [chains])
  const targetId = params.get('target') || targets[0]?.id || null
  const mode: PathMode = params.get('paths') === 'all' ? 'all' : 'shortest'
  const view: View = isMobile ? 'list' : params.get('view') === 'list' ? 'list' : 'canvas'

  const { detail, error, isLoading, mutate } = useAttackPathDetail(targetId)
  const [focus, setFocus] = useState<Focus>(null)
  const [selectedRaw, setSelected] = useState(0)
  const [taskOpen, setTaskOpen] = useState(false)

  const setParam = useCallback(
    (key: string, value: string | null) => {
      const q = new URLSearchParams(params.toString())
      if (value === null) q.delete(key)
      else q.set(key, value)
      router.replace(`/attack-paths?${q.toString()}`, { scroll: false })
    },
    [params, router]
  )

  const shown = useMemo(() => (detail ? shownPaths(detail, mode) : []), [detail, mode])
  const selected = shown.includes(selectedRaw) ? selectedRaw : (shown[0] ?? 0)
  const byKey = useMemo(() => (detail ? nodeByKey(detail) : new Map()), [detail])
  const target = detail ? byKey.get(detail.target) : undefined
  const sel = detail?.paths[selected]
  const chokes = useMemo(() => (detail ? chokeRows(detail) : []), [detail])
  const firstChoke = chokes[0]
  const canTask = can(Permission.RemediationWrite) && remediationOn

  const cycle = useCallback(
    (delta: 1 | -1) => {
      if (shown.length < 2) return
      const i = shown.indexOf(selected)
      setSelected(shown[(i + delta + shown.length) % shown.length])
    },
    [shown, selected]
  )

  const openNode = useCallback(
    (key: string) => {
      const n = byKey.get(key)
      if (n && !n.hidden && n.assetId) router.push(assetFindingsHref(n.assetId))
    },
    [byKey, router]
  )

  const computedAt = detail?.computedAt ? new Date(detail.computedAt) : null
  const computedLabel =
    computedAt && !Number.isNaN(computedAt.getTime())
      ? computedAt.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' })
      : ''

  const title =
    target && !target.hidden
      ? t('prioritization.attackPath.titleTo', 'Path to {name}', { name: target.name })
      : t('prioritization.attackPaths.title', 'Attack paths')

  const description =
    sel && detail ? (
      <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="tabular-nums">
          {sel.length === 1
            ? t('prioritization.attackPath.hopOne', '1 hop')
            : t('prioritization.attackPath.hops', '{n} hops', { n: sel.length })}
        </span>
        <span className="tabular-nums">
          {t('prioritization.attackPath.kevSteps', '{n} known exploited', { n: sel.kevSteps })}
        </span>
        {sel.likelihood !== null && (
          <span className="tabular-nums">
            {t('prioritization.attackPath.likelihoodShort', 'Likelihood {w}', {
              w: formatWeight(sel.likelihood),
            })}
          </span>
        )}
        <span>
          {t(
            'prioritization.attackPath.descriptionTail',
            'The product of the step weights, so every step is traceable.'
          )}
        </span>
      </span>
    ) : (
      t(
        'prioritization.attackPath.description',
        'How the internet reaches your assets, and which fix cuts the most paths.'
      )
    )

  const header = (
    <PageHeader
      title={title}
      description={description}
      viewSwitcher={
        !isMobile && detail && detail.paths.length > 0 ? (
          <ViewSwitcher<View>
            value={view}
            onChange={(v) => setParam('view', v === 'canvas' ? null : v)}
            options={[
              {
                value: 'canvas',
                label: t('prioritization.attackPath.viewCanvas', 'Graph'),
                icon: Network,
              },
              {
                value: 'list',
                label: t('prioritization.attackPath.viewList', 'List view'),
                icon: List,
              },
            ]}
          />
        ) : undefined
      }
      actionsClassName="basis-full sm:basis-auto"
    >
      {targets.length > 0 && (
        <Select value={targetId ?? undefined} onValueChange={(v) => setParam('target', v)}>
          <SelectTrigger
            className="h-9 w-full sm:w-56"
            aria-label={t('prioritization.attackPath.targetLabel', 'Target asset')}
          >
            <SelectValue placeholder={t('prioritization.attackPath.targetLabel', 'Target asset')} />
          </SelectTrigger>
          <SelectContent>
            {targetId && !targets.some((o) => o.id === targetId) && target && !target.hidden && (
              <SelectItem value={targetId}>{target.name}</SelectItem>
            )}
            {targets.map((o) => (
              <SelectItem key={o.id} value={o.id}>
                <span className="flex items-center gap-1.5">
                  {o.crown && (
                    <Crown
                      className="size-3.5"
                      aria-label={t('prioritization.attackPath.crownJewel', 'Crown jewel')}
                    />
                  )}
                  {o.name}
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      {detail && detail.paths.length > 1 && (
        <FilterSelect<PathMode>
          label={t('prioritization.attackPath.pathsLabel', 'Paths')}
          value={mode}
          clearable={false}
          onChange={(v) => setParam('paths', v === 'all' ? 'all' : null)}
          options={[
            { value: 'shortest', label: t('prioritization.attackPath.shortest', 'Shortest') },
            {
              value: 'all',
              label: t('prioritization.attackPath.all', 'All'),
              count: detail.paths.length,
            },
          ]}
        />
      )}
      {canTask && detail && detail.paths.length > 0 && (
        <Button
          type="button"
          disabled={!firstChoke?.node.finding}
          onClick={() => setTaskOpen(true)}
          data-testid="choke-task"
        >
          {t('prioritization.attackPath.createTask', 'Create task for choke point')}
        </Button>
      )}
    </PageHeader>
  )

  let body: React.ReactNode
  if (chainsLoading || (targetId && isLoading)) {
    body = <BodySkeleton />
  } else if (chainsError && !targetId) {
    body = (
      <ErrorState
        title={t('prioritization.errorTitle.attackPaths', 'attack paths')}
        error={chainsError}
        onRetry={() => void reloadChains()}
      />
    )
  } else if (!targetId) {
    body =
      chains?.summary.hasRelationshipData === false ? (
        <EmptyState
          icon={GitBranch}
          title={t('prioritization.noRelationships.title', 'No relationship data yet')}
          description={t(
            'prioritization.attackPaths.noRelationships',
            'Add relationships between your assets to see which ones internet-facing entry points can reach.'
          )}
          action={
            <Button size="sm" asChild>
              <Link href="/assets">
                {t('prioritization.goToAssets', 'Go to assets')}
                <ArrowRight className="ms-2 h-4 w-4" aria-hidden />
              </Link>
            </Button>
          }
        />
      ) : (
        <EmptyState
          icon={Route}
          title={t('prioritization.attackPath.noTargetsTitle', 'No path reaches a dangerous asset')}
          description={t(
            'prioritization.attackPath.noTargetsDescription',
            'No internet-facing entry point reaches an asset with a known exploited or critical finding through the relationships you track.'
          )}
          action={
            <Button size="sm" variant="outline" asChild>
              <Link href="/crown-jewels">
                {t('prioritization.attackPath.reviewCrownJewels', 'Review crown jewels')}
              </Link>
            </Button>
          }
        />
      )
  } else if (error || !detail) {
    body = (
      <ErrorState
        title={t('prioritization.errorTitle.attackPaths', 'attack paths')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  } else if (detail.paths.length === 0) {
    body = (
      <EmptyState
        icon={Route}
        title={t(
          'prioritization.attackPath.noPathsTitle',
          'No path from the internet reaches {name}',
          {
            name: target && !target.hidden ? target.name : '',
          }
        )}
        description={t(
          'prioritization.attackPath.noPathsDescription',
          'No internet-facing entry point reaches this asset through the relationships you track.'
        )}
      />
    )
  } else {
    const more = detail.totalPaths > detail.paths.length || detail.capped
    body = (
      // The side cards go beside the canvas only when the canvas keeps a
      // readable width (zoom 1 for a three-step route); below that they sit
      // under it, side by side.
      <div className="grid gap-4 2xl:grid-cols-[minmax(0,1fr)_300px]">
        <section
          className="min-w-0 overflow-hidden rounded-lg border bg-card"
          aria-label={t('prioritization.attackPath.canvasLabel', 'Attack path graph')}
        >
          {view === 'canvas' && (
            <div className="border-b border-border-subtle px-4 py-2.5">
              <AttackPathLegend />
            </div>
          )}
          {view === 'canvas' ? (
            <div
              className="h-[520px] border-b border-border-subtle"
              data-testid="attack-path-canvas"
            >
              <AttackPathCanvas
                detail={detail}
                shown={shown}
                selected={selected}
                focus={focus}
                onFocusChange={setFocus}
                onOpenNode={openNode}
                onCyclePath={cycle}
              />
            </div>
          ) : (
            <div className="border-b border-border-subtle">
              <AttackPathList
                detail={detail}
                shown={shown}
                selected={selected}
                onSelect={setSelected}
              />
            </div>
          )}
          <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 px-4 py-2.5 text-xs text-muted-foreground">
            <span className="flex flex-wrap gap-x-3">
              {computedLabel && (
                <span>
                  {t('prioritization.attackPath.computedAt', 'Computed at {time}', {
                    time: computedLabel,
                  })}
                </span>
              )}
              <span>{t('prioritization.attackPath.inScope', 'Paths in your scope')}</span>
              {more && (
                <span data-testid="paths-capped">
                  {t('prioritization.attackPath.showingOf', 'Showing {n} of {total} paths', {
                    n: detail.paths.length,
                    total: detail.capped ? `${detail.totalPaths}+` : detail.totalPaths,
                  })}
                </span>
              )}
            </span>
            <span className="flex items-center gap-2">
              <span>
                {t('prioritization.attackPath.weights', 'Weights from EPSS, KEV and severity')}
              </span>
              <Popover>
                <PopoverTrigger asChild>
                  <button
                    type="button"
                    className="rounded text-signal-text hover:underline focus-visible:ring-2 focus-visible:ring-ring outline-none"
                  >
                    {t('prioritization.attackPath.how', 'How')}
                  </button>
                </PopoverTrigger>
                <PopoverContent className="w-80 text-sm" align="end">
                  <p className="font-semibold">
                    {t('prioritization.attackPath.howTitle', 'How a path is scored')}
                  </p>
                  <ul className="mt-2 grid gap-1.5 text-muted-foreground">
                    <li>
                      {t(
                        'prioritization.attackPath.howStep',
                        'Each step weighs the open finding most likely to let an attacker onto that asset: its EPSS score, at least 0.9 when it is known exploited, and at least 0.5, 0.3, 0.1 or 0.05 for a critical, high, medium or low finding.'
                      )}
                    </li>
                    <li>
                      {t(
                        'prioritization.attackPath.howAssumed',
                        'A step with no open finding counts as 1: the relationship alone is taken to allow it.'
                      )}
                    </li>
                    <li>
                      {t(
                        'prioritization.attackPath.howProduct',
                        'The path likelihood is the product of its step weights. A choke point is a step whose findings, once fixed, cut the most of the paths shown.'
                      )}
                    </li>
                  </ul>
                </PopoverContent>
              </Popover>
            </span>
          </div>
        </section>
        <aside className="grid content-start gap-4 md:grid-cols-2 2xl:grid-cols-1">
          <ChokePointsCard detail={detail} onFocus={setFocus} />
          <PathScoreCard
            detail={detail}
            selected={selected}
            total={shown.length}
            onSelect={setSelected}
            onFocus={(f) => setFocus(f && f.kind === 'path' ? null : f)}
          />
        </aside>
      </div>
    )
  }

  return (
    <Main>
      <PageStack>
        {header}
        {body}
      </PageStack>
      {taskOpen && firstChoke?.node.finding && (
        <AddFindingsToTaskDialog
          open
          onOpenChange={(o) => {
            if (!o) setTaskOpen(false)
          }}
          findings={[
            {
              id: firstChoke.node.finding.id,
              title: firstChoke.node.finding.title || stepText(firstChoke.node),
            },
          ]}
        />
      )}
    </Main>
  )
}
