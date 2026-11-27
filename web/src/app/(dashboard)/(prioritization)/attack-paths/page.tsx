'use client'

/**
 * Attack paths: how the internet reaches one asset (research/229
 * mockups/attack-path.html). A flow canvas from the internet through entry
 * points and hops to the asset, a list view of the same routes (the default on
 * a phone), choke points ("fix this to cut N paths") and the score of the
 * selected path as a breakdown of step weights. Data:
 * GET /api/v1/attack-surface/attack-paths/{id}, in the viewer's data scope
 * (server/docs/architecture/attack-paths.md); the targets come from the exposure
 * chains.
 */

import { PossiblePathLabel } from '@/components/ui/possible-path-label'
import { useCallback, useMemo, useRef, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { ArrowRight, Crown, GitBranch, List, Network, Route } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
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
import { FlowFullscreen } from '@/components/flow/flow-fullscreen'
import {
  GraphFrame,
  GraphLegend,
  GraphNote,
  GraphToolbar,
} from '@/components/graph-page/graph-page'
import { AttackPathNodeSheet } from '@/features/attack-surface/components/attack-path-node-sheet'
import { AttackPathCanvas } from '@/features/attack-surface/components/attack-path-canvas'
import {
  AttackPathLegend,
  AttackPathList,
  ChokePointsCard,
  PathScoreCard,
  useAttackPathLegendItems,
} from '@/features/attack-surface/components/attack-path-panels'
import {
  chokeRows,
  formatWeight,
  nodeByKey,
  shownPaths,
  stepText,
  type Focus,
  type PathMode,
} from '@/features/attack-surface/lib/attack-path-model'
import { formatTime } from '@/lib/app-locale'

type View = 'canvas' | 'list'

function BodySkeleton() {
  return (
    <div className="grid gap-4" data-testid="attack-path-loading">
      <Skeleton className="h-control w-full max-w-md rounded-md" />
      <Skeleton className="h-96 w-full rounded-lg" />
    </div>
  )
}

export default function AttackPathsPage() {
  const { t } = useTranslation()
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
  // All paths by default: the graph opens on the whole picture (entry, foothold,
  // pivot, target); "Shortest" narrows it to one route.
  const mode: PathMode = params.get('paths') === 'shortest' ? 'shortest' : 'all'
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
  // The task goes to the first choke point that has a finding to fix; a step
  // that has none (an identity, a relationship alone) cannot be a task, so with
  // no such choke point the action is not offered at all.
  const taskChoke = chokes.find((c) => c.node.finding)
  const canTask = can(Permission.RemediationWrite) && remediationOn

  const cycle = useCallback(
    (delta: 1 | -1) => {
      if (shown.length < 2) return
      const i = shown.indexOf(selected)
      setSelected(shown[(i + delta + shown.length) % shown.length])
    },
    [shown, selected]
  )

  // The detail of a step opens over the page; its findings are one link away.
  const [openKey, setOpenKey] = useState<string | null>(null)
  const [sheetOpen, setSheetOpen] = useState(false)
  // Where focus was when the detail opened: the node on the graph, or the
  // step's name in the list.
  const openerRef = useRef<{ key: string; list: HTMLElement | null }>({ key: '', list: null })
  // Made once: the canvas keeps its handlers while the page re-renders.
  const [openNode] = useState(() => (key: string) => {
    const active = document.activeElement as HTMLElement | null
    openerRef.current = {
      key,
      list: active?.closest('[data-testid="attack-path-list"]') ? active : null,
    }
    setOpenKey(key)
    setSheetOpen(true)
  })
  const returnFocus = () => {
    const { key, list } = openerRef.current
    if (list?.isConnected) return list
    return document.querySelector<HTMLElement>(
      `.react-flow__node[data-id="${CSS.escape(key)}"] [data-testid="flow-node"]`
    )
  }
  const openNodeData = openKey ? (byKey.get(openKey) ?? null) : null
  const legendItems = useAttackPathLegendItems()

  const computedAt = detail?.computedAt ? new Date(detail.computedAt) : null
  const computedLabel =
    computedAt && !Number.isNaN(computedAt.getTime())
      ? formatTime(computedAt, { hour: '2-digit', minute: '2-digit' })
      : ''

  // The title and the line under it never change with the data, so the header
  // holds still while the paths load; the selected path is named in the
  // selection line over the graph.
  const description = (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span>
        {t(
          'prioritization.attackPath.description',
          'How the internet could reach your assets, and which fix cuts the most paths.'
        )}
      </span>
      <PossiblePathLabel />
    </span>
  )

  const selection =
    sel && detail ? (
      <div
        data-slot="graph-selection"
        className="flex flex-wrap items-center gap-x-3 gap-y-1 text-dense text-muted-foreground"
      >
        {target && !target.hidden && (
          <span className="font-medium text-foreground">
            {t('prioritization.attackPath.titleTo', 'Path to {name}', { name: target.name })}
          </span>
        )}
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
      </div>
    ) : null

  const taskButton = (size?: 'sm') => (
    <Button
      type="button"
      size={size}
      variant={size ? 'outline' : 'default'}
      onClick={() => setTaskOpen(true)}
      data-testid="choke-task"
    >
      {t('prioritization.attackPath.createTask', 'Create task for choke point')}
    </Button>
  )
  const offerTask = canTask && !!detail && detail.paths.length > 0 && !!taskChoke

  const header = (
    <PageHeader
      title={t('prioritization.attackPaths.title', 'Attack paths')}
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
    >
      {/* On a phone the action sits on the choke points card, so the header does not grow. */}
      {offerTask && !isMobile && taskButton()}
    </PageHeader>
  )

  const graphFacts = (more: boolean) =>
    detail ? (
      <>
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
        <span>{t('prioritization.attackPath.weights', 'Weights from EPSS, KEV and severity')}</span>
      </>
    ) : null

  const toolbar =
    targets.length > 0 || detail ? (
      <GraphToolbar
        label={t('prioritization.attackPath.toolbarLabel', 'Attack path filters')}
        end={
          // The note needs no data: it shows from the first paint, so the
          // toolbar's second row on a phone is there before the paths arrive.
          !detail || detail.paths.length > 0 ? (
            <>
              {view === 'canvas' && detail && (
                <GraphLegend items={legendItems} testId="attack-path-legend" />
              )}
              <GraphNote
                label={t('prioritization.attackPath.howLabel', 'How paths are scored')}
                title={t('prioritization.attackPath.howTitle', 'How a path is scored')}
              >
                <p>
                  {t(
                    'prioritization.attackPath.howStep',
                    'Each step weighs the open finding most likely to let an attacker onto that asset: its EPSS score, at least 0.9 when it is known exploited, and at least 0.5, 0.3, 0.1 or 0.05 for a critical, high, medium or low finding.'
                  )}
                </p>
                <p>
                  {t(
                    'prioritization.attackPath.howAssumed',
                    'A step with no open finding counts as 1: the relationship alone is taken to allow it.'
                  )}
                </p>
                <p>
                  {t(
                    'prioritization.attackPath.howProduct',
                    'The path likelihood is the product of its step weights. A choke point is a step whose findings, once fixed, cut the most of the paths shown.'
                  )}
                </p>
              </GraphNote>
            </>
          ) : undefined
        }
      >
        {targets.length > 0 && (
          <Select value={targetId ?? undefined} onValueChange={(v) => setParam('target', v)}>
            <SelectTrigger
              className="min-w-0 flex-1 sm:w-56 sm:flex-none"
              aria-label={t('prioritization.attackPath.targetLabel', 'Target asset')}
            >
              <SelectValue
                placeholder={t('prioritization.attackPath.targetLabel', 'Target asset')}
              />
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
            onChange={(v) => setParam('paths', v === 'shortest' ? 'shortest' : null)}
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
      </GraphToolbar>
    ) : null

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
      <>
        {view === 'canvas' ? (
          <GraphFrame
            label={t('prioritization.attackPath.canvasLabel', 'Attack path graph')}
            header={selection}
            footer={graphFacts(more)}
          >
            <FlowFullscreen
              className="flex min-h-0 flex-1 flex-col"
              title={t('prioritization.attackPath.canvasLabel', 'Attack path graph')}
            >
              {(full) => (
                <div
                  className={
                    full
                      ? 'flex min-h-0 flex-1 flex-col rounded-md border'
                      : 'flex min-h-0 flex-1 flex-col'
                  }
                >
                  {full && (
                    <div className="border-b border-border-subtle px-4 py-2.5">
                      <AttackPathLegend />
                    </div>
                  )}
                  <div
                    className={full ? 'min-h-80 flex-1' : 'min-h-0 flex-1'}
                    data-testid={full ? 'attack-path-canvas-full' : 'attack-path-canvas'}
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
                </div>
              )}
            </FlowFullscreen>
          </GraphFrame>
        ) : (
          <GraphFrame
            fill={false}
            label={t('prioritization.attackPath.listLabel', 'Attack paths as a list')}
            header={selection}
            footer={graphFacts(more)}
          >
            <AttackPathList
              detail={detail}
              shown={shown}
              selected={selected}
              onSelect={setSelected}
              onOpenNode={openNode}
            />
          </GraphFrame>
        )}
        {/* What to fix and how the selected path scores: under the graph, never beside it. */}
        <div className="grid items-start gap-4 md:grid-cols-2">
          <ChokePointsCard
            detail={detail}
            onFocus={setFocus}
            action={offerTask && isMobile ? taskButton('sm') : undefined}
          />
          <PathScoreCard
            detail={detail}
            selected={selected}
            total={shown.length}
            onSelect={setSelected}
            onFocus={(f) => setFocus(f && f.kind === 'path' ? null : f)}
          />
        </div>
      </>
    )
  }

  return (
    <Main>
      <PageStack>
        {header}
        {toolbar}
        {body}
      </PageStack>
      {detail && (
        <AttackPathNodeSheet
          open={sheetOpen && openNodeData !== null}
          detail={detail}
          node={openNodeData}
          through={
            openKey ? shown.filter((i) => detail.paths[i]?.nodes.includes(openKey)).length : 0
          }
          shownTotal={shown.length}
          onOpenChange={setSheetOpen}
          returnFocus={returnFocus}
          onHighlight={
            view === 'canvas' && openKey
              ? () => {
                  setFocus({ kind: 'node', key: openKey })
                  setSheetOpen(false)
                }
              : undefined
          }
        />
      )}
      {taskOpen && taskChoke?.node.finding && (
        <AddFindingsToTaskDialog
          open
          onOpenChange={(o) => {
            if (!o) setTaskOpen(false)
          }}
          findings={[
            {
              id: taskChoke.node.finding.id,
              title: taskChoke.node.finding.title || stepText(taskChoke.node),
            },
          ]}
        />
      )}
    </Main>
  )
}
