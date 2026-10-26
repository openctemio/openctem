'use client'

import * as React from 'react'
import { ArrowDown, ChevronLeft, ChevronRight, Crown } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Counter } from '@/components/ui/counter'
import { KevBadge } from '@/components/ui/kev-badge'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { AttackPathDetail, PathNode } from '../hooks/use-attack-path-detail'
import {
  assetFindingsHref,
  chokeRows,
  formatWeight,
  nodeByKey,
  pathScore,
  stepText,
  type Focus,
} from '../lib/attack-path-model'
import { ROLE_DOT } from './attack-path-canvas'
import { useAttackPathLabels } from './attack-path-labels'

const cardClass = 'rounded-lg border bg-card text-card-foreground'
const cardHead = 'flex items-center justify-between gap-2 border-b border-border-subtle px-4 py-3'

/** "View 6 findings": the count is the asset's open findings, the link opens exactly that list. */
export function FindingsLink({ node, className }: { node: PathNode; className?: string }) {
  const { t } = useTranslation()
  if (node.hidden || !node.assetId) return null
  return (
    <Link
      href={assetFindingsHref(node.assetId)}
      className={cn('whitespace-nowrap text-signal-text hover:underline', className)}
      data-testid="node-findings-link"
      data-count={node.openFindings}
    >
      {node.openFindings === 1
        ? t('prioritization.attackPath.viewOneFinding', 'View 1 finding')
        : t('prioritization.attackPath.viewFindings', 'View {n} findings', {
            n: node.openFindings,
          })}
    </Link>
  )
}

export function ChokePointsCard({
  detail,
  onFocus,
}: {
  detail: AttackPathDetail
  onFocus: (focus: Focus) => void
}) {
  const { t } = useTranslation()
  const rows = chokeRows(detail)
  return (
    <section className={cardClass} aria-labelledby="ap-choke-title">
      <div className={cardHead}>
        <h2 id="ap-choke-title" className="flex items-center gap-2 text-sm font-semibold">
          {t('prioritization.attackPath.chokeTitle', 'Choke points')}
          <Counter value={rows.length} />
        </h2>
      </div>
      {rows.length === 0 ? (
        <p className="px-4 py-3 text-sm text-muted-foreground">
          {t(
            'prioritization.attackPath.chokeEmpty',
            'No step on these paths has an open finding to fix. The routes rely on relationships alone.'
          )}
        </p>
      ) : (
        <ol className="divide-y divide-border-subtle" data-testid="choke-points">
          {rows.map((r, i) => {
            const step = stepText(r.node)
            return (
              <li
                key={r.key}
                className="grid grid-cols-[24px_1fr] gap-2 px-4 py-2.5"
                onMouseEnter={() => onFocus({ kind: 'node', key: r.key })}
                onMouseLeave={() => onFocus(null)}
                onFocus={() => onFocus({ kind: 'node', key: r.key })}
                onBlur={() => onFocus(null)}
              >
                <span
                  aria-hidden
                  className={cn(
                    'pt-0.5 text-xs tabular-nums',
                    i === 0 ? 'font-semibold' : 'text-muted-foreground'
                  )}
                >
                  {String(i + 1).padStart(2, '0')}
                </span>
                <div className="min-w-0">
                  <div className="text-sm font-semibold break-words">
                    {t('prioritization.attackPath.chokeFix', 'Fix {step} on {asset}', {
                      step:
                        step || t('prioritization.attackPath.openFindings', 'the open findings'),
                      asset: r.node.name,
                    })}
                  </div>
                  <div className="mt-1 flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-xs text-muted-foreground">
                    <span data-testid="choke-breaks" data-breaks={r.breaks}>
                      {i === 0
                        ? t(
                            'prioritization.attackPath.chokeCutFirst',
                            'Fix this to cut {n} of {of} paths',
                            {
                              n: r.breaks,
                              of: r.of,
                            }
                          )
                        : t('prioritization.attackPath.chokeCut', 'Cuts {n} of {of} paths', {
                            n: r.breaks,
                            of: r.of,
                          })}
                    </span>
                    <span className="flex items-center gap-3">
                      {r.node.finding && (
                        <Link
                          href={`/findings/${encodeURIComponent(r.node.finding.id)}`}
                          className="whitespace-nowrap text-signal-text hover:underline"
                        >
                          {t('prioritization.attackPath.viewFinding', 'View finding')}
                        </Link>
                      )}
                      <FindingsLink node={r.node} />
                    </span>
                  </div>
                </div>
              </li>
            )
          })}
        </ol>
      )}
    </section>
  )
}

export function PathScoreCard({
  detail,
  selected,
  total,
  onSelect,
  onFocus,
}: {
  detail: AttackPathDetail
  selected: number
  total: number
  onSelect: (index: number) => void
  onFocus: (focus: Focus) => void
}) {
  const { t } = useTranslation()
  const labels = useAttackPathLabels()
  const score = pathScore(detail, selected)
  if (!score) return null
  return (
    <section className={cardClass} aria-labelledby="ap-score-title" data-testid="path-score">
      <div className={cardHead}>
        <h2 id="ap-score-title" className="text-sm font-semibold">
          {t('prioritization.attackPath.scoreTitle', 'Path score')}
        </h2>
        {total > 1 ? (
          <div className="flex items-center gap-1 text-xs text-muted-foreground">
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label={t('prioritization.attackPath.prevPath', 'Previous path')}
              onClick={() => onSelect((selected - 1 + total) % total)}
            >
              <ChevronLeft className="size-4" aria-hidden />
            </Button>
            <span aria-live="polite" className="tabular-nums">
              {t('prioritization.attackPath.pathOf', 'Path {n} of {of}', {
                n: selected + 1,
                of: total,
              })}
            </span>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label={t('prioritization.attackPath.nextPath', 'Next path')}
              onClick={() => onSelect((selected + 1) % total)}
            >
              <ChevronRight className="size-4" aria-hidden />
            </Button>
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">
            {t('prioritization.attackPath.noHiddenWeights', 'No hidden weights')}
          </span>
        )}
      </div>
      <ol
        className="grid gap-1.5 px-4 py-3 text-sm"
        onMouseLeave={() => onFocus({ kind: 'path', index: selected })}
      >
        {score.rows.map((r, i) => {
          const step = stepText(r.node)
          return (
            <li
              key={r.key}
              className="flex items-start justify-between gap-3"
              onMouseEnter={() => onFocus({ kind: 'node', key: r.key })}
            >
              <span className="min-w-0">
                <span className="text-muted-foreground">{labels.role(r.node)}</span>{' '}
                {r.node.hidden ? (
                  <span className="italic">{labels.hiddenTitle}</span>
                ) : r.node.finding ? (
                  <Link
                    href={`/findings/${encodeURIComponent(r.node.finding.id)}`}
                    className="break-words hover:underline"
                    title={r.node.finding.title}
                  >
                    {step}
                  </Link>
                ) : (
                  <span>{labels.basis('assumed')}</span>
                )}
                {!r.node.hidden && (
                  <span className="block text-xs text-muted-foreground">
                    {r.node.name}
                    {r.node.basis && r.node.basis !== 'assumed' && (
                      <span className="ms-2">{labels.basis(r.node.basis)}</span>
                    )}
                  </span>
                )}
              </span>
              <b className="shrink-0 font-semibold tabular-nums">
                {r.weight === null
                  ? t('prioritization.attackPath.weightHidden', 'hidden')
                  : i === 0
                    ? formatWeight(r.weight)
                    : t('prioritization.attackPath.times', '× {w}', { w: formatWeight(r.weight) })}
              </b>
            </li>
          )
        })}
        <li className="mt-1 flex justify-between gap-3 border-t border-border-subtle pt-2">
          <span>{t('prioritization.attackPath.likelihood', 'Path likelihood')}</span>
          <b className="font-semibold tabular-nums" data-testid="path-likelihood">
            {score.likelihood === null
              ? t(
                  'prioritization.attackPath.likelihoodHidden',
                  'Withheld, a step is outside your access'
                )
              : formatWeight(score.likelihood)}
          </b>
        </li>
      </ol>
    </section>
  )
}

/**
 * The list view: the same routes as an ordered list (research/229 §4.2), the
 * default on a phone and one click away on a desktop. Each step names the
 * finding that enables the move onto the next asset.
 */
export function AttackPathList({
  detail,
  shown,
  selected,
  onSelect,
}: {
  detail: AttackPathDetail
  shown: number[]
  selected: number
  onSelect: (index: number) => void
}) {
  const { t } = useTranslation()
  const labels = useAttackPathLabels()
  const byKey = nodeByKey(detail)
  return (
    <div className="grid gap-4 p-4" data-testid="attack-path-list">
      {shown.map((pi) => {
        const p = detail.paths[pi]
        return (
          <section
            key={pi}
            aria-labelledby={`ap-list-${pi}`}
            className={cn('grid gap-2', pi === selected && 'rounded-md')}
          >
            <h2
              id={`ap-list-${pi}`}
              className="flex flex-wrap items-center gap-2 text-sm font-semibold"
            >
              <button
                type="button"
                aria-pressed={pi === selected}
                onClick={() => onSelect(pi)}
                className="rounded text-left outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
              >
                {pi === 0
                  ? t('prioritization.attackPath.listShortest', 'Shortest path')
                  : t('prioritization.attackPath.listPath', 'Path {n}', { n: pi + 1 })}
              </button>
              <span className="text-xs font-normal text-muted-foreground">
                {p.length === 1
                  ? t('prioritization.attackPath.hopOne', '1 hop')
                  : t('prioritization.attackPath.hops', '{n} hops', { n: p.length })}
              </span>
              {p.likelihood !== null && (
                <span className="text-xs font-normal text-muted-foreground tabular-nums">
                  {t('prioritization.attackPath.likelihoodShort', 'Likelihood {w}', {
                    w: formatWeight(p.likelihood),
                  })}
                </span>
              )}
            </h2>
            <ol className="grid gap-2">
              {p.nodes.map((k, i) => {
                const n = byKey.get(k)!
                const next = byKey.get(p.nodes[i + 1] ?? '')
                const via = stepText(next)
                return (
                  <li key={k} className="rounded-md border bg-card px-3 py-2.5 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span aria-hidden className={cn('size-2 rounded-sm', ROLE_DOT[n.role])} />
                      <span className="text-xs font-medium">{labels.role(n)}</span>
                      {n.isCrownJewel && <Crown className="size-3.5" aria-hidden />}
                    </div>
                    <div className="mt-1 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                      <span
                        className={cn('font-semibold break-all', n.hidden && 'font-normal italic')}
                      >
                        {n.hidden ? labels.hiddenTitle : n.name}
                      </span>
                      {!n.hidden && <FindingsLink node={n} className="text-xs" />}
                    </div>
                    {i === 0 && stepText(n) && (
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <span>
                          {t(
                            'prioritization.attackPath.fromInternet',
                            'From the internet through {step}',
                            {
                              step: stepText(n),
                            }
                          )}
                        </span>
                        <span className="tabular-nums">{formatWeight(n.weight)}</span>
                        {n.finding?.kev && <KevBadge />}
                      </div>
                    )}
                    {next && (
                      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <ArrowDown className="size-3.5" aria-hidden />
                        <span>
                          {next.hidden
                            ? t(
                                'prioritization.attackPath.toHidden',
                                'to a step outside your access'
                              )
                            : via
                              ? t('prioritization.attackPath.via', 'through {step}', { step: via })
                              : t(
                                  'prioritization.attackPath.viaAssumed',
                                  'no open finding, relationship assumed'
                                )}
                        </span>
                        {!next.hidden && (
                          <span className="tabular-nums">{formatWeight(next.weight)}</span>
                        )}
                        {next.finding?.kev && <KevBadge />}
                      </div>
                    )}
                  </li>
                )
              })}
            </ol>
          </section>
        )
      })}
    </div>
  )
}

/** The legend: the kind dots, the KEV chip and the edge states, in the shared label language. */
export function AttackPathLegend() {
  const { t } = useTranslation()
  const items: { key: string; mark: React.ReactNode; label: string }[] = [
    {
      key: 'entry',
      mark: <span className={cn('size-2 rounded-sm', ROLE_DOT.entry)} />,
      label: t('prioritization.attackPath.role.entry', 'Entry point'),
    },
    {
      key: 'hop',
      mark: <span className={cn('size-2 rounded-sm', ROLE_DOT.hop)} />,
      label: t('prioritization.attackPath.role.hop', 'Hop'),
    },
    {
      key: 'target',
      mark: <span className={cn('size-2 rounded-sm', ROLE_DOT.target)} />,
      label: t('prioritization.attackPath.role.target', 'Target'),
    },
    {
      key: 'selected',
      mark: <span className="h-0.5 w-5 rounded bg-signal" />,
      label: t('prioritization.attackPath.legendSelected', 'Selected path'),
    },
    {
      key: 'alt',
      mark: <span className="w-5 border-t-2 border-dotted border-border-strong" />,
      label: t('prioritization.attackPath.legendAlt', 'Other path'),
    },
    {
      key: 'width',
      mark: <span className="h-1 w-5 rounded bg-border-strong" />,
      label: t('prioritization.attackPath.legendWidth', 'Thicker line, likelier step'),
    },
  ]
  return (
    <ul
      className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-muted-foreground"
      aria-label={t('prioritization.attackPath.legend', 'Legend')}
      data-testid="attack-path-legend"
    >
      {items.map((i) => (
        <li key={i.key} className="flex items-center gap-1.5">
          <span aria-hidden className="flex items-center">
            {i.mark}
          </span>
          {i.label}
        </li>
      ))}
      <li className="flex items-center gap-1.5">
        <KevBadge />
        <span>{t('prioritization.attackPath.legendKev', 'Known exploited step')}</span>
      </li>
    </ul>
  )
}
