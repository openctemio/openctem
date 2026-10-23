'use client'

/**
 * Attack paths to crown jewels: how many crown jewels in scope an entry
 * point reaches (a link to the attack paths), and the top ones by path
 * score. No crown jewel designated and none reachable are different
 * empty states; designating crown jewels is the place to act.
 */

import { Crown } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { safeInternalHref } from '@/lib/safe-href'
import { useTranslation } from '@/context/i18n-provider'
import { formatCount } from '@/lib/format-metric'
import { cn } from '@/lib/utils'
import { PathsTable } from './table-viz'
import { ChartOrTable, DrillLink } from './viz-parts'
import type { PathsResult } from './types'

export function PathsViz({
  result,
  href,
  designateHref = '/crown-jewels',
}: {
  result: PathsResult
  /** The attack paths the count opens. */
  href?: string
  designateHref?: string
}) {
  const { t, locale } = useTranslation()
  if (result.designated === 0) {
    return (
      <div className="flex flex-1 flex-col items-start justify-center gap-2 text-sm">
        <Crown className="size-5 text-muted-foreground" aria-hidden />
        <p className="font-medium">
          {t('dashboardKit.paths.noneDesignated', 'No crown jewels designated')}
        </p>
        <p className="text-muted-foreground">
          {t(
            'dashboardKit.paths.noneDesignatedHint',
            'Mark your high-value assets as crown jewels to see which ones an attacker can reach.'
          )}
        </p>
        <Button asChild variant="outline" size="sm">
          <Link href={safeInternalHref(designateHref) ?? '/crown-jewels'}>
            {t('dashboardKit.paths.designate', 'Designate crown jewels')}
          </Link>
        </Button>
      </div>
    )
  }
  const count = formatCount(result.reachable, locale)
  const chart = (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <p className="flex flex-wrap items-baseline gap-x-2">
        <DrillLink
          to={href}
          label={t('dashboardKit.paths.reachableLabel', '{n} crown jewels reachable', { n: count })}
          className={cn(
            'text-3xl font-semibold tabular-nums hover:underline',
            result.reachable > 0 ? 'text-destructive' : 'text-foreground'
          )}
        >
          {count}
        </DrillLink>
        <span className="text-xs text-muted-foreground">
          {t(
            'dashboardKit.paths.ofDesignated',
            'of {n} crown jewels reachable from an entry point',
            {
              n: formatCount(result.designated, locale),
            }
          )}
        </span>
      </p>
      {result.reachable === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t(
            'dashboardKit.paths.noneReachable',
            'No attack path reaches a crown jewel in your scope.'
          )}
        </p>
      ) : (
        <ul className="flex flex-col divide-y">
          {result.rows.map((r) => (
            <li key={r.id}>
              <DrillLink
                to={r.href}
                className="flex items-center gap-2 py-1.5 text-sm hover:bg-accent/40"
              >
                <span className="min-w-0 flex-1 truncate">{r.name}</span>
                <span className="shrink-0 text-xs text-muted-foreground">
                  {r.entry_point
                    ? t('dashboardKit.paths.isEntryPoint', 'Entry point itself')
                    : t(
                        'dashboardKit.paths.reachedFrom',
                        'from {n, plural, one {# entry point} other {# entry points}}',
                        { n: r.reachable_from }
                      )}
                </span>
                <span
                  className="w-10 shrink-0 text-end text-xs font-semibold tabular-nums"
                  title={t('dashboardKit.paths.scoreLabel', 'Exposure score')}
                >
                  <span className="sr-only">
                    {t('dashboardKit.paths.scoreLabel', 'Exposure score')}:{' '}
                  </span>
                  {formatCount(Math.round(r.score), locale)}
                </span>
              </DrillLink>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
  return <ChartOrTable chart={chart} table={<PathsTable result={result} />} />
}
