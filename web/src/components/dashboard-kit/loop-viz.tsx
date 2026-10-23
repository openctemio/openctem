'use client'

/**
 * The CTEM loop: five stages as an ordered list, each with its figure (a
 * link to the list it counts), a second figure, and its state as an icon
 * and words. The stage with the largest gap is the current step
 * (aria-current="step"), marked "Act here" with a neutral dot.
 * The stages sit in one divided row, no inner cards; state is never only a colour.
 */

import { CheckCircle2, CircleMinus, TriangleAlert, XCircle } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { formatCount, formatMetric } from '@/lib/format-metric'
import { cn } from '@/lib/utils'
import { StagesTable } from './table-viz'
import { ChartOrTable, DrillLink, useLabel } from './viz-parts'
import type { StageState, StagesResult } from './types'

const STATE_ICON: Record<StageState, React.ReactNode> = {
  good: <CheckCircle2 className="size-3.5 text-success" aria-hidden />,
  warn: <TriangleAlert className="size-3.5 text-warning" aria-hidden />,
  crit: <XCircle className="size-3.5 text-destructive" aria-hidden />,
  unmeasured: <CircleMinus className="size-3.5 text-muted-foreground" aria-hidden />,
}

export function LoopViz({ result }: { result: StagesResult }) {
  const { t, locale } = useTranslation()
  const label = useLabel()
  const stateText: Record<StageState, string> = {
    good: t('dashboardKit.stage.good', 'On track'),
    warn: t('dashboardKit.stage.warn', 'Needs attention'),
    crit: t('dashboardKit.stage.crit', 'Off track'),
    unmeasured: t('dashboardKit.stage.unmeasured', 'Not measured'),
  }
  const chart = (
    <div className="overflow-hidden rounded-lg border">
      <ol
        className="-ms-px -mt-px grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5"
        aria-label={t('dashboardKit.stage.listLabel', 'Stages')}
      >
        {result.stages.map((s, i) => {
          const current = result.focus === i
          const name = label(s)
          const value = formatMetric(s.value, s.unit ?? 'count', locale)
          return (
            <li
              key={s.key}
              data-state={s.state}
              aria-current={current ? 'step' : undefined}
              className="flex min-w-0 flex-col gap-1.5 border-s border-t p-3"
            >
              <div className="flex items-baseline justify-between gap-2 text-xs">
                <span className="truncate font-medium">{name}</span>
                <span className="tabular-nums text-muted-foreground" aria-hidden>
                  {String(i + 1).padStart(2, '0')}
                </span>
              </div>
              <DrillLink
                to={s.drill}
                label={`${name}: ${value}`}
                className={cn(
                  'w-fit text-2xl font-semibold leading-none tabular-nums hover:underline',
                  s.value == null && 'text-muted-foreground'
                )}
              >
                {value}
              </DrillLink>
              {/* One internal grid for every stage: label, value, a two-line
                sub-line block, then the status pinned to the bottom, so cards
                in a row line up whatever their content. */}
              <div className="flex min-h-9 flex-col gap-0.5 text-xs">
                {s.detail && (
                  <DrillLink
                    to={s.detail.drill}
                    className="w-fit text-muted-foreground hover:underline"
                  >
                    {t(s.detail.label_key, '{n}', { n: formatCount(s.detail.value, locale) })}
                  </DrillLink>
                )}
                {current ? (
                  <span className="inline-flex items-center gap-1.5 font-medium">
                    <span className="size-2 shrink-0 rounded-full bg-foreground" aria-hidden />
                    {s.flag_key ? t(s.flag_key) : t('dashboardKit.stage.actHere', 'Act here')}
                  </span>
                ) : (
                  s.flag_key && <span className="text-muted-foreground">{t(s.flag_key)}</span>
                )}
              </div>
              <span className="mt-auto inline-flex w-fit items-center gap-1 rounded-full border px-2 py-0.5 text-xs">
                {STATE_ICON[s.state]}
                {s.value == null && s.reason_key ? t(s.reason_key) : stateText[s.state]}
              </span>
            </li>
          )
        })}
      </ol>
    </div>
  )
  return <ChartOrTable chart={chart} table={<StagesTable result={result} />} />
}
