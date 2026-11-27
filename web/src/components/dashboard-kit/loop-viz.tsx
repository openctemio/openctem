'use client'

/**
 * The CTEM loop: five stages as an ordered list, each with its figure (a
 * link to the list it counts), a second figure, and its state as an icon
 * and words. The stage with the largest gap is the current step
 * (aria-current="step"), marked "Act here" with the brand marker dot (stage-state.tsx)
 * on the line every stage keeps for its note, so it never adds a row to one tile.
 * The stages sit in one divided row, no inner cards; state is never only a colour.
 */

import { useTranslation } from '@/context/i18n-provider'
import { formatCount, formatMetric } from '@/lib/format-metric'
import { cn } from '@/lib/utils'
import { ActHere, StageStateIcon, useStageStateText } from './stage-state'
import { StagesTable } from './table-viz'
import { ChartOrTable, DrillLink, useLabel } from './viz-parts'
import type { StagesResult } from './types'

export function LoopViz({ result }: { result: StagesResult }) {
  const { t, locale } = useTranslation()
  const label = useLabel()
  const stateText = useStageStateText()
  // The columns follow the card, not the window: a card beside the sidebar at
  // 1024 px is 660 px wide and five stages did not fit in it. The tiles fill
  // the card's height when its row is taller than they are.
  const chart = (
    <div className="@container flex h-full flex-col overflow-hidden rounded-lg border">
      <ol
        className="-ms-px -mt-px grid flex-1 grid-cols-2 @min-[440px]:grid-cols-3 @min-[680px]:grid-cols-5"
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
              // Five stages in two or three columns end on a short row: the
              // last stage takes two columns there, so no blank cell is left.
              className="flex min-w-0 flex-col gap-1.5 border-s border-t p-3 last:col-span-2 @min-[680px]:last:col-span-1"
            >
              <div className="flex items-baseline justify-between gap-2 text-xs">
                {/* A stage's name wraps ("Xác định phạm v…" said nothing). */}
                <span className="min-w-0 font-medium break-words">{name}</span>
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
                    className="w-fit max-w-full text-muted-foreground hover:underline"
                  >
                    {t(s.detail.label_key, '{n}', { n: formatCount(s.detail.value, locale) })}
                  </DrillLink>
                )}
                {current ? (
                  <ActHere label={s.flag_key ? t(s.flag_key) : undefined} inline />
                ) : (
                  s.flag_key && <span className="text-muted-foreground">{t(s.flag_key)}</span>
                )}
              </div>
              {/* max-w-full: at 1024px a cell is about 110 px wide and "Needs attention"
                  ran 6 px past it; the status wraps instead. */}
              <span className="mt-auto inline-flex w-fit max-w-full items-center gap-1 rounded-2xl border px-2 py-0.5 text-xs">
                <StageStateIcon state={s.state} />
                {s.value == null && s.reason_key ? t(s.reason_key) : stateText(s.state)}
              </span>
            </li>
          )
        })}
      </ol>
    </div>
  )
  return <ChartOrTable chart={chart} table={<StagesTable result={result} />} />
}
