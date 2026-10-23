'use client'

/**
 * The table form of every shape: the exact figures behind a chart, and the
 * accessible view of it. Rows link to their list when a drill is given.
 */

import { useTranslation } from '@/context/i18n-provider'
import {
  formatBucket,
  formatCount,
  formatDelta,
  formatMetric,
  type MetricUnit,
} from '@/lib/format-metric'
import { DrillLink, useLabel } from './viz-parts'
import type {
  CategoryResult,
  DrillFn,
  MatrixResult,
  PathsResult,
  StagesResult,
  TimeSeriesResult,
} from './types'

const TH = 'px-2 py-1.5 text-start text-xs font-medium text-muted-foreground'
const TD = 'px-2 py-1.5 text-sm tabular-nums'

function Cell({ text, to }: { text: string; to?: string | null }) {
  return (
    <DrillLink to={to} className="hover:underline">
      {text}
    </DrillLink>
  )
}

export function CategoryTable({
  result,
  unit = 'count',
  drill,
}: {
  result: CategoryResult
  unit?: MetricUnit
  drill?: DrillFn
}) {
  const { t, locale } = useTranslation()
  const label = useLabel()
  const hasPrevious = result.rows.some((r) => r.previous != null)
  return (
    <div className="overflow-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b">
            <th className={TH} scope="col">
              {t('dashboardKit.table.item', 'Item')}
            </th>
            <th className={TH + ' text-end'} scope="col">
              {t('dashboardKit.table.value', 'Value')}
            </th>
            {hasPrevious && (
              <>
                <th className={TH + ' text-end'} scope="col">
                  {t('dashboardKit.table.previous', 'Previous')}
                </th>
                <th className={TH + ' text-end'} scope="col">
                  {t('dashboardKit.table.change', 'Change')}
                </th>
              </>
            )}
          </tr>
        </thead>
        <tbody>
          {result.rows.map((r) => (
            <tr key={r.key} className="border-b last:border-0">
              <th scope="row" className={TD + ' font-normal text-start'}>
                <Cell text={label(r)} to={drill?.({ key: r.key })} />
              </th>
              <td className={TD + ' text-end'}>{formatMetric(r.value, unit, locale)}</td>
              {hasPrevious && (
                <>
                  <td className={TD + ' text-end text-muted-foreground'}>
                    {formatMetric(r.previous ?? null, unit, locale)}
                  </td>
                  <td className={TD + ' text-end text-muted-foreground'}>
                    {r.previous == null ? '—' : formatDelta(r.value - r.previous, unit, locale)}
                  </td>
                </>
              )}
            </tr>
          ))}
        </tbody>
        <tfoot>
          <tr>
            <th scope="row" className={TD + ' text-start font-medium'}>
              {t('dashboardKit.table.total', 'Total')}
            </th>
            <td className={TD + ' text-end font-medium'}>
              {formatMetric(result.total, unit, locale)}
            </td>
            {hasPrevious && <td colSpan={2} />}
          </tr>
        </tfoot>
      </table>
    </div>
  )
}

export function TimeSeriesTable({
  result,
  unit = 'count',
  drill,
}: {
  result: TimeSeriesResult
  unit?: MetricUnit
  drill?: DrillFn
}) {
  const { t, locale } = useTranslation()
  const label = useLabel()
  const times = Array.from(new Set(result.series.flatMap((s) => s.points.map((p) => p.t)))).sort()
  return (
    <div className="overflow-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b">
            <th className={TH} scope="col">
              {t('dashboardKit.table.period', 'Period')}
            </th>
            {result.series.map((s) => (
              <th key={s.key} className={TH + ' text-end'} scope="col">
                {label(s)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {times.map((time) => (
            <tr key={time} className="border-b last:border-0">
              <th scope="row" className={TD + ' font-normal text-start'}>
                {formatBucket(time, result.bucket, locale)}
              </th>
              {result.series.map((s) => {
                const p = s.points.find((x) => x.t === time)
                return (
                  <td key={s.key} className={TD + ' text-end'}>
                    <Cell
                      text={p ? formatMetric(p.v, unit, locale) : '—'}
                      to={p ? drill?.({ series: s.key, t: time }) : undefined}
                    />
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function MatrixTable({ result, drill }: { result: MatrixResult; drill?: DrillFn }) {
  const { t, locale } = useTranslation()
  const label = useLabel()
  return (
    <div className="overflow-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b">
            <th className={TH} scope="col">
              <span className="sr-only">{t('dashboardKit.table.item', 'Item')}</span>
            </th>
            {result.cols.map((c) => (
              <th key={c.key} className={TH + ' text-end'} scope="col">
                {label(c)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {result.rows.map((r, i) => (
            <tr key={r.key} className="border-b last:border-0">
              <th scope="row" className={TD + ' font-normal text-start'}>
                {label(r)}
              </th>
              {result.cols.map((c, j) => {
                const v = result.cells[i]?.[j] ?? null
                return (
                  <td key={c.key} className={TD + ' text-end'}>
                    <Cell
                      text={formatCount(v, locale)}
                      to={v ? drill?.({ series: r.key, key: c.key }) : undefined}
                    />
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function StagesTable({ result }: { result: StagesResult }) {
  const { t, locale } = useTranslation()
  const label = useLabel()
  return (
    <div className="overflow-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b">
            <th className={TH} scope="col">
              {t('dashboardKit.table.stage', 'Stage')}
            </th>
            <th className={TH + ' text-end'} scope="col">
              {t('dashboardKit.table.value', 'Value')}
            </th>
          </tr>
        </thead>
        <tbody>
          {result.stages.map((s) => (
            <tr key={s.key} className="border-b last:border-0">
              <th scope="row" className={TD + ' font-normal text-start'}>
                <Cell text={label(s)} to={s.drill} />
              </th>
              <td className={TD + ' text-end'}>
                {formatMetric(s.value, s.unit ?? 'count', locale)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function PathsTable({ result }: { result: PathsResult }) {
  const { t, locale } = useTranslation()
  return (
    <div className="overflow-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b">
            <th className={TH} scope="col">
              {t('dashboardKit.paths.crownJewel', 'Crown jewel')}
            </th>
            <th className={TH + ' text-end'} scope="col">
              {t('dashboardKit.paths.entryPoints', 'Entry points reaching it')}
            </th>
            <th className={TH + ' text-end'} scope="col">
              {t('dashboardKit.paths.score', 'Path score')}
            </th>
          </tr>
        </thead>
        <tbody>
          {result.rows.map((r) => (
            <tr key={r.id} className="border-b last:border-0">
              <th scope="row" className={TD + ' font-normal text-start'}>
                <Cell text={r.name} to={r.href} />
              </th>
              <td className={TD + ' text-end'}>
                {r.entry_point
                  ? t('dashboardKit.paths.isEntryPoint', 'Entry point itself')
                  : formatCount(r.reachable_from, locale)}
              </td>
              <td className={TD + ' text-end'}>{formatCount(Math.round(r.score), locale)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
