'use client'

/**
 * The embedded findings table: the `items` shape drawn as a compact table
 * (Priority, Finding with its asset and KEV chip, Severity, SLA), a read-only
 * row of the list's filters above it, and a footer that says how much of the
 * list it shows with a link that opens the same list. Read-only: it draws the
 * widget's already-scoped rows and opens nothing but the widget's own drill.
 */

import { KevBadge } from '@/components/ui/kev-badge'
import { PriorityBadge } from '@/components/ui/priority-badge'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { useTranslation } from '@/context/i18n-provider'
import { formatCount } from '@/lib/format-metric'
import { isPriorityClass } from '@/lib/priority-colors'
import { safeInternalHref } from '@/lib/safe-href'
import { DueLabel } from './due-label'
import { DrillLink } from './viz-parts'
import type { ItemsResult } from './types'

const TH = 'px-2 py-1.5 text-start text-meta font-medium text-muted-foreground'
const TD = 'px-2 py-2 align-top text-data'
/** Severity and SLA are the first columns to go on a phone. */
const WIDE = 'hidden sm:table-cell'

export interface ItemsTableProps {
  result: ItemsResult
  /** The full list in the same order and filter ("Open in Findings"). */
  viewAllHref?: string
  /** The list's filters, already translated, shown as read-only chips. */
  filters?: string[]
}

export function ItemsTable({ result, viewAllHref, filters = [] }: ItemsTableProps) {
  const { t, locale } = useTranslation()
  const rows = result.rows
  const open = safeInternalHref(viewAllHref)
  const n = formatCount(rows.length, locale)
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2" data-testid="items-table">
      {filters.length > 0 && (
        <ul
          className="flex flex-wrap gap-1.5"
          aria-label={t('dashboardKit.itemsTable.filters', 'List filters')}
        >
          {filters.map((f) => (
            <li
              key={f}
              className="rounded-full border px-2 py-0.5 text-meta text-muted-foreground"
              data-testid="items-table-filter"
            >
              {f}
            </li>
          ))}
        </ul>
      )}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b">
              <th className={TH} scope="col">
                {t('dashboardKit.itemsTable.priority', 'Priority')}
              </th>
              <th className={TH} scope="col">
                {t('dashboardKit.itemsTable.finding', 'Finding')}
              </th>
              <th className={`${TH} ${WIDE}`} scope="col" data-col="severity">
                {t('dashboardKit.itemsTable.severity', 'Severity')}
              </th>
              <th className={`${TH} ${WIDE}`} scope="col" data-col="sla">
                {t('dashboardKit.itemsTable.sla', 'SLA')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {rows.map((r) => (
              <tr key={r.id}>
                <td className={`${TD} whitespace-nowrap`}>
                  {r.priority && isPriorityClass(r.priority) ? (
                    <PriorityBadge priorityClass={r.priority} />
                  ) : (
                    <PriorityBadge priorityClass={null} />
                  )}
                </td>
                <td className={`${TD} min-w-[12rem]`}>
                  <div className="flex items-start gap-2">
                    <div className="min-w-0 flex-1">
                      <DrillLink to={r.href} className="line-clamp-2 font-medium hover:underline">
                        {r.title?.trim() || t('dashboardKit.items.untitled', 'Untitled finding')}
                      </DrillLink>
                      {r.asset && (
                        <p className="truncate text-meta text-muted-foreground">{r.asset}</p>
                      )}
                    </div>
                    {r.kev && <KevBadge label={t('dashboardKit.items.kev', 'KEV')} />}
                  </div>
                </td>
                <td className={`${TD} ${WIDE} whitespace-nowrap`}>
                  <SeverityBadge severity={r.severity} />
                </td>
                <td className={`${TD} ${WIDE} whitespace-nowrap`}>
                  <DueLabel dueAt={r.due_at} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-auto flex items-center justify-between gap-2 pt-1 text-meta text-muted-foreground">
        <span data-testid="items-table-footer">
          {result.total != null
            ? t('dashboardKit.itemsTable.topOf', 'Top {n} of {total}', {
                n,
                total: formatCount(result.total, locale),
              })
            : t('dashboardKit.itemsTable.top', 'Top {n}', { n })}
        </span>
        {open && (
          <DrillLink to={open} className="text-primary hover:underline">
            {t('dashboardKit.itemsTable.open', 'Open in Findings')}
          </DrillLink>
        )}
      </div>
    </div>
  )
}
