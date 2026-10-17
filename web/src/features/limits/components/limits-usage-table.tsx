'use client'

import type { ReactNode } from 'react'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import {
  formatLimit,
  isLimitKey,
  LIMIT_KEY_LABEL,
  usagePercent,
  type LimitKey,
} from '../lib/limit-keys'

/** One row of the table: what the organization uses against one limit. */
export interface LimitUsageRow {
  key: LimitKey
  limit?: number
  used?: number
  over_limit?: boolean
  uncounted?: boolean
}

export interface LimitsUsageTableProps<R extends LimitUsageRow> {
  rows: R[]
  /** Extra text under the limit (the console: who set it, why, until when). */
  limitNote?: (row: R) => ReactNode
  /** A cell at the end of each row (the console's actions). */
  action?: (row: R) => ReactNode
  actionColumn?: string
}

/** The translated name of a limit key. */
export function useLimitKeyLabel() {
  const { t } = useTranslation()
  return (key: string | undefined) =>
    isLimitKey(key) ? t(`limits.key.${key}`, LIMIT_KEY_LABEL[key]) : (key ?? '')
}

/**
 * Used/limit per limit of one organization: the console's organization
 * Limits tab and the organization's Settings > Usage & limits. Lowering a
 * limit never removes anything, so a row can be over its limit; it is
 * flagged, not hidden.
 */
export function LimitsUsageTable<R extends LimitUsageRow>({
  rows,
  limitNote,
  action,
  actionColumn,
}: LimitsUsageTableProps<R>) {
  const { t } = useTranslation()
  const keyLabel = useLimitKeyLabel()
  const unlimited = t('limits.unlimited', 'Unlimited')
  const notCounted = t('limits.notCounted', 'Counted while a limit is set')

  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t('limits.col.item', 'Limit')}</TableHead>
            <TableHead className="w-[40%]">{t('limits.col.used', 'Used')}</TableHead>
            <TableHead>{t('limits.col.limit', 'Allowed')}</TableHead>
            {action && <TableHead className="text-end">{actionColumn}</TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => {
            const used = row.used ?? 0
            const pct = usagePercent(used, row.limit)
            return (
              <TableRow key={row.key} data-over-limit={row.over_limit ? 'true' : undefined}>
                <TableCell className="font-medium">
                  <div className="flex flex-wrap items-center gap-2">
                    {keyLabel(row.key)}
                    {row.over_limit && (
                      <Badge variant="destructive">{t('limits.overLimit', 'Over limit')}</Badge>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-3">
                    {row.uncounted ? (
                      <span className="text-muted-foreground" title={notCounted}>
                        <span aria-hidden="true">—</span>
                        <span className="sr-only">{notCounted}</span>
                      </span>
                    ) : (
                      <span className="tabular-nums">{used}</span>
                    )}
                    {pct !== null && (
                      <Progress
                        value={pct}
                        className="h-1.5 max-w-40"
                        aria-label={`${keyLabel(row.key)}: ${used} / ${row.limit}`}
                      />
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-col gap-0.5">
                    <span className="tabular-nums">{formatLimit(row.limit, unlimited)}</span>
                    {limitNote?.(row)}
                  </div>
                </TableCell>
                {action && <TableCell className="text-end">{action(row)}</TableCell>}
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}
