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
import type { PlanEffectiveLimit } from '@/lib/api/generated'
import {
  formatLimit,
  isPlanKey,
  ORGANIZATION_KEYS,
  usagePercent,
  type PlanKey,
} from '../lib/plan-keys'

export interface PlanUsageTableText {
  limit: string
  limitColumn: string
  usedColumn: string
  unlimited: string
  overLimit: string
  override: string
  /** "until {date}" for an expiring override. */
  until: (date: string) => string
  keyLabel: (key: PlanKey) => string
}

export interface PlanUsageTableProps {
  limits: PlanEffectiveLimit[]
  text: PlanUsageTableText
  /** A cell at the end of each row (the console's override actions). */
  action?: (row: PlanEffectiveLimit & { key: PlanKey }) => ReactNode
  actionColumn?: string
}

/**
 * Used/limit per limit of one organization: the console's organization plan
 * tab and the organization's Settings > Plan & usage. Lowering a limit never
 * removes anything, so a row can be over its limit; it is flagged, not hidden.
 */
export function PlanUsageTable({ limits, text, action, actionColumn }: PlanUsageTableProps) {
  const rows = ORGANIZATION_KEYS.map((key) => {
    const row = limits.find((l) => l.key === key)
    return { ...(row ?? {}), key } as PlanEffectiveLimit & { key: PlanKey }
  }).filter((r) => isPlanKey(r.key))

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{text.limit}</TableHead>
          <TableHead className="w-[40%]">{text.usedColumn}</TableHead>
          <TableHead>{text.limitColumn}</TableHead>
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
                  {text.keyLabel(row.key)}
                  {row.over_limit && <Badge variant="destructive">{text.overLimit}</Badge>}
                </div>
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-3">
                  <span className="tabular-nums">{used}</span>
                  {pct !== null && (
                    <Progress
                      value={pct}
                      className="h-1.5 max-w-40"
                      aria-label={`${text.keyLabel(row.key)}: ${used} / ${row.limit}`}
                    />
                  )}
                </div>
              </TableCell>
              <TableCell>
                <div className="flex flex-col gap-0.5">
                  <span className="tabular-nums">{formatLimit(row.limit, text.unlimited)}</span>
                  {row.source === 'override' && (
                    <span className="text-xs text-muted-foreground">
                      {text.override}
                      {row.override_expires_at ? ` ${text.until(row.override_expires_at)}` : ''}
                      {row.override_reason ? `: ${row.override_reason}` : ''}
                    </span>
                  )}
                </div>
              </TableCell>
              {action && <TableCell className="text-end">{action(row)}</TableCell>}
            </TableRow>
          )
        })}
      </TableBody>
    </Table>
  )
}
