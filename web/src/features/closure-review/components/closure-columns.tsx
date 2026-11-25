'use client'

import type { ColumnDef } from '@tanstack/react-table'

import { SeverityBadge } from '@/components/ui/severity-badge'
import type { DataTableColumnMeta } from '@/features/shared/components/data-table/column-meta'
import { TonePill } from '@/features/shared/components/tone-pill'
import { CellText } from '@/features/shared/components/cell-text'
import { ApprovalFindingLink } from '@/features/findings/components/approval-finding-link'
import { useTranslation } from '@/context/i18n-provider'
import { formatLocalized, formatRelative } from '@/lib/format-date'
import { toDisplayText } from '@/lib/untrusted-text'

import type { ClosureEvidence as Evidence } from '../types'
import { closureScanId, closureTool, METHOD_LABEL } from './closure-evidence'

/** What both closure lists show of a row. */
export interface ClosureRow {
  finding_id: string
  finding_title: string
  severity: string
  asset_name?: string
  evidence: Evidence
}

type Translate = ReturnType<typeof useTranslation>['t']

/** Widths in px: the longest en and vi value whole, plus the cell padding. */
export const CLOSURE_WIDTH = {
  // Small enough that Ready to close keeps its other columns whole in a 698 px frame
  // (1024 wide with the sidebar open).
  findingMin: 176,
  // "Default-branch scan" / "Quét nhánh mặc định" and the Held mark.
  method: 200,
  tool: 120,
} as const

/** A table frame narrower than this drops the column (Display > Columns brings it back). */
export const CLOSURE_HIDE_BELOW = { asset: 1300, tool: 1180, scan: 1300, method: 920 } as const

const meta = (m: DataTableColumnMeta) => m

/** How the platform knows: the method, and Held when a mass vanish held the close. */
export function ClosureMethod({ method, evidence }: { method: string; evidence: Evidence }) {
  const { t } = useTranslation()
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      <span className="truncate">
        {t(`findings.closureReview.method.${method}`, METHOD_LABEL[method] ?? method)}
      </span>
      {evidence.held === true && (
        <TonePill
          tone="warning"
          label={t('findings.closureReview.held', 'Held for review')}
          title={t(
            'findings.closureReview.heldHint',
            'Many findings vanished in one scan, so nothing closed automatically.'
          )}
        />
      )}
    </span>
  )
}

/** A relative time with the absolute one on hover; a dash without a value. */
export function ClosureTime({ value }: { value?: string }) {
  const { locale } = useTranslation()
  if (!value) return <span className="text-muted-foreground">-</span>
  return (
    <time
      dateTime={value}
      title={formatLocalized(value, locale, { time: true })}
      className="whitespace-nowrap text-muted-foreground"
    >
      {formatRelative(value, '-', locale)}
    </time>
  )
}

/**
 * The columns both lists share, in order: the finding (frozen at the start),
 * its severity, its asset, then how the close is proven. `method`, `at` and
 * `atLabel` differ between a proposal and a close already made.
 */
export function closureColumns<T extends ClosureRow>(
  t: Translate,
  opts: {
    method: (row: T) => string
    at: (row: T) => string | undefined
    methodLabel: string
    atLabel: string
    /** Drop the time column below this frame width (a list with more columns). */
    atHideBelow?: number
  }
): ColumnDef<T>[] {
  const label = {
    finding: t('findings.closureReview.col.finding', 'Finding'),
    severity: t('findings.closureReview.col.severity', 'Severity'),
    asset: t('findings.closureReview.col.asset', 'Asset'),
    tool: t('findings.closureReview.col.tool', 'Tool'),
    scan: t('findings.closureReview.col.scan', 'Scan'),
  }
  return [
    {
      id: 'finding',
      meta: meta({
        kind: 'name',
        pin: 'start',
        minWidth: CLOSURE_WIDTH.findingMin,
        label: label.finding,
      }),
      header: label.finding,
      enableHiding: false,
      enableSorting: false,
      cell: ({ row }) => (
        // The title takes the room the column has and never widens it.
        <div className="w-0 min-w-full">
          <ApprovalFindingLink
            findingId={row.original.finding_id}
            findingTitle={row.original.finding_title}
            lines={1}
          />
        </div>
      ),
    },
    {
      id: 'severity',
      meta: meta({ kind: 'severity', label: label.severity }),
      header: label.severity,
      enableSorting: false,
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    },
    {
      id: 'asset',
      meta: meta({ kind: 'asset', hideBelow: CLOSURE_HIDE_BELOW.asset, label: label.asset }),
      header: label.asset,
      enableSorting: false,
      cell: ({ row }) =>
        row.original.asset_name ? (
          <div className="w-0 min-w-full">
            <CellText dir="auto">{toDisplayText(row.original.asset_name, 120)}</CellText>
          </div>
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    {
      id: 'method',
      // The phone card and Display > Columns keep it below that frame.
      meta: meta({
        kind: 'text',
        width: CLOSURE_WIDTH.method,
        hideBelow: CLOSURE_HIDE_BELOW.method,
        label: opts.methodLabel,
      }),
      header: opts.methodLabel,
      enableSorting: false,
      cell: ({ row }) => (
        <ClosureMethod method={opts.method(row.original)} evidence={row.original.evidence} />
      ),
    },
    {
      id: 'tool',
      meta: meta({
        kind: 'text',
        width: CLOSURE_WIDTH.tool,
        hideBelow: CLOSURE_HIDE_BELOW.tool,
        label: label.tool,
      }),
      header: label.tool,
      enableSorting: false,
      cell: ({ row }) => {
        const tool = closureTool(row.original.evidence)
        return tool ? (
          <span className="block truncate text-muted-foreground">{tool}</span>
        ) : (
          <span className="text-muted-foreground">-</span>
        )
      },
    },
    {
      id: 'at',
      meta: meta({ kind: 'datetime-recent', hideBelow: opts.atHideBelow, label: opts.atLabel }),
      header: opts.atLabel,
      enableSorting: false,
      cell: ({ row }) => <ClosureTime value={opts.at(row.original)} />,
    },
    {
      id: 'scan',
      meta: meta({ kind: 'id', hideBelow: CLOSURE_HIDE_BELOW.scan, label: label.scan }),
      header: label.scan,
      enableSorting: false,
      cell: ({ row }) => {
        const scan = closureScanId(row.original.evidence)
        return scan ? (
          <span className="font-mono text-muted-foreground" title={scan}>
            {scan.slice(0, 8)}
          </span>
        ) : (
          <span className="text-muted-foreground">-</span>
        )
      },
    },
  ]
}
