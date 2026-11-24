'use client'

/**
 * A program's own targets with what it says about each (RFC-065 §16.8):
 * the port or path limit, bounty eligibility, maximum severity,
 * environment, testing instructions, prerequisites and how far the target
 * can be trusted. They are shown as published; none of them authorizes a
 * scan (the scope entries do).
 *
 * The shared table: on a phone each target is a card (a seven-column table
 * squeezed the target into a sliver and cut its headers), and there is no
 * toolbar row (nothing to search or arrange).
 */

import { useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable } from '@/features/shared'
import type { ProgramItem } from '../api/programs-api.types'
import { itemLimit } from '../lib/program-targets'

export function ProgramTargetsTable({
  items,
  error,
  onRetry,
}: {
  items: ProgramItem[]
  /** The program's read failed (a refresh while its last copy shows). */
  error?: unknown
  onRetry?: () => void
}) {
  const { t } = useTranslation()
  const rows = useMemo(() => items.filter((i) => i.in_scope), [items])
  const columns = useMemo<ColumnDef<ProgramItem>[]>(
    () => [
      {
        id: 'target',
        meta: { kind: 'name' },
        header: t('programs.targets.target', 'Target'),
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs [overflow-wrap:anywhere]">{row.original.raw}</span>
        ),
      },
      {
        id: 'limit',
        meta: { kind: 'text' },
        header: t('programs.targets.limit', 'Limited to'),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs">{itemLimit(row.original) || '—'}</span>
        ),
      },
      {
        // Bounty, maximum severity and environment in one column of labelled
        // lines: seven columns did not fit a tablet and cut the last header.
        id: 'terms',
        meta: { kind: 'text' },
        header: t('programs.targets.terms', 'Terms'),
        enableSorting: false,
        cell: ({ row }) => {
          const it = row.original
          const lines: [string, string][] = []
          if (it.eligible_for_bounty !== undefined)
            lines.push([
              t('programs.targets.bounty', 'Bounty'),
              it.eligible_for_bounty
                ? t('programs.targets.eligible', 'Eligible')
                : t('programs.targets.notEligible', 'Not eligible'),
            ])
          if (it.max_severity)
            lines.push([
              t('programs.targets.maxSeverity', 'Max severity'),
              t(`programs.targets.severity.${it.max_severity}`, it.max_severity),
            ])
          if (it.environment)
            lines.push([
              t('programs.targets.environment', 'Environment'),
              t(`programs.targets.env.${it.environment}`, it.environment),
            ])
          if (lines.length === 0) return '—'
          return (
            <span className="flex flex-col text-xs">
              {lines.map(([label, value]) => (
                <span key={label}>
                  <span className="text-muted-foreground">{label}:</span> {value}
                </span>
              ))}
            </span>
          )
        },
      },
      {
        id: 'source',
        meta: { kind: 'status' },
        header: t('programs.targets.trust', 'Source'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.confidence ? (
            <Badge variant={row.original.confidence === 'published' ? 'secondary' : 'outline'}>
              {t(`programs.targets.trust.${row.original.confidence}`, row.original.confidence)}
            </Badge>
          ) : (
            '—'
          ),
      },
      {
        id: 'instructions',
        meta: { kind: 'text' },
        header: t('programs.targets.instructions', 'Instructions'),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="block max-w-xs whitespace-pre-wrap text-xs text-muted-foreground">
            {row.original.instructions}
            {row.original.requires && (
              <span className="block">
                {t('programs.targets.requires', 'Requires: {value}', {
                  value: row.original.requires,
                })}
              </span>
            )}
          </span>
        ),
      },
    ],
    [t]
  )
  if (rows.length === 0) return null
  return (
    <DataTable
      columns={columns}
      data={rows}
      error={error}
      onRetry={onRetry}
      getRowId={(it) => `${it.raw}|${it.ports ?? ''}`}
      showToolbar={false}
      showSearch={false}
      showColumnToggle={false}
      pageSize={50}
    />
  )
}
