'use client'

/**
 * A program's own targets with what it says about each (RFC-065 §16.8):
 * the port or path limit, bounty eligibility, maximum severity,
 * environment, testing instructions, prerequisites and how far the target
 * can be trusted. They are shown as published; none of them authorizes a
 * scan (the scope entries do).
 */

import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import type { ProgramItem } from '../api/programs-api.types'
import { itemLimit } from '../lib/program-targets'

export function ProgramTargetsTable({ items }: { items: ProgramItem[] }) {
  const { t } = useTranslation()
  const rows = items.filter((i) => i.in_scope)
  if (rows.length === 0) return null
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('programs.targets.target', 'Target')}</TableHead>
          <TableHead>{t('programs.targets.limit', 'Limited to')}</TableHead>
          <TableHead>{t('programs.targets.bounty', 'Bounty')}</TableHead>
          <TableHead>{t('programs.targets.maxSeverity', 'Max severity')}</TableHead>
          <TableHead>{t('programs.targets.environment', 'Environment')}</TableHead>
          <TableHead>{t('programs.targets.trust', 'Source')}</TableHead>
          <TableHead>{t('programs.targets.instructions', 'Instructions')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((it) => (
          <TableRow key={`${it.raw}|${it.ports ?? ''}`}>
            <TableCell className="font-mono text-xs break-all">{it.raw}</TableCell>
            <TableCell className="font-mono text-xs">{itemLimit(it) || '—'}</TableCell>
            <TableCell className="text-xs">
              {it.eligible_for_bounty === undefined
                ? '—'
                : it.eligible_for_bounty
                  ? t('programs.targets.eligible', 'Eligible')
                  : t('programs.targets.notEligible', 'Not eligible')}
            </TableCell>
            <TableCell className="text-xs">
              {it.max_severity
                ? t(`programs.targets.severity.${it.max_severity}`, it.max_severity)
                : '—'}
            </TableCell>
            <TableCell className="text-xs">
              {it.environment ? t(`programs.targets.env.${it.environment}`, it.environment) : '—'}
            </TableCell>
            <TableCell>
              {it.confidence ? (
                <Badge variant={it.confidence === 'published' ? 'secondary' : 'outline'}>
                  {t(`programs.targets.trust.${it.confidence}`, it.confidence)}
                </Badge>
              ) : (
                '—'
              )}
            </TableCell>
            <TableCell className="text-muted-foreground max-w-xs text-xs whitespace-pre-wrap">
              {it.instructions}
              {it.requires && (
                <span className="block">
                  {t('programs.targets.requires', 'Requires: {value}', { value: it.requires })}
                </span>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
