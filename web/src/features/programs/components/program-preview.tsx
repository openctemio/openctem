'use client'

/**
 * What an import or re-import would do (RFC-065 §5.2), as the server
 * answered it: entries to create, already covered or refused, program
 * exclusions (with any overlap with the organization's own scope) and items
 * no scan can target.
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
import type {
  PlannedEntry,
  PlannedExclusion,
  ProgramItem,
  ProgramPreview as Preview,
} from '../api/programs-api.types'
import { summarizePreview } from '../lib/program-form'
import { portLimit } from '../lib/program-targets'

const ENTRY_STATUS: Record<
  PlannedEntry['status'],
  { label: string; variant: 'default' | 'secondary' | 'outline' | 'destructive' }
> = {
  create: { label: 'Will be added', variant: 'default' },
  keep: { label: 'Kept', variant: 'secondary' },
  already_covered: { label: 'Already an entry', variant: 'outline' },
  refused: { label: 'Refused', variant: 'destructive' },
}

export function ProgramEntriesTable({ entries }: { entries: PlannedEntry[] }) {
  const { t } = useTranslation()
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('programs.preview.target', 'In scope')}</TableHead>
          <TableHead>{t('programs.preview.type', 'Type')}</TableHead>
          <TableHead>{t('programs.preview.result', 'Result')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {entries.map((e) => (
          <TableRow key={`${e.target_type}:${e.pattern}:${e.constraint?.ports ?? ''}`}>
            <TableCell className="font-mono text-xs break-all">
              {e.pattern}
              {portLimit(e.constraint?.ports, e.constraint?.protocol) && (
                <Badge variant="outline" className="ml-2 font-mono">
                  {t('programs.targets.onlyPorts', 'only {ports}', {
                    ports: portLimit(e.constraint?.ports, e.constraint?.protocol),
                  })}
                </Badge>
              )}
            </TableCell>
            <TableCell className="text-muted-foreground text-xs">{e.target_type}</TableCell>
            <TableCell>
              <Badge variant={ENTRY_STATUS[e.status].variant}>
                {t(`programs.preview.status.${e.status}`, ENTRY_STATUS[e.status].label)}
              </Badge>
              {e.code && <span className="text-muted-foreground ml-2 text-xs">{e.code}</span>}
              {e.source && (
                <span className="text-muted-foreground ml-2 text-xs">
                  {t('programs.preview.source', 'source: {source}', { source: e.source })}
                </span>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

export function ProgramExclusionsTable({ exclusions }: { exclusions: PlannedExclusion[] }) {
  const { t } = useTranslation()
  if (exclusions.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">
        {t('programs.preview.noExclusions', 'No program exclusions.')}
      </p>
    )
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>
            {t('programs.preview.excluded', 'Out of scope for program entries')}
          </TableHead>
          <TableHead>{t('programs.preview.why', 'Why')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {exclusions.map((x) => (
          <TableRow key={`${x.target_type}:${x.pattern}`}>
            <TableCell className="font-mono text-xs break-all">{x.pattern}</TableCell>
            <TableCell className="text-xs">
              <span className="text-muted-foreground">{x.reason}</span>
              {x.in_scope_by && (
                <div className="mt-1">
                  <Badge variant="outline">
                    {t('programs.preview.overlap', 'In scope by {source}: {pattern}', {
                      source: x.in_scope_by.source,
                      pattern: x.in_scope_by.pattern,
                    })}
                  </Badge>
                </div>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function NotScannable({ items }: { items: ProgramItem[] }) {
  const { t } = useTranslation()
  if (items.length === 0) return null
  return (
    <div className="space-y-1">
      <h4 className="text-sm font-medium">
        {t('programs.preview.notScannable', 'Not scannable ({count})', { count: items.length })}
      </h4>
      <ul className="text-muted-foreground space-y-0.5 text-xs">
        {items.map((it) => (
          <li key={`${it.in_scope}:${it.raw}`} className="break-all">
            <span className="font-mono">{it.raw}</span>
            {it.note && <span> ({it.note})</span>}
          </li>
        ))}
      </ul>
    </div>
  )
}

export function ProgramPreviewView({ preview }: { preview: Preview }) {
  const { t } = useTranslation()
  const s = summarizePreview(preview)
  return (
    <div className="space-y-4">
      <p className="text-sm">
        {t(
          'programs.preview.summary',
          '{create} entries will be added, {covered} already exist, {refused} are refused; {exclusions} program exclusions ({overlaps} overlap your own scope). Probes allowed up to {tier}.',
          {
            create: s.create,
            covered: s.alreadyCovered,
            refused: s.refused,
            exclusions: s.exclusions,
            overlaps: s.overlaps,
            tier: preview.max_tier,
          }
        )}
      </p>
      <ProgramEntriesTable entries={preview.entries} />
      <ProgramExclusionsTable exclusions={preview.exclusions} />
      <NotScannable items={preview.not_scannable} />
    </div>
  )
}
