'use client'

import { useMemo } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable, DataTableColumnHeader } from '@/features/shared'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { ExternalLink, FileWarning, Info } from 'lucide-react'
import { getMitreTechnique, mitreTechniqueUrl } from '@/features/pentest/lib/mitre-attack'
import type { AttackerProfileLite, Threat, ThreatFilters } from '../types'
import { StatusLozenge } from '@/components/ui/status-lozenge'
import { getThreatStatusStyle } from '../lib/threat-status'

interface ThreatModelTableProps {
  threats: Threat[]
  filters: ThreatFilters
  onFiltersChange: (filters: ThreatFilters) => void
  profileMap: Map<string, AttackerProfileLite>
  nameFor: (id: string | undefined) => string
}

const ALL = 'all'

/** Build a readable entry → hop → target path from resolved asset names. */
function pathLabel(threat: Threat, nameFor: (id: string | undefined) => string): string {
  const raw = [threat.entry_point_asset_id, threat.hop_asset_id, threat.target_asset_id]
    .filter(Boolean)
    .map((id) => nameFor(id))
  const dedup = raw.filter((name, i) => i === 0 || name !== raw[i - 1])
  return dedup.join(' → ')
}

export function ThreatModelTable({
  threats,
  filters,
  onFiltersChange,
  profileMap,
  nameFor,
}: ThreatModelTableProps) {
  const { t } = useTranslation()
  // Filter option lists derived from the full (unfiltered) threat set.
  const { tactics, attackers, techniques, statuses } = useMemo(() => {
    const tacticSet = new Set<string>()
    const attackerSet = new Map<string, string>()
    const techniqueSet = new Map<string, string>()
    const statusSet = new Set<string>()
    for (const th of threats) {
      tacticSet.add(th.tactic)
      statusSet.add(th.status)
      attackerSet.set(
        th.attacker_profile_id,
        profileMap.get(th.attacker_profile_id)?.name ?? t('threatModel.table.unknown', 'Unknown')
      )
      const techName = th.technique_name ?? getMitreTechnique(th.technique_id)?.name
      techniqueSet.set(
        th.technique_id,
        techName ? `${th.technique_id}, ${techName}` : th.technique_id
      )
    }
    return {
      tactics: Array.from(tacticSet).sort(),
      attackers: Array.from(attackerSet.entries()).sort((a, b) => a[1].localeCompare(b[1])),
      techniques: Array.from(techniqueSet.entries()).sort((a, b) => a[0].localeCompare(b[0])),
      statuses: Array.from(statusSet).sort(),
    }
  }, [threats, profileMap, t])

  const filtered = useMemo(
    () =>
      threats.filter((th) => {
        if (filters.status !== ALL && th.status !== filters.status) return false
        if (filters.tactic !== ALL && th.tactic !== filters.tactic) return false
        if (filters.attacker !== ALL && th.attacker_profile_id !== filters.attacker) return false
        if (filters.technique !== ALL && th.technique_id !== filters.technique) return false
        return true
      }),
    [threats, filters]
  )

  const columns = useMemo<ColumnDef<Threat>[]>(
    () => [
      {
        accessorKey: 'attacker_profile_id',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('threatModel.table.attacker', 'Attacker')}
          />
        ),
        cell: ({ row }) => {
          const profile = profileMap.get(row.original.attacker_profile_id)
          return (
            <span className="font-medium">
              {profile?.name ?? t('threatModel.table.unknownAttacker', 'Unknown attacker')}
            </span>
          )
        },
      },
      {
        id: 'path',
        header: t('threatModel.table.attackPath', 'Attack path'),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-muted-foreground text-xs">{pathLabel(row.original, nameFor)}</span>
        ),
      },
      {
        accessorKey: 'technique_id',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('threatModel.table.technique', 'Technique')}
          />
        ),
        cell: ({ row }) => {
          const id = row.original.technique_id
          const name = row.original.technique_name ?? getMitreTechnique(id)?.name
          return (
            <a
              href={mitreTechniqueUrl(id)}
              target="_blank"
              rel="noopener noreferrer"
              className="group inline-flex items-center gap-1"
            >
              <span className="font-mono text-xs font-medium">{id}</span>
              {name && <span className="text-muted-foreground text-xs">{name}</span>}
              <ExternalLink className="text-muted-foreground h-3 w-3 opacity-0 transition-opacity group-hover:opacity-100" />
            </a>
          )
        },
      },
      {
        accessorKey: 'tactic',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('threatModel.table.tactic', 'Tactic')} />
        ),
        cell: ({ row }) => (
          <Badge variant="outline" className="font-normal">
            {row.original.tactic}
          </Badge>
        ),
      },
      {
        accessorKey: 'mitigation_id',
        header: t('threatModel.table.mitigation', 'Mitigation'),
        enableSorting: false,
        cell: ({ row }) => {
          const id = row.original.mitigation_id
          const name = row.original.mitigation_name
          const summary = row.original.mitigation_summary
          if (!id && !name) {
            return <span className="text-muted-foreground text-xs">—</span>
          }
          // Prefer the human name; keep the Mxxxx id as a muted secondary label.
          const primary = name ?? id
          const label = (
            <span className="flex flex-col leading-tight">
              <span className="text-sm">{primary}</span>
              {name && id && <span className="text-muted-foreground font-mono text-xs">{id}</span>}
            </span>
          )
          if (!summary) return label
          return (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="inline-flex cursor-help items-start gap-1">
                    {label}
                    <Info className="text-muted-foreground mt-0.5 h-3.5 w-3.5 shrink-0" />
                  </span>
                </TooltipTrigger>
                <TooltipContent className="max-w-xs">{summary}</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )
        },
      },
      {
        accessorKey: 'status',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('threatModel.table.status', 'Status')} />
        ),
        cell: ({ row }) => {
          const threat = row.original
          const style = getThreatStatusStyle(threat.status)
          return (
            <div className="flex items-center gap-1.5">
              <StatusLozenge
                tone={style.tone}
                icon={style.icon}
                label={t(style.labelKey, threat.status)}
                value={threat.status}
              />
              {threat.status_reason && (
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Info className="text-muted-foreground h-3.5 w-3.5 cursor-help" />
                    </TooltipTrigger>
                    <TooltipContent className="max-w-xs">{threat.status_reason}</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'score',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('threatModel.table.score', 'Score')} />
        ),
        cell: ({ row }) => (
          <span className="text-sm tabular-nums">{row.original.score.toFixed(1)}</span>
        ),
      },
      {
        id: 'evidence',
        header: t('threatModel.table.evidence', 'Evidence'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.evidence_finding_id ? (
            <Button variant="ghost" size="sm" asChild className="h-7 px-2">
              <Link href={`/findings/${row.original.evidence_finding_id}`}>
                <FileWarning className="me-1 h-3.5 w-3.5" />
                {t('threatModel.table.finding', 'Finding')}
              </Link>
            </Button>
          ) : (
            <span className="text-muted-foreground text-xs">—</span>
          ),
      },
    ],
    [profileMap, nameFor, t]
  )

  const setFilter = (patch: Partial<ThreatFilters>) => onFiltersChange({ ...filters, ...patch })

  const filtersOn =
    filters.status !== ALL ||
    filters.tactic !== ALL ||
    filters.attacker !== ALL ||
    filters.technique !== ALL

  // The filters sit in the table toolbar rather than a row of their own above it.
  const toolbarStart = (
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      <Select
        value={filters.status}
        onValueChange={(v) => setFilter({ status: v as ThreatFilters['status'] })}
      >
        <SelectTrigger
          className="h-9 w-auto max-w-52"
          aria-label={t('threatModel.filter.byStatus', 'Filter by status')}
        >
          <SelectValue placeholder={t('threatModel.table.status', 'Status')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>{t('threatModel.filter.allStatuses', 'All statuses')}</SelectItem>
          {statuses.map((s) => (
            <SelectItem key={s} value={s}>
              {t(getThreatStatusStyle(s as Threat['status']).labelKey, s)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select value={filters.tactic} onValueChange={(v) => setFilter({ tactic: v })}>
        <SelectTrigger
          className="h-9 w-auto max-w-52"
          aria-label={t('threatModel.filter.byTactic', 'Filter by tactic')}
        >
          <SelectValue placeholder={t('threatModel.table.tactic', 'Tactic')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>{t('threatModel.filter.allTactics', 'All tactics')}</SelectItem>
          {tactics.map((tactic) => (
            <SelectItem key={tactic} value={tactic}>
              {tactic}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select value={filters.attacker} onValueChange={(v) => setFilter({ attacker: v })}>
        <SelectTrigger
          className="h-9 w-auto max-w-52"
          aria-label={t('threatModel.filter.byAttacker', 'Filter by attacker')}
        >
          <SelectValue placeholder={t('threatModel.table.attacker', 'Attacker')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>
            {t('threatModel.filter.allAttackers', 'All attackers')}
          </SelectItem>
          {attackers.map(([id, name]) => (
            <SelectItem key={id} value={id}>
              {name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select value={filters.technique} onValueChange={(v) => setFilter({ technique: v })}>
        <SelectTrigger
          className="h-9 w-auto max-w-52"
          aria-label={t('threatModel.filter.byTechnique', 'Filter by technique')}
        >
          <SelectValue placeholder={t('threatModel.table.technique', 'Technique')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>
            {t('threatModel.filter.allTechniques', 'All techniques')}
          </SelectItem>
          {techniques.map(([id, label]) => (
            <SelectItem key={id} value={id}>
              {label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {filtersOn && (
        <Button
          variant="ghost"
          size="sm"
          className="h-9"
          onClick={() =>
            onFiltersChange({ status: ALL, tactic: ALL, attacker: ALL, technique: ALL })
          }
        >
          {t('threatModel.filter.clear', 'Clear filters')}
        </Button>
      )}
    </div>
  )

  return (
    <DataTable
      columns={columns}
      data={filtered}
      showSearch={false}
      toolbarStart={toolbarStart}
      emptyMessage={t('threatModel.table.emptyTitle', 'No threats match these filters')}
      emptyDescription={t(
        'threatModel.table.emptyDescription',
        'Clear the filters to see every threat.'
      )}
    />
  )
}
