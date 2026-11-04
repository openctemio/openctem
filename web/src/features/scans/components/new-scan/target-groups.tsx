'use client'

/**
 * The Targets step's result column: what the scan will probe, grouped by kind
 * (domains, wildcards, address ranges, addresses, URLs, assets, asset groups),
 * each row with the scope check's answer, each group with the setting that
 * applies to it (the caller's `settings`) right under its heading. Long groups
 * show a few rows and "Show all". Scope is the server's answer (POST
 * /scope/check); nothing is decided here.
 */

import { useState, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import type { ApiScopeCheckResult } from '@/features/scope'
import type { TargetGroup, TargetGroupKind } from '../../lib/target-groups'
import { StateIcon, targetVerdict, verdictText, type RowState } from './target-list'

/** Rows shown per group before "Show all". */
export const GROUP_ROWS = 5

interface TargetGroupsProps {
  groups: readonly TargetGroup[]
  resultFor?: (target: string) => ApiScopeCheckResult | undefined
  checking?: boolean
  checkAvailable?: boolean
  /** A group's setting, under its heading. */
  settings?: Partial<Record<TargetGroupKind, ReactNode>>
  /** Extra words for a row (what a wildcard holds now), by its checkAs. */
  rowNote?: (checkAs: string) => string | undefined
}

export function TargetGroups({
  groups,
  resultFor,
  checking,
  checkAvailable = true,
  settings,
  rowNote,
}: TargetGroupsProps) {
  if (groups.length === 0) return null
  return (
    <div className="min-w-0 divide-y rounded-lg border" data-testid="target-groups">
      {groups.map((g) => (
        <Group
          key={g.kind}
          group={g}
          resultFor={resultFor}
          checking={checking}
          checkAvailable={checkAvailable}
          setting={settings?.[g.kind]}
          rowNote={rowNote}
        />
      ))}
    </div>
  )
}

function Group({
  group,
  resultFor,
  checking,
  checkAvailable,
  setting,
  rowNote,
}: {
  group: TargetGroup
  resultFor?: (target: string) => ApiScopeCheckResult | undefined
  checking?: boolean
  checkAvailable: boolean
  setting?: ReactNode
  rowNote?: (checkAs: string) => string | undefined
}) {
  const { t } = useTranslation()
  const [all, setAll] = useState(false)
  const rows = all ? group.rows : group.rows.slice(0, GROUP_ROWS)
  const headingId = `target-group-${group.kind}`
  return (
    <section
      className="min-w-0 space-y-2 p-3"
      aria-labelledby={headingId}
      data-testid={`target-group-${group.kind}`}
    >
      <h3 id={headingId} className="flex items-baseline gap-2 text-sm font-medium">
        {t(`scans.targetGroups.${group.kind}`)}
        <span className="text-xs font-normal text-muted-foreground tabular-nums">
          {group.rows.length.toLocaleString()}
        </span>
      </h3>
      {setting}
      <ul className="min-w-0 space-y-1">
        {rows.map((row) => {
          const state: RowState = row.checkAs
            ? targetVerdict(t, resultFor?.(row.checkAs), { checking, checkAvailable })
            : { kind: 'unchecked' }
          const note = row.checkAs ? rowNote?.(row.checkAs) : undefined
          const detail = [
            row.scannedAs
              ? t('scans.targetGroups.scannedAs', undefined, { target: row.scannedAs })
              : '',
            row.added ? t('scans.targetGroups.added') : '',
            row.checkAs ? verdictText(t, state) : t('scans.targetGroups.membersLater'),
            note ?? '',
          ]
            .filter(Boolean)
            .join(', ')
          return (
            <li key={row.key} className="flex min-w-0 items-start gap-2" data-state={state.kind}>
              <span className="mt-0.5">
                <StateIcon state={state} />
              </span>
              <span className="min-w-0 flex-1">
                <span
                  className={
                    row.checkAs ? 'block truncate font-mono text-sm' : 'block truncate text-sm'
                  }
                  title={row.label}
                >
                  {row.label}
                </span>
                <span
                  className="block truncate text-xs text-muted-foreground"
                  title={state.kind === 'refused' ? state.title : detail}
                >
                  {detail}
                </span>
              </span>
            </li>
          )
        })}
      </ul>
      {group.rows.length > GROUP_ROWS && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="-ms-2 h-8 max-sm:min-h-11"
          onClick={() => setAll((v) => !v)}
        >
          {all
            ? t('scans.preview.showFewer')
            : t('scans.preview.showAll', undefined, { count: group.rows.length })}
        </Button>
      )}
    </section>
  )
}
