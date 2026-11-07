'use client'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { RunStatusBadge } from '@/features/shared'
import type { RunZoneSplit } from '@/lib/api/scan-workflow-types'
import { toDisplayText } from '@/lib/untrusted-text'

const runHref = (id: string) => `/scans/runs?run=${encodeURIComponent(id)}`

/**
 * A workflow run whose targets fell in several scan zones runs as one zone
 * run per zone. On the parent: one row per zone (targets, status, link to
 * the zone run). On a zone run: which run it is part of and its zone.
 */
export function RunZoneSplitPanel({
  split,
  parentRunId,
}: {
  split: RunZoneSplit
  parentRunId?: string
}) {
  const { t } = useTranslation()
  const noZone = t('scans.runZoneSplit.noZone')
  const parent = parentRunId ?? split.parent_run_id
  if (parent) {
    return (
      <p className="text-sm" data-testid="run-zone-split-child">
        {t(
          'scans.runZoneSplit.partOf',
          'Zone run {part} of {parts} ({zone}) of a scan whose targets are in several zones.',
          {
            zone: split.zone_name ? toDisplayText(split.zone_name) : noZone,
            part: split.part ?? 1,
            parts: split.parts ?? 1,
          }
        )}{' '}
        <Link href={runHref(parent)} className="font-medium underline-offset-2 hover:underline">
          {t('scans.runZoneSplit.openParent')}
        </Link>
      </p>
    )
  }
  const groups = split.groups ?? []
  return (
    <div className="space-y-2" data-testid="run-zone-split-groups">
      <p className="text-sm text-muted-foreground">{t('scans.runZoneSplit.explain')}</p>
      <ul className="divide-y rounded-md border">
        {groups.map((g, i) => (
          <li
            key={g.zone_id || `none-${i}`}
            className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm"
          >
            <span className="font-medium">{g.zone_name ? toDisplayText(g.zone_name) : noZone}</span>
            <span className="text-muted-foreground">
              {t('scans.runZoneSplit.targets', '{count} target(s)', { count: g.targets })}
            </span>
            <span className="ml-auto flex items-center gap-3">
              {g.status === 'refused' ? (
                <span className="text-muted-foreground">
                  {t('scans.runZoneSplit.refused')}
                  {g.reason ? `: ${toDisplayText(g.reason)}` : ''}
                </span>
              ) : (
                <>
                  {g.run_status && <RunStatusBadge status={g.run_status} />}
                  {g.run_id && (
                    <Link
                      href={runHref(g.run_id)}
                      className="font-medium underline-offset-2 hover:underline"
                    >
                      {t('scans.runZoneSplit.openRun')}
                    </Link>
                  )}
                </>
              )}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}
