'use client'

/**
 * The targets the organization's exclusions left out of a run, or would
 * leave out of a scan about to start, with the matching rules (RFC-054
 * §6.5): GET /scan-runs/{id} `dispatch.excluded` and the scan preview's
 * `targets.excluded_detail`. A range cut around excluded addresses is listed
 * with how many it lost. Rules link to Scoping > Out of scope.
 */

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'

export interface ExcludedTargetItem {
  target?: string
  rules?: { kind?: string; id?: string; pattern?: string }[]
  cut?: boolean
  removed_addresses?: number
}

/** Scoping > Out of scope. */
export const OUT_OF_SCOPE_HREF = '/scope?tab=out'

export function ExcludedTargetsList({
  items,
  total,
}: {
  items: ExcludedTargetItem[]
  /** Targets left out whole (the run's count); cut ranges are added. */
  total: number
}) {
  const { t } = useTranslation()
  if (items.length === 0 && total === 0) return null
  const cut = items.filter((i) => i.cut).length
  const count = total + cut
  return (
    <section className="space-y-2" data-testid="excluded-targets">
      <h4 className="text-sm font-semibold">
        {count === 1
          ? t('scans.excluded.title.one', '1 target left out by exclusions')
          : t('scans.excluded.title.other', '{count} targets left out by exclusions', { count })}
      </h4>
      {items.length > 0 && (
        <ul className="divide-y rounded-md border text-sm">
          {items.map((i) => (
            <li
              key={`${i.cut ? 'cut' : 'whole'}:${i.target}`}
              className="flex flex-col gap-0.5 px-3 py-2 sm:flex-row sm:items-baseline sm:gap-3"
            >
              <code className="shrink-0 break-all font-mono text-xs">{i.target}</code>
              <span className="min-w-0 flex-1 text-xs text-muted-foreground">
                {i.cut
                  ? t('scans.excluded.cut', 'Range scanned without {count} excluded address(es)', {
                      count: i.removed_addresses ?? 0,
                    })
                  : t('scans.excluded.whole', 'Not scanned')}
              </span>
              <span className="text-xs">
                {(i.rules ?? []).length === 0 ? (
                  <span className="text-muted-foreground">
                    {t('scans.excluded.ruleUnknown', 'Matching rule not recorded')}
                  </span>
                ) : (
                  (i.rules ?? []).map((r) => (
                    <Link
                      key={r.id ?? r.pattern}
                      href={OUT_OF_SCOPE_HREF}
                      className="me-2 text-primary hover:underline"
                    >
                      {t('scans.excluded.rule', 'Exclusion {pattern}', {
                        pattern: r.pattern ?? '',
                      })}
                    </Link>
                  ))
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
      {count > items.length && items.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {t('scans.excluded.more', 'The first {shown} are listed.', { shown: items.length })}
        </p>
      )}
    </section>
  )
}
