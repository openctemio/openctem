'use client'

import { Checkbox } from '@/components/ui/checkbox'
import { useTranslation } from '@/context/i18n-provider'
import type { MobileRowSelection } from '@/features/shared/components/data-table'
import { MetaLine } from '@/features/shared/components/text-layout'
import { useSeverityLabel } from '@/hooks/use-scale-labels'
import type { SeverityLevel } from '@/lib/severity'
import { formatEpssScore } from '@/lib/epss'
import { toDisplayText } from '@/lib/untrusted-text'
import { CveLink } from '../cve-link'
import { headlineFixVersion } from '../../lib/vuln-list'
import type { VulnListItem } from '../../types/list'
import { signalWords } from './vuln-list-cells'

/**
 * A vulnerability on a phone. Fixed slots, plain text, one fact per element:
 *
 *   [ ] CVE-2024-3094 ................................... P1
 *       Backdoor in xz (two lines at most)
 *       Known exploited, Weaponized, 2 past SLA
 *       Critical 10.0   EPSS 86.2%   12 assets   Fix 5.6.2
 *
 * The priority slot is always there (a dash when the vulnerability is not
 * prioritised). A tap on the card opens the vulnerability page; the checkbox
 * shows only in select mode.
 */
export function VulnPhoneCard({
  item,
  selection,
  onOpen,
}: {
  item: VulnListItem
  selection: MobileRowSelection
  onOpen: () => void
}) {
  const { t } = useTranslation()
  const severityLabel = useSeverityLabel()
  const fix = headlineFixVersion(item)
  const title = item.title && item.title !== item.cve_id ? toDisplayText(item.title, 160) : ''
  const signals = signalWords(item, t)
  return (
    <div
      data-slot="vuln-card"
      data-state={selection.selected ? 'selected' : undefined}
      className="flex cursor-pointer items-start gap-3 px-3 py-3 hover:bg-muted/50 data-[state=selected]:bg-muted"
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('button, a[href], [role="checkbox"]')) return
        onOpen()
      }}
    >
      {selection.selectable && (
        <Checkbox
          className="mt-0.5 shrink-0"
          checked={selection.selected}
          onCheckedChange={(v) => selection.onSelectedChange(!!v)}
          aria-label={t('vulnPage.list.selectRow', 'Select {cve}', { cve: item.cve_id })}
        />
      )}
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex min-w-0 items-baseline justify-between gap-3">
          <CveLink id={item.cve_id} stopPropagation className="min-w-0 truncate font-medium" />
          <span
            data-slot="vuln-card-priority"
            className="shrink-0 text-sm font-medium tabular-nums"
            aria-label={
              item.worst_priority
                ? t('vulnPage.list.mobile.priority', 'Priority {class}', {
                    class: item.worst_priority,
                  })
                : t('findings.priorityBadge.none', 'Not prioritised')
            }
          >
            {item.worst_priority || <span className="text-muted-foreground">—</span>}
          </span>
        </div>
        {title && <p className="line-clamp-2 text-sm text-muted-foreground">{title}</p>}
        <p className="text-meta">
          {signals.length > 0 ? (
            signals.join(', ')
          ) : (
            <span className="text-muted-foreground">
              {t('vulnPage.list.signal.none', 'No signal')}
            </span>
          )}
        </p>
        <MetaLine
          items={[
            <span key="sev">
              {severityLabel(item.severity as SeverityLevel)}
              {item.cvss_score != null && (
                <span className="ms-1 tabular-nums">{item.cvss_score.toFixed(1)}</span>
              )}
            </span>,
            <span key="epss" className="tabular-nums">
              {t('vulnPage.list.mobile.epss', 'EPSS {value}', {
                value: formatEpssScore(item.epss_score, 1, '—'),
              })}
            </span>,
            <span key="assets" className="tabular-nums">
              {t('vulnPage.list.mobile.assets', '{count, plural, one {# asset} other {# assets}}', {
                count: item.assets,
              })}
            </span>,
            <span key="fix">
              {fix
                ? t('vulnPage.list.mobile.fix', 'Fix {version}', {
                    version: toDisplayText(fix, 40),
                  })
                : t('vulnPage.list.noFix', 'No fix yet')}
            </span>,
          ]}
        />
      </div>
    </div>
  )
}
