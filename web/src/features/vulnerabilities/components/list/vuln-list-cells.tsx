'use client'

/**
 * The cells of the vulnerabilities list. Every cell is one line: the row
 * keeps the density's height (40 or 52), and what does not fit on the line is
 * in the cell's tooltip and on the vulnerability page. Producer and feed text
 * renders as text.
 */

import { Bug, Clock, Flame, Globe } from 'lucide-react'
import Link from '@/components/link'
import { KevBadge } from '@/components/ui/kev-badge'
import { SignalChip } from '@/components/ui/signal-chip'
import { useTranslation } from '@/context/i18n-provider'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import { formatEpssScore } from '@/lib/epss'
import { safeHref } from '@/lib/safe-href'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { EpssSparkline } from '../epss-trend'
import {
  headlineFixVersion,
  kevDueDays,
  remediationState,
  rowFindingsHref,
} from '../../lib/vuln-list'
import type { VulnListItem } from '../../types/list'
import { formatNumber } from '@/lib/app-locale'

type Translate = ReturnType<typeof useTranslation>['t']

/** Width of the Exploitation column (px), and what its chips may use of it. */
export const SIGNALS_WIDTH = 224
const SIGNALS_ROOM = SIGNALS_WIDTH - 12
const MORE_WIDTH = 24
/** Mean width of a chip's letter (12 px medium), in px. */
const CHAR = 6.6

/** The words of a row's exploitation signals, strongest first. */
export function signalWords(item: VulnListItem, t: Translate): string[] {
  const words: string[] = []
  if (item.kev) words.push(t('vulnPage.list.chip.kev', 'Known exploited'))
  if (item.emerging) words.push(t('vulnPage.list.signal.emerging', 'Emerging threat'))
  if (item.exploit) words.push(exploitWord(item, t))
  if (item.past_sla > 0) {
    words.push(t('vulnPage.list.signal.pastSla', '{count} past SLA', { count: item.past_sla }))
  }
  return words
}

function exploitWord(item: VulnListItem, t: Translate): string {
  const maturity = item.exploit_maturity
  return maturity === 'weaponized'
    ? t('vulnPage.list.signal.weaponized', 'Weaponized')
    : maturity === 'functional'
      ? t('vulnPage.list.signal.functional', 'Working exploit')
      : maturity === 'poc'
        ? t('vulnPage.list.signal.poc', 'Proof of concept')
        : t('vulnPage.list.signal.exploit', 'Public exploit')
}

/** The title, then the first aliases, on one line; the whole of both in the tooltip. */
export function VulnTitleCell({ item }: { item: VulnListItem }) {
  const { t } = useTranslation()
  const title = item.title && item.title !== item.cve_id ? toDisplayText(item.title, 200) : ''
  const aliases = item.aliases.slice(0, 2).join(', ')
  const more = item.aliases.length > 2 ? ` +${item.aliases.length - 2}` : ''
  const full = [title, item.aliases.join(', ')].filter(Boolean).join('\n')
  return (
    <div
      className="@container flex min-w-0 items-baseline gap-2 whitespace-nowrap"
      title={full || undefined}
    >
      {title ? (
        <span className="min-w-0 truncate">{title}</span>
      ) : !item.in_catalog ? (
        <span className="min-w-0 truncate text-muted-foreground">
          {t('vulnPage.list.notInCatalog', 'Not in the catalog yet')}
        </span>
      ) : aliases ? null : (
        <span className="text-muted-foreground">—</span>
      )}
      {aliases && (
        // Beside the title only where the cell has room for both.
        <span
          className={cn(
            'max-w-[40%] shrink-0 truncate font-mono text-xs text-muted-foreground',
            title && 'hidden @[15rem]:inline'
          )}
        >
          {aliases}
          {more}
        </span>
      )}
    </div>
  )
}

/**
 * KEV (with due state), emerging threat, public exploit, past SLA: text
 * chips on one line. KEV and an emerging threat always show; the rest show
 * while they fit and are counted otherwise, with their words in the tooltip.
 */
export function SignalsCell({ item }: { item: VulnListItem }) {
  const { t } = useTranslation()
  const days = kevDueDays(item.kev_due_date)
  const pastDue = days !== undefined && days < 0
  const words = signalWords(item, t)
  if (words.length === 0) {
    return (
      <span className="whitespace-nowrap text-muted-foreground">
        {t('vulnPage.list.signal.none', 'No signal')}
      </span>
    )
  }
  // What fits the column on one line, estimated from the words themselves
  // (the column is fixed, so nothing is measured). Known exploited and an
  // emerging threat always show (they lead the line, in that order); the
  // next ones show while there is room, the rest are counted. When the lead
  // chips do not fit with the count, the KEV chip gives up its qualifiers
  // ("Ransomware" first, then "Past due"), which are counted instead.
  const ransomwareWord = t('findings.list.kevRansomware', 'Ransomware')
  const pastDueWord = t('findings.list.kevPastDue', 'Past due')
  const qualifier = (word: string) => 14 + word.length * CHAR
  let ransomware = !!(item.kev && item.kev_ransomware)
  let showPastDue = pastDue
  const kevWidth = () =>
    56 + (ransomware ? qualifier(ransomwareWord) : 0) + (showPastDue ? qualifier(pastDueWord) : 0)
  const width = (i: number) => (item.kev && i === 0 ? kevWidth() : 30 + words[i].length * CHAR)
  const dropped = () => [
    ...(item.kev && item.kev_ransomware && !ransomware ? [ransomwareWord] : []),
    ...(item.kev && pastDue && !showPastDue ? [pastDueWord] : []),
  ]
  const lead = item.kev && item.emerging ? 2 : 1
  const leadWidth = () => width(0) + (lead === 2 ? width(1) + 4 : 0)
  const counted = (shown: number) => words.length - shown + dropped().length
  while (
    (ransomware || showPastDue) &&
    leadWidth() + (counted(lead) > 0 ? MORE_WIDTH : 0) > SIGNALS_ROOM
  ) {
    if (ransomware) ransomware = false
    else showPastDue = false
  }
  let used = leadWidth()
  let shown = lead
  while (shown < words.length) {
    const next = width(shown) + 4
    if (used + next + (counted(shown + 1) > 0 ? MORE_WIDTH : 0) > SIGNALS_ROOM) break
    used += next
    shown += 1
  }
  const chips = []
  if (item.kev) {
    chips.push(
      <KevBadge
        key="kev"
        className="whitespace-nowrap"
        ransomware={ransomware}
        pastDue={showPastDue}
      />
    )
  }
  if (item.emerging) {
    chips.push(
      <SignalChip key="em" icon={Flame} tone="alert" className="whitespace-nowrap">
        <Link
          href={`/emerging-threats/${encodeURIComponent(item.emerging.id)}`}
          onClick={(e) => e.stopPropagation()}
          className="hover:underline"
        >
          {t('vulnPage.list.signal.emerging', 'Emerging threat')}
        </Link>
      </SignalChip>
    )
  }
  if (item.exploit) {
    chips.push(
      <SignalChip key="ex" icon={Bug} className="whitespace-nowrap">
        {exploitWord(item, t)}
      </SignalChip>
    )
  }
  if (item.past_sla > 0) {
    chips.push(
      <SignalChip key="sla" icon={Clock} tone="alert" alertText className="whitespace-nowrap">
        {t('vulnPage.list.signal.pastSla', '{count} past SLA', { count: item.past_sla })}
      </SignalChip>
    )
  }
  const hiddenWords = [...dropped(), ...words.slice(shown)]
  return (
    <div className="flex min-w-0 items-center gap-1 overflow-hidden whitespace-nowrap">
      {chips.slice(0, shown)}
      {hiddenWords.length > 0 && (
        <span
          className="shrink-0 text-xs tabular-nums text-muted-foreground"
          title={hiddenWords.join(', ')}
          aria-label={t('vulnPage.list.signal.more', 'and {signals}', {
            signals: hiddenWords.join(', '),
          })}
        >
          +{hiddenWords.length}
        </span>
      )}
    </div>
  )
}

export function SeverityCell({ item }: { item: VulnListItem }) {
  return (
    <span className="flex items-center gap-2 whitespace-nowrap">
      <SeverityBadge severity={item.severity} />
      {item.cvss_score != null && (
        <span className="text-muted-foreground tabular-nums">{item.cvss_score.toFixed(1)}</span>
      )}
    </span>
  )
}

/** The score, then the 30-day line beside it. */
export function EpssCell({ item }: { item: VulnListItem }) {
  const { t } = useTranslation()
  return (
    <span className="inline-flex items-center justify-end gap-2 whitespace-nowrap">
      <EpssSparkline points={item.epss_trend} />
      <span
        className="tabular-nums"
        title={
          item.epss_percentile != null
            ? t('vulnPage.list.epssPercentile', 'Higher than {pct} of all CVEs', {
                pct: formatEpssScore(item.epss_percentile, 0),
              })
            : undefined
        }
      >
        {formatEpssScore(item.epss_score, 1, '—')}
      </span>
    </span>
  )
}

export function KevDueText({ due }: { due?: string }) {
  const { t } = useTranslation()
  const days = kevDueDays(due)
  if (days === undefined) return <span className="text-muted-foreground">—</span>
  return (
    <span className={cn('whitespace-nowrap', days < 0 && 'text-destructive')}>
      {days < 0
        ? t('vulnPage.list.kevPastDue', '{days, plural, one {# day} other {# days}} past due', {
            days: -days,
          })
        : t('vulnPage.list.kevDueIn', 'Due in {days, plural, one {# day} other {# days}}', {
            days,
          })}
    </span>
  )
}

/** The count (a link to the findings by asset), then how many face the internet (globe mark). */
export function AssetsCell({ item, params }: { item: VulnListItem; params: URLSearchParams }) {
  const { t } = useTranslation()
  const internet = t('vulnPage.list.internet', '{count} internet-facing', {
    count: item.internet_facing_assets,
  })
  return (
    <span className="flex min-w-0 items-baseline gap-2 whitespace-nowrap">
      <Link
        href={safeHref(rowFindingsHref(item.cve_id, params, { group: 'asset_id' })) ?? '/findings'}
        onClick={(e) => e.stopPropagation()}
        className="font-medium tabular-nums hover:underline"
        aria-label={t(
          'vulnPage.list.assetsAria',
          '{count, plural, one {# asset} other {# assets}}: open the findings by asset',
          { count: item.assets }
        )}
      >
        {formatNumber(item.assets)}
      </Link>
      {item.internet_facing_assets > 0 && (
        <span
          className="inline-flex items-center gap-1 text-xs tabular-nums text-muted-foreground"
          title={internet}
        >
          <Globe className="size-3.5 shrink-0" aria-hidden />
          <span aria-hidden>{formatNumber(item.internet_facing_assets)}</span>
          <span className="sr-only">{internet}</span>
        </span>
      )}
    </span>
  )
}

/** The first product, its first versions, and how many more products. */
export function ProductCell({ item }: { item: VulnListItem }) {
  const { t } = useTranslation()
  const p = item.products[0]
  if (!p) return <span className="text-muted-foreground">—</span>
  const versions = p.versions.slice(0, 2).join(', ')
  const name = toDisplayText(p.name, 80)
  const full = [name, p.versions.join(', ')].filter(Boolean).join('\n')
  return (
    <span className="flex min-w-0 items-baseline gap-2 whitespace-nowrap" title={full}>
      <span className="min-w-0 truncate">{name}</span>
      {versions && (
        <span className="max-w-[45%] shrink-0 truncate font-mono text-xs text-muted-foreground">
          {toDisplayText(versions, 80)}
          {p.versions.length > 2 ? ` +${p.versions.length - 2}` : ''}
        </span>
      )}
      {item.products.length > 1 && (
        <span className="shrink-0 text-xs text-muted-foreground">
          {t('vulnPage.list.moreProducts', '+{count} more', { count: item.products.length - 1 })}
        </span>
      )}
    </span>
  )
}

export function FixCell({ item }: { item: VulnListItem }) {
  const { t } = useTranslation()
  const fix = headlineFixVersion(item)
  if (fix) {
    return (
      <span className="block truncate font-mono" title={item.fixed_versions.join(', ')}>
        {toDisplayText(fix, 40)}
      </span>
    )
  }
  return (
    <span className="whitespace-nowrap text-muted-foreground">
      {item.has_fix
        ? t('vulnPage.list.fixKnown', 'Fix known')
        : t('vulnPage.list.noFix', 'No fix yet')}
    </span>
  )
}

/** Where the open findings stand in remediation tasks: a link to those findings. */
export function remediationText(item: VulnListItem, t: Translate): string {
  const st = remediationState(item)
  return st === 'closed'
    ? t('vulnPage.list.rem.closed', 'All closed')
    : st === 'untracked'
      ? t('vulnPage.list.rem.untracked', 'Not in a task')
      : st === 'tracked'
        ? t('vulnPage.list.rem.tracked', 'In tasks')
        : t('vulnPage.list.rem.partial', '{done} of {total} in tasks', {
            done: item.in_task,
            total: item.open_findings,
          })
}

export function RemediationCell({ item, params }: { item: VulnListItem; params: URLSearchParams }) {
  const { t } = useTranslation()
  const st = remediationState(item)
  return (
    <Link
      href={safeHref(rowFindingsHref(item.cve_id, params, { state: 'open' })) ?? '/findings'}
      onClick={(e) => e.stopPropagation()}
      className={cn(
        'whitespace-nowrap hover:underline',
        st !== 'untracked' && 'text-muted-foreground'
      )}
    >
      {remediationText(item, t)}
    </Link>
  )
}
