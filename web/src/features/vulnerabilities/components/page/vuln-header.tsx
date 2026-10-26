'use client'

import { Flame, ListChecks, Wrench } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/features/shared/components/page-header'
import { Button } from '@/components/ui/button'
import { DisabledReason } from '@/components/ui/disabled-reason'
import { KevBadge } from '@/components/ui/kev-badge'
import { PriorityBadge } from '@/components/ui/priority-badge'
import { SignalChip } from '@/components/ui/signal-chip'
import { useTranslation } from '@/context/i18n-provider'
import { aliasHref } from '@/features/findings/lib/finding-intel'
import { SafeExternalLink } from '@/components/safe-external-link'
import type { Vulnerability } from '../../types'
import type { CveExposure } from '../../types/exposure'
import { cveFindingsHref } from '../../lib/vuln-page'
import { formatDateOnly } from '@/lib/date-only'

export interface VulnHeaderProps {
  cve: string
  vuln?: Vulnerability
  exposure: CveExposure
  fix?: string
  /** Opens "Create remediation task"; undefined when the caller may not create one. */
  onCreateTask?: () => void
}

/**
 * The page header: title, the CVE and its aliases with provenance, the
 * signal chips (KEV, emerging threat, worst priority, fix available) and the
 * actions. anatomy-ok: inside a PageStack (vulnerability-page.tsx renders it first). Every action works inside the caller's scope.
 */
export function VulnHeader({ cve, vuln, exposure, fix, onCreateTask }: VulnHeaderProps) {
  const { t, locale } = useTranslation()
  const title = vuln?.title && vuln.title !== cve ? vuln.title : undefined
  const { findings, intel } = exposure
  const kev = vuln?.cisa_kev
  const ransomware = kev?.ransomware_use?.toLowerCase() === 'known'
  // Why Create task is off, in the order a reader would ask: nothing in scope,
  // nothing still open, everything already in a task.
  const createTaskBlocker =
    findings.total === 0
      ? t('vulnPage.header.noFindings', 'No finding of this vulnerability in your scope')
      : findings.active === 0
        ? t('vulnPage.header.noActive', 'Every finding of this vulnerability is closed')
        : findings.not_in_task === 0
          ? t('vulnPage.header.allInTasks', 'Every active finding is already in a remediation task')
          : undefined

  return (
    <PageHeader
      title={title ?? cve}
      description={
        <ul
          className="mt-1 flex flex-wrap items-center gap-1.5"
          aria-label={t('vulnPage.header.identifiers', 'Identifiers and signals')}
        >
          <li>
            <Badge
              variant="outline"
              className="font-mono text-xs font-semibold" // label-ok: a CVE id is an identifier
            >
              {cve}
            </Badge>
          </li>
          {intel.aliases.map((a) => {
            const href = aliasHref(a.source === 'ghsa' ? 'ghsa' : 'osv', a.id)
            const provenance = t(
              'vulnPage.header.aliasProvenance',
              'Linked by the signed {source} feed, synced {date}',
              {
                source: a.source.toUpperCase(),
                date: formatDateOnly(a.synced_at, locale, { dateStyle: 'medium' }),
              }
            )
            return (
              <li key={a.id}>
                <Badge
                  variant="outline"
                  className="font-mono text-xs"
                  title={provenance}
                  asChild={!!href}
                >
                  {href ? (
                    <SafeExternalLink href={href} aria-label={`${a.id}, ${provenance}`}>
                      {a.id}
                    </SafeExternalLink>
                  ) : (
                    <span>{a.id}</span>
                  )}
                </Badge>
              </li>
            )
          })}
          {kev && (
            <li>
              <KevBadge ransomware={ransomware} />
            </li>
          )}
          {intel.emerging && (
            <li>
              <SignalChip icon={Flame} tone="alert">
                <Link
                  href={`/emerging-threats/${encodeURIComponent(intel.emerging.id)}`}
                  className="hover:underline"
                >
                  {t('vulnPage.header.emerging', 'Emerging threat')}
                  {': '}
                  {t(`vulnPage.emergingState.${intel.emerging.state}`, intel.emerging.state)}
                </Link>
              </SignalChip>
            </li>
          )}
          {findings.worst_priority && (
            <li>
              <PriorityBadge priorityClass={findings.worst_priority} showWord />
            </li>
          )}
          {fix && (
            <li>
              <SignalChip icon={Wrench}>
                {t('vulnPage.header.fixAvailable', 'Fix available: {version}', { version: fix })}
              </SignalChip>
            </li>
          )}
        </ul>
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        {findings.total > 0 && (
          <Button asChild variant="outline" size="sm">
            <Link href={cveFindingsHref(cve, { state: 'all' })}>
              <ListChecks className="me-1.5 h-4 w-4" aria-hidden />
              {t('vulnPage.header.openFindings', 'Open {count} findings', {
                count: findings.total.toLocaleString(),
              })}
            </Link>
          </Button>
        )}
        {onCreateTask && (
          <DisabledReason reason={createTaskBlocker}>
            <Button size="sm" onClick={onCreateTask} disabled={createTaskBlocker !== undefined}>
              {t('vulnPage.header.createTask', 'Create remediation task')}
            </Button>
          </DisabledReason>
        )}
      </div>
    </PageHeader>
  )
}
