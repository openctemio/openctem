'use client'

import { FileUp, Inbox, Lock, SearchX } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import type { FindingsEmptyKind } from '../lib/empty-kind'

interface FindingsEmptyStateProps {
  kind: FindingsEmptyKind
  /** Findings in the page's scope that the filters and search hide, when known. */
  hiddenCount?: number
  /** Name of the state being viewed (Open, Fixed...), for the "hidden" sentence. */
  stateLabel?: string
  /** Filters the person applied (chips and facets), not counting search. */
  filterCount: number
  hasSearch: boolean
  canImport: boolean
  /** May open the scans page (scans:read); hides "Set up a scan" otherwise. */
  canSetUpScan: boolean
  /** May open the integrations settings (integrations:read). */
  canOpenIntegrations: boolean
  onImport: () => void
  onClearFilters: () => void
  /** Offered when the view is not already "All". */
  onSearchAllStates?: () => void
  /** What the refusal says is missing, when the server named it. */
  denial?: string
}

/**
 * The findings list's empty body: one of three kinds, each with the next
 * action. Rendered inside the table area so the toolbar and chips stay.
 */
export function FindingsEmptyState({
  kind,
  hiddenCount,
  stateLabel,
  filterCount,
  hasSearch,
  canImport,
  canSetUpScan,
  canOpenIntegrations,
  onImport,
  onClearFilters,
  onSearchAllStates,
  denial,
}: FindingsEmptyStateProps) {
  const { t } = useTranslation()

  if (kind === 'no_access') {
    return (
      <Body icon={<Lock className="h-10 w-10 text-muted-foreground/50" aria-hidden />}>
        <p className="text-sm font-medium">
          {t('findings.empty.noAccessTitle', 'You do not have access to these findings')}
        </p>
        <p className="max-w-md text-xs text-muted-foreground">
          {denial ??
            t(
              'findings.empty.noAccessHint',
              'Ask an organization administrator to grant access to findings.'
            )}
        </p>
      </Body>
    )
  }

  if (kind === 'nothing') {
    return (
      <Body icon={<Inbox className="h-10 w-10 text-muted-foreground/50" aria-hidden />}>
        <p className="text-sm font-medium">
          {t('findings.empty.nothingTitle', 'No findings in this organization yet')}
        </p>
        <p className="max-w-md text-xs text-muted-foreground">
          {t(
            'findings.empty.nothingHint',
            'Findings appear when a scan finishes or when you import results from another tool.'
          )}
        </p>
        <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
          {canImport && (
            <Button size="sm" onClick={onImport}>
              <FileUp className="me-2 h-4 w-4" aria-hidden />
              {t('findings.empty.importResults', 'Import results')}
            </Button>
          )}
          {canSetUpScan && (
            <Button size="sm" variant="outline" asChild>
              <Link href="/scans">{t('findings.empty.setUpScan', 'Set up a scan')}</Link>
            </Button>
          )}
          {canOpenIntegrations && (
            <Button size="sm" variant="ghost" asChild>
              <Link href="/settings/integrations">
                {t('findings.empty.integrations', 'Integrations')}
              </Link>
            </Button>
          )}
        </div>
      </Body>
    )
  }

  const reasons: string[] = []
  if (filterCount > 0) {
    reasons.push(
      t('findings.empty.byFilters', '{count, plural, one {# filter} other {# filters}}', {
        count: filterCount,
      })
    )
  }
  if (hasSearch) reasons.push(t('findings.empty.bySearch', 'your search'))
  const reasonText = reasons.join(` ${t('findings.empty.and', 'and')} `)

  return (
    <Body icon={<SearchX className="h-10 w-10 text-muted-foreground/50" aria-hidden />}>
      <p className="text-sm font-medium">{t('findings.empty.noMatchTitle', 'No findings match')}</p>
      <p className="max-w-md text-xs text-muted-foreground">
        {typeof hiddenCount === 'number' && hiddenCount > 0 && reasonText
          ? t('findings.empty.hidden', '{count} {state} findings are hidden by {reasons}.', {
              count: hiddenCount.toLocaleString(),
              state: (stateLabel ?? '').toLowerCase(),
              reasons: reasonText,
            })
          : t(
              'findings.empty.noMatchHint',
              'Nothing in this view matches. Widen the view to see more.'
            )}
      </p>
      <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
        {(filterCount > 0 || hasSearch) && (
          <Button size="sm" onClick={onClearFilters}>
            {filterCount > 0
              ? t('findings.empty.clearFilters', 'Clear filters')
              : t('findings.empty.clearSearch', 'Clear search')}
          </Button>
        )}
        {onSearchAllStates && (
          <Button size="sm" variant="outline" onClick={onSearchAllStates}>
            {t('findings.empty.searchAllStates', 'Search all statuses')}
          </Button>
        )}
      </div>
    </Body>
  )
}

function Body({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div
      data-testid="findings-empty-state"
      className="flex flex-col items-center justify-center gap-2 py-12 text-center"
    >
      {icon}
      {children}
    </div>
  )
}
