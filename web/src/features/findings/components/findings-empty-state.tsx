'use client'

import * as React from 'react'
import { ClipboardCheck, FileUp, Inbox, Lock, SearchX, type LucideIcon } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState } from '@/features/shared/components/empty-state'
import type { FindingsEmptyKind } from '../lib/empty-kind'
import { PRACTICE_VIEW_TEXT, practiceLabelKey, type PracticeView } from '../lib/practice'

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
  /** May create a scan (scans:write, the gate of the scan form); hides "Run a scan" otherwise. */
  canRunScan: boolean
  /** May open the integrations settings (integrations:read). */
  canOpenIntegrations: boolean
  onImport: () => void
  onClearFilters: () => void
  /** Offered when the view is not already "All". */
  onSearchAllStates?: () => void
  /** What the refusal says is missing, when the server named it. */
  denial?: string
  /** The chosen practice, for its first run (`practice_nothing`). */
  practice?: PracticeView
}

/**
 * The findings list's empty body: one of four kinds, each with its next
 * action, drawn with the shared EmptyState inside the table's frame. A kind
 * has at most one filled button; the others are outline or ghost.
 */
export function FindingsEmptyState({
  kind,
  hiddenCount,
  stateLabel,
  filterCount,
  hasSearch,
  canImport,
  canRunScan,
  canOpenIntegrations,
  onImport,
  onClearFilters,
  onSearchAllStates,
  denial,
  practice,
}: FindingsEmptyStateProps) {
  const { t } = useTranslation()

  // A practice with nothing yet: what it covers and the one action that brings
  // it in (the sentence stays without the permission to import).
  if (kind === 'practice_nothing' && practice) {
    const compliance = practice === 'compliance'
    const name = t(practiceLabelKey(practice), PRACTICE_VIEW_TEXT[practice].label)
    return (
      <Body
        kind={kind}
        icon={compliance ? ClipboardCheck : Inbox}
        title={
          compliance
            ? t('findings.empty.practiceNothing.complianceTitle', 'No benchmark checks yet')
            : t('findings.empty.practiceNothing.title', 'No {practice} findings yet', {
                practice: name,
              })
        }
        description={
          compliance
            ? t(
                'findings.empty.practiceNothing.complianceHint',
                'Import a scan that runs a compliance audit, and each control appears here with its result.'
              )
            : t(
                'findings.empty.practiceNothing.hint',
                'They appear when a scan or an import brings in findings of this kind.'
              )
        }
      >
        {canImport && (
          <Button onClick={onImport}>
            <FileUp aria-hidden />
            {t('findings.empty.importResults', 'Import results')}
          </Button>
        )}
      </Body>
    )
  }

  // A refused read: what the viewer cannot do, and the one way on.
  if (kind === 'no_access') {
    return (
      <Body
        kind={kind}
        icon={Lock}
        title={t('findings.empty.noAccessTitle', 'You cannot read findings here')}
        description={
          denial ??
          t(
            'findings.empty.noAccessHint',
            'Your role in this organization does not include reading findings. An organization administrator can grant it.'
          )
        }
      >
        <Button variant="outline" asChild>
          <Link href="/">{t('findings.empty.goToDashboard', 'Go to the dashboard')}</Link>
        </Button>
      </Body>
    )
  }

  // First run: the first way to bring findings in that the viewer may use is
  // the filled button.
  if (kind === 'nothing') {
    return (
      <Body
        kind={kind}
        icon={Inbox}
        title={t('findings.empty.nothingTitle', 'No findings yet')}
        description={t(
          'findings.empty.nothingHint',
          'Findings appear when a scan finishes or when you import results from another tool.'
        )}
      >
        {canRunScan && (
          <Button asChild>
            {/* The scans page opens its scan form for `?new=scan` (lib/open-form.ts). */}
            <Link href="/scans?new=scan">{t('findings.empty.runScan', 'Run a scan')}</Link>
          </Button>
        )}
        {canImport && (
          <Button variant={canRunScan ? 'outline' : 'default'} onClick={onImport}>
            <FileUp aria-hidden />
            {t('findings.empty.importResults', 'Import results')}
          </Button>
        )}
        {canOpenIntegrations && (
          <Button variant="ghost" asChild>
            <Link href="/settings/integrations">
              {t('findings.empty.connectTool', 'Connect a tool')}
            </Link>
          </Button>
        )}
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
  const canClear = filterCount > 0 || hasSearch

  return (
    <Body
      kind="no_match"
      icon={SearchX}
      title={t('findings.empty.noMatchTitle', 'No findings match')}
      description={
        typeof hiddenCount === 'number' && hiddenCount > 0 && reasonText
          ? t('findings.empty.hidden', '{count} {state} findings are hidden by {reasons}.', {
              count: hiddenCount.toLocaleString(),
              state: (stateLabel ?? '').toLowerCase(),
              reasons: reasonText,
            })
          : t(
              'findings.empty.noMatchHint',
              'Nothing in this view matches. Widen the view to see more.'
            )
      }
    >
      {canClear && (
        <Button onClick={onClearFilters}>
          {filterCount > 0
            ? t('findings.empty.clearFilters', 'Clear filters')
            : t('findings.empty.clearSearch', 'Clear search')}
        </Button>
      )}
      {onSearchAllStates && (
        <Button variant={canClear ? 'outline' : 'default'} onClick={onSearchAllStates}>
          {t('findings.empty.searchAllStates', 'Search all states')}
        </Button>
      )}
    </Body>
  )
}

/**
 * The shared empty block with this list's actions under it: in a row, and
 * stacked full width on a phone.
 */
function Body({
  kind,
  icon,
  title,
  description,
  children,
}: {
  kind: FindingsEmptyKind
  icon: LucideIcon
  title: string
  description: string
  children?: React.ReactNode
}) {
  const actions = React.Children.toArray(children)
  return (
    <div data-testid="findings-empty-state" data-kind={kind}>
      <EmptyState
        card={false}
        icon={icon}
        title={title}
        description={description}
        action={
          actions.length > 0 ? (
            <div
              data-slot="empty-actions"
              className="flex flex-col items-stretch gap-2 sm:flex-row sm:flex-wrap sm:items-center sm:justify-center"
            >
              {actions}
            </div>
          ) : undefined
        }
      />
    </div>
  )
}
