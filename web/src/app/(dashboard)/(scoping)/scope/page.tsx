'use client'

/**
 * Scoping › Scope (research/53, RFC-054): what scans may touch.
 *
 * Two lists, In scope (entries) and Out of scope (exclusions, which always
 * win), each listing every row (pending ones with their pill), plus
 * Approvals: every change waiting for a second person, shown while the
 * organization requires approvals or something still waits. No inline
 * toggles; widening actions say they may need approval and go through
 * step-up. The tab and filters live in the URL.
 */

import { useEffect, useEffectEvent, useState } from 'react'
import Link from '@/components/link'
import { Plus, Settings2, ShieldOff } from 'lucide-react'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import {
  FilterSelect,
  ListToolbar,
  MetricStrip,
  GatedSectionTabs,
  PageHeader,
  PageStack,
  type MetricStripItem,
} from '@/features/shared'
import { SCOPE_SECTION_TABS } from '@/config/section-tabs'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  ScopeEntryDialog,
  useScopeExclusionsApi,
  useScopeAddMode,
  useScopeTargetsApi,
} from '@/features/scope'
import {
  ScopeEntriesTable,
  SCOPE_PAGE_SIZES,
} from '@/features/scope/components/scope-entries-table'
import { ScopeExclusionsTable } from '@/features/scope/components/scope-exclusions-table'
import { ScopeExclusionDialog } from '@/features/scope/components/scope-exclusion-dialog'
import { ScopeApprovals, usePendingScopeChanges } from '@/features/scope/components/scope-approvals'
import { ScopeOnboarding } from '@/features/scope/components/scope-onboarding'
import { useTranslation } from '@/context/i18n-provider'

// Domain proof and Networks are their own pages (route tabs of Scope).
const TABS = ['in', 'out', 'approvals'] as const
type ScopeTab = (typeof TABS)[number]

export default function ScopePage() {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.ScopeWrite)
  // Add applies at once except under Strict scan approval, where a member
  // without scope:approve requests (and only when requests are accepted).
  const { settings, entriesNeedApproval, isRequest, canAdd } = useScopeAddMode()

  const [tabParam, setTabParam] = useUrlFilter('tab', 'in')
  const tabVisible = (name: string) =>
    (TABS as readonly string[]).includes(name) && (name !== 'approvals' || showApprovals)

  const [q, setQ] = useUrlFilter('q', '')
  const [kind, setKind] = useUrlFilter('kind', 'all')
  const [status, setStatus] = useUrlFilter('status', 'all')
  const list = useListParams({ pageSizes: SCOPE_PAGE_SIZES, defaultPageSize: 20 })
  const { page, perPage, setPage } = list
  const [searchInput, setSearchInput] = useState(q)
  const debounced = useSearchQuery(searchInput).term
  const commitSearch = useEffectEvent((next: string) => {
    if (next !== q) {
      setQ(next)
      setPage(1)
    }
  })
  useEffect(() => {
    commitSearch(debounced)
  }, [debounced])

  const [addOpen, setAddOpen] = useState(false)
  const [excludeOpen, setExcludeOpen] = useState(false)

  const selectTab = (next: string) => {
    if (next === tab) return
    setSearchInput('')
    setQ('')
    setKind('all')
    setStatus('all')
    setPage(1)
    setTabParam(next)
  }
  const onPagination = list.setPagination

  // The add dialogs' "Show it" for an existing row: its tab, searched.
  const showExisting = (href: string) => {
    const p = new URL(href, 'http://local').searchParams
    const next = p.get('q') ?? ''
    setSearchInput(next)
    setQ(next)
    setKind('all')
    setStatus(p.get('status') ?? 'all')
    setPage(1)
    setTabParam(p.get('tab') ?? 'in')
  }

  // Counts for the tabs and the strip (one row each; the lists load their own).
  const { data: activeEntries, error: activeEntriesError } = useScopeTargetsApi({
    status: 'active',
    per_page: 1,
  })
  const { data: inEntries } = useScopeTargetsApi({
    status: 'active,pending,expired,inactive',
    per_page: 1,
  })
  const { data: outRows } = useScopeExclusionsApi({
    status: 'active,pending,inactive,expired,rejected',
    per_page: 1,
  })
  const { data: activeOut, error: activeOutError } = useScopeExclusionsApi({
    status: 'active',
    per_page: 1,
  })
  const { total: pending } = usePendingScopeChanges()
  // Without approvals in force and nothing waiting there is nothing to decide.
  const showApprovals = entriesNeedApproval || pending > 0
  const tab: ScopeTab = tabVisible(tabParam) ? (tabParam as ScopeTab) : 'in'

  // The strip counts what is in effect and each metric opens exactly those
  // rows (its tab filtered to status active); the tabs count every row they
  // list, whatever its status.
  const openInEffect = (next: 'in' | 'out') => {
    // Clicking the tile that is already showing its rows clears the filter.
    if (tab === next && status === 'active') {
      setStatus('all')
      setPage(1)
      return
    }
    selectTab(next)
    setStatus('active')
  }
  const metrics: MetricStripItem[] = [
    {
      key: 'in',
      label: t('scope.strip.entriesInEffect', 'Entries in effect'),
      value: activeEntries?.total ?? 0,
      onClick: () => openInEffect('in'),
      active: tab === 'in' && status === 'active',
    },
    {
      key: 'out',
      label: t('scope.strip.exclusionsInEffect', 'Exclusions in effect'),
      value: activeOut?.total ?? 0,
      onClick: () => openInEffect('out'),
      active: tab === 'out' && status === 'active',
    },
    ...(showApprovals
      ? ([
          {
            key: 'approvals',
            label: t('scope.strip.waiting', 'Waiting for approval'),
            value: pending,
            tone: pending > 0 ? 'warning' : 'default',
            hint:
              pending > 0
                ? t('scope.strip.waitingHint', 'authorize nothing until approved')
                : undefined,
            onClick: () => selectTab('approvals'),
            active: tab === 'approvals',
          },
        ] satisfies MetricStripItem[])
      : []),
  ]

  const addLabel = isRequest
    ? t('scope.entry.titleRequest', 'Request access')
    : t('scope.entry.titleAdd', 'Add to scope')
  const primary =
    tab === 'out'
      ? canWrite && (
          <Button size="sm" onClick={() => setExcludeOpen(true)}>
            <ShieldOff className="h-4 w-4" />
            {t('scope.putOut', 'Put out of scope')}
          </Button>
        )
      : canAdd && (
          <Button size="sm" onClick={() => setAddOpen(true)}>
            <Plus className="h-4 w-4" />
            {addLabel}
          </Button>
        )

  const query = { search: q, kind, status, page, perPage }

  // Which list the page shows (entries, exclusions, changes waiting for
  // approval): a token first in the list's toolbar, not a second tab row
  // under the Scope tabs (research/249 R21). Counts are every row each list
  // holds, whatever its status.
  const listSelect = (
    <FilterSelect<ScopeTab>
      label={t('scope.show.label', 'Show')}
      value={tab}
      clearable={false}
      options={[
        { value: 'in', label: t('scope.tabs.entries', 'Entries'), count: inEntries?.total },
        { value: 'out', label: t('scope.tabs.exclusions', 'Exclusions'), count: outRows?.total },
        ...(showApprovals
          ? [
              {
                value: 'approvals' as const,
                label: t('scope.tabs.approvals', 'Approvals'),
                count: pending,
              },
            ]
          : []),
      ]}
      onChange={(v) => selectTab(v || 'in')}
    />
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('scope.title', 'Scope')}
          description={t(
            'scope.description',
            'What scans may touch. Anything not listed is out of scope, and an exclusion always wins.'
          )}
        >
          <Button asChild variant="outline" size="sm">
            <Link href="/settings/scope">
              <Settings2 className="h-4 w-4" />
              {t('scope.policy', 'Policy')}
            </Link>
          </Button>
          {primary}
        </PageHeader>
        <GatedSectionTabs tabs={SCOPE_SECTION_TABS} label={t('scope.sections', 'Scope sections')} />

        <MetricStrip
          loading={(!activeEntries && !activeEntriesError) || (!activeOut && !activeOutError)}
          items={metrics}
        />

        {tab === 'in' ? (
          <ScopeEntriesTable
            leading={listSelect}
            query={query}
            searchInput={searchInput}
            onSearchInput={setSearchInput}
            onKindChange={(v) => {
              setKind(v)
              setPage(1)
            }}
            onStatusChange={(v) => {
              setStatus(v)
              setPage(1)
            }}
            onPagination={onPagination}
            emptyAction={
              <ScopeOnboarding
                activeProof={settings?.active_proof}
                canAdd={canAdd}
                onAdd={() => setAddOpen(true)}
              />
            }
          />
        ) : tab === 'out' ? (
          <ScopeExclusionsTable
            leading={listSelect}
            query={query}
            searchInput={searchInput}
            onSearchInput={setSearchInput}
            onKindChange={(v) => {
              setKind(v)
              setPage(1)
            }}
            onStatusChange={(v) => {
              setStatus(v)
              setPage(1)
            }}
            onPagination={onPagination}
          />
        ) : (
          <>
            <ListToolbar start={listSelect} />
            <ScopeApprovals />
          </>
        )}
      </PageStack>
      <ScopeEntryDialog open={addOpen} onOpenChange={setAddOpen} onShowExisting={showExisting} />
      <ScopeExclusionDialog
        open={excludeOpen}
        onOpenChange={setExcludeOpen}
        onShowExisting={showExisting}
      />
    </Main>
  )
}
