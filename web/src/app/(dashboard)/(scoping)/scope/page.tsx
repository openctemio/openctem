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
import { ScopeEntryDialog, useScopeAddMode } from '@/features/scope'
import {
  ScopeEntriesTable,
  SCOPE_PAGE_SIZES,
} from '@/features/scope/components/scope-entries-table'
import { ScopeExclusionsTable } from '@/features/scope/components/scope-exclusions-table'
import { ScopeExclusionDialog } from '@/features/scope/components/scope-exclusion-dialog'
import { noLongerOursPattern } from '@/features/scope/lib/exclusion-kind'
import { entryStatus } from '@/features/scope/lib/scope-entry'
import {
  setScopeTargetActive,
  sumStatusCounts,
  useScopeStatusCounts,
} from '@/features/scope/api/use-scope-api'
import type { ApiScopeTarget, ScopeExclusionKind } from '@/features/scope/api/scope-api.types'
import { ScopeApprovals } from '@/features/scope/components/scope-approvals'
import { ScopeOnboarding } from '@/features/scope/components/scope-onboarding'
import { ScopeProviderAddressesCard } from '@/features/scope/components/scope-provider-addresses-card'
import { ScopeCheckTool } from '@/features/scope/components/scope-check-tool'
import { useScopeStatsApi } from '@/features/scope/api/use-scope-api'
import { useEASMVerifiedDomains } from '@/features/attack-surface/hooks/use-easm-verified-domains'
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
  const list = useListParams({ pageSizes: SCOPE_PAGE_SIZES })
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
  // "No longer ours" on an entry: the exclusion dialog opens prefilled, and
  // the entry is deactivated once the exclusion is saved (research/320).
  const [excludeInitial, setExcludeInitial] = useState<
    { pattern: string; kind: ScopeExclusionKind } | undefined
  >(undefined)
  const [retireEntry, setRetireEntry] = useState<ApiScopeTarget | null>(null)
  const noLongerOurs = (entry: ApiScopeTarget) => {
    const pattern = noLongerOursPattern(entry)
    if (!pattern) return
    setExcludeInitial({ pattern, kind: 'not_ours' })
    setRetireEntry(entry)
    setExcludeOpen(true)
  }
  const openExclude = (open: boolean) => {
    setExcludeOpen(open)
    if (!open) {
      setExcludeInitial(undefined)
      setRetireEntry(null)
    }
  }

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

  // Counts for the tabs, the strip and the approvals: two requests (entries,
  // exclusions), each counting every status; the lists load their own rows.
  // While the entries list is shown it carries the entry counts itself.
  const [listCounts, setListCounts] = useState<Record<string, number> | undefined>(undefined)
  // The exclusion counts only show in the Show menu (and the approvals
  // badge): read them when the menu opens or another list is shown.
  const [menuOpened, setMenuOpened] = useState(false)
  const counts = useScopeStatusCounts(tabParam === 'in', tabParam !== 'in' || menuOpened)
  const entryCounts = counts.targets ?? listCounts
  const inEntries = entryCounts
    ? sumStatusCounts(entryCounts, ['active', 'pending', 'expired', 'inactive'])
    : undefined
  const outRows = counts.exclusions
    ? sumStatusCounts(counts.exclusions, ['active', 'pending', 'inactive', 'expired', 'rejected'])
    : undefined
  const pending = (entryCounts?.pending ?? 0) + (counts.exclusions?.pending ?? 0)
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
  // The summary counts known targets (the internet-facing inventory the
  // caller may see, GET /scope/stats): in scope, excluded, found but covered
  // by no entry; and the domains still waiting for their DNS proof. A count
  // the server does not send yet reads "Not measured", never a guess.
  const stats = useScopeStatsApi()
  const inventory = stats.data as
    | (typeof stats.data & { inventory_excluded?: number; inventory_not_covered?: number })
    | undefined
  const proofs = useEASMVerifiedDomains()
  const pendingProof = proofs.domains.filter((d) => d.status !== 'verified').length
  const counted = (n: number | undefined) => ({
    value:
      typeof n === 'number' || stats.isLoading
        ? (n ?? '')
        : t('scope.strip.notMeasured', 'Not measured'),
  })
  const metrics: MetricStripItem[] = [
    {
      key: 'in',
      label: t('scope.strip.inScope', 'In scope'),
      ...counted(inventory?.inventory_in_scope),
      description: t(
        'scope.strip.inScopeHint',
        'Known internet-facing targets an entry in effect covers. Opens the entries in effect.'
      ),
      onClick: () => openInEffect('in'),
      active: tab === 'in' && status === 'active',
    },
    {
      key: 'out',
      label: t('scope.strip.excluded', 'Excluded'),
      ...counted(inventory?.inventory_excluded),
      description: t(
        'scope.strip.excludedHint',
        'Known internet-facing targets an exclusion in effect removes. Opens the exclusions in effect.'
      ),
      onClick: () => openInEffect('out'),
      active: tab === 'out' && status === 'active',
    },
    ...(proofs.enabled
      ? ([
          {
            key: 'proof',
            label: t('scope.strip.pendingProof', 'Pending proof'),
            value: proofs.isLoading ? '' : pendingProof,
            tone: pendingProof > 0 ? 'warning' : 'default',
            description: t(
              'scope.strip.pendingProofHint',
              'Domains waiting for their DNS TXT record to be found.'
            ),
            href: '/scope/domain-proof',
          },
        ] satisfies MetricStripItem[])
      : []),
    {
      key: 'unknown',
      label: t('scope.strip.foundUnknown', 'Found but unknown'),
      ...counted(inventory?.inventory_not_covered),
      description: t(
        'scope.strip.foundUnknownHint',
        'Internet-facing targets discovery found that no entry covers and no exclusion removes.'
      ),
      href: '/assets?scope_status=not_covered',
    },
  ]

  const addLabel = isRequest
    ? t('scope.entry.titleRequest', 'Request access')
    : t('scope.entry.titleAdd', 'Add to scope')
  const primary =
    tab === 'out'
      ? canWrite && (
          <Button size="sm" onClick={() => openExclude(true)}>
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
      foldLabel
      onOpenChange={(open) => open && setMenuOpened(true)}
      options={[
        { value: 'in', label: t('scope.tabs.entries', 'Entries'), count: inEntries },
        { value: 'out', label: t('scope.tabs.exclusions', 'Exclusions'), count: outRows },
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
          // A list page: on a phone the list comes first (as on Certificates).
          description={
            <span className="max-md:hidden">
              {t(
                'scope.description',
                'What scans may touch at full intensity. Assets no entry covers get what Scan unclassified assets allows, and an exclusion always wins.'
              )}
            </span>
          }
        >
          <Button asChild variant="outline" size="sm">
            <Link href="/settings/scope">
              <Settings2 className="h-4 w-4" />
              {t('scope.policy', 'Policy')}
            </Link>
          </Button>
          <ScopeCheckTool />
          {primary}
        </PageHeader>
        <GatedSectionTabs tabs={SCOPE_SECTION_TABS} label={t('scope.sections', 'Scope sections')} />

        <MetricStrip
          loading={stats.isLoading}
          error={
            stats.error ? t('scope.strip.failed', 'Could not read the scope summary.') : undefined
          }
          items={metrics}
        />

        {/* Scope entries on provider shared addresses: only while there is
            something to decide. */}
        {tab === 'in' && <ScopeProviderAddressesCard enabled={(inEntries ?? 0) > 0} />}

        {tab === 'in' ? (
          <ScopeEntriesTable
            leading={listSelect}
            onNoLongerOurs={noLongerOurs}
            onStatusCounts={setListCounts}
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
        onOpenChange={openExclude}
        onShowExisting={showExisting}
        initial={excludeInitial}
        onCreated={() => {
          // Deactivating narrows scope: no step-up, no approval.
          if (retireEntry?.id && entryStatus(retireEntry) === 'active')
            void setScopeTargetActive(retireEntry.id, false).catch(() => undefined)
        }}
      />
    </Main>
  )
}
