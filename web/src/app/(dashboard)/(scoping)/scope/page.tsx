'use client'

/**
 * Scoping › Scope (research/53, RFC-054): what scans may touch.
 *
 * Two lists, In scope (entries) and Out of scope (exclusions, which always
 * win), plus Approvals: every change waiting for a second person. No inline
 * toggles; widening actions say they may need approval and go through
 * step-up. The tab and filters live in the URL.
 */

import { useEffect, useEffectEvent, useState } from 'react'
import Link from 'next/link'
import { Plus, Settings2, ShieldOff } from 'lucide-react'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { MetricStrip, PageHeader, type MetricStripItem } from '@/features/shared'
import { useDebounce } from '@/hooks/use-debounce'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  ScopeEntryDialog,
  useScopeExclusionsApi,
  useScopeSettingsApi,
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
import { EASMDomainProofPanel } from '@/features/attack-surface/components/easm-domain-proof'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'

const TABS = ['in', 'out', 'approvals', 'proof'] as const
type ScopeTab = (typeof TABS)[number]

export default function ScopePage() {
  const canWrite = useHasPermission(Permission.ScopeWrite)
  const canApprove = useHasPermission(Permission.ScopeApprove)
  const { data: settings } = useScopeSettingsApi()
  const membersMayRequest = settings?.one_off_targets === 'admins_and_requests'

  const [tabParam, setTabParam] = useUrlFilter('tab', 'in')
  const { moduleIds } = useTenantModules()
  const proofVisible = moduleIds.includes('attack_surface')
  const tab: ScopeTab =
    (TABS as readonly string[]).includes(tabParam) && (tabParam !== 'proof' || proofVisible)
      ? (tabParam as ScopeTab)
      : 'in'

  const [q, setQ] = useUrlFilter('q', '')
  const [kind, setKind] = useUrlFilter('kind', 'all')
  const [status, setStatus] = useUrlFilter('status', 'all')
  const list = useListParams({ pageSizes: SCOPE_PAGE_SIZES, defaultPageSize: 20 })
  const { page, perPage, setPage } = list
  const [searchInput, setSearchInput] = useState(q)
  const debounced = useDebounce(searchInput, 300)
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

  // Counts for the tabs and the strip (one row each; the lists load their own).
  const { data: activeEntries } = useScopeTargetsApi({ status: 'active', per_page: 1 })
  const { data: inEntries } = useScopeTargetsApi({ status: 'active,expired,inactive', per_page: 1 })
  const { data: outRows } = useScopeExclusionsApi({
    status: 'active,inactive,expired',
    per_page: 1,
  })
  const { data: activeOut } = useScopeExclusionsApi({ status: 'active', per_page: 1 })
  const { total: pending } = usePendingScopeChanges()

  const metrics: MetricStripItem[] = [
    {
      key: 'in',
      label: 'In scope',
      value: activeEntries?.total ?? 0,
      hint: 'entries in effect',
      onClick: () => selectTab('in'),
      active: tab === 'in',
    },
    {
      key: 'out',
      label: 'Out of scope',
      value: activeOut?.total ?? 0,
      hint: 'exclusions in effect',
      onClick: () => selectTab('out'),
      active: tab === 'out',
    },
    {
      key: 'approvals',
      label: 'Waiting for approval',
      value: pending,
      tone: pending > 0 ? 'warning' : 'default',
      hint: pending > 0 ? 'authorize nothing until approved' : undefined,
      onClick: () => selectTab('approvals'),
      active: tab === 'approvals',
    },
  ]

  const addLabel = canApprove ? 'Add to scope' : 'Request access'
  const primary =
    tab === 'out'
      ? canWrite && (
          <Button size="sm" onClick={() => setExcludeOpen(true)}>
            <ShieldOff className="h-4 w-4" />
            Put out of scope
          </Button>
        )
      : tab === 'proof'
        ? null
        : canWrite &&
          (canApprove || membersMayRequest) && (
            <Button size="sm" onClick={() => setAddOpen(true)}>
              <Plus className="h-4 w-4" />
              {addLabel}
            </Button>
          )

  const query = { search: q, kind, status, page, perPage }

  return (
    <Main>
      <PageHeader
        title="Scope"
        description="What scans may touch. Anything not listed is out of scope, and an exclusion always wins."
      >
        <Button asChild variant="outline" size="sm">
          <Link href="/settings/scope">
            <Settings2 className="h-4 w-4" />
            Policy
          </Link>
        </Button>
        {primary}
      </PageHeader>

      <MetricStrip className="mt-5" items={metrics} />

      <Tabs value={tab} onValueChange={selectTab} className="mt-5">
        <div className="no-scrollbar -mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
          <TabsList>
            <TabsTrigger value="in">
              In scope <TabsCount value={inEntries?.total ?? '…'} />
            </TabsTrigger>
            <TabsTrigger value="out">
              Out of scope <TabsCount value={outRows?.total ?? '…'} />
            </TabsTrigger>
            <TabsTrigger value="approvals">
              Approvals <TabsCount value={pending} />
            </TabsTrigger>
            {proofVisible && <TabsTrigger value="proof">Domain proof</TabsTrigger>}
          </TabsList>
        </div>

        <TabsContent value="in" className="mt-5">
          <ScopeEntriesTable
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
                canAdd={canWrite && (canApprove || membersMayRequest)}
                onAdd={() => setAddOpen(true)}
              />
            }
          />
        </TabsContent>
        <TabsContent value="out" className="mt-5">
          <ScopeExclusionsTable
            query={query}
            searchInput={searchInput}
            onSearchInput={setSearchInput}
            onKindChange={(v) => {
              setKind(v)
              setPage(1)
            }}
            onPagination={onPagination}
          />
        </TabsContent>
        <TabsContent value="approvals" className="mt-5">
          <ScopeApprovals />
        </TabsContent>
        {proofVisible && (
          <TabsContent value="proof" className="mt-5">
            <EASMDomainProofPanel />
          </TabsContent>
        )}
      </Tabs>

      <ScopeEntryDialog open={addOpen} onOpenChange={setAddOpen} />
      <ScopeExclusionDialog open={excludeOpen} onOpenChange={setExcludeOpen} />
    </Main>
  )
}
