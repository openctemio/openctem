'use client'

import { useMemo, useState } from 'react'
import { Download } from 'lucide-react'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  AddFilterPanel,
  FacetOption,
  FacetPanel,
  FacetSection,
  FilterChipsRow,
  FilterSelect,
  FilterSheet,
  PageHeader,
  PageStack,
} from '@/features/shared'
import { ListCount, ListToolbarTitle } from '@/features/shared/components/list-title-row'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { useTranslation } from '@/context/i18n-provider'
import { useCsvExport, type ExportFieldConfig } from '@/hooks/use-csv-export'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useListParams } from '@/hooks/use-list-params'
import {
  useAdminAuditLogs,
  type AuditOutcome,
} from '@console/features/admin-console/api/use-admin-audit'
import { AdminActivityTable } from '@console/features/admin-console/components/admin-activity-table'
import {
  AuditKindLens,
  auditKind,
} from '@console/features/admin-console/components/audit-kind-lens'
import {
  AdminAuditChainBadge,
  AdminAuditChainStatus,
} from '@console/features/admin-console/components/admin-audit-chain-status'
import { AdminAuditDetailSheet } from '@console/features/admin-console/components/admin-audit-detail-sheet'
import { dayBound } from '@console/features/admin-console/lib/audit-range'
import type { AdminAuditEntry } from '@console/features/admin-console/types'

const exportFields = (
  t: ReturnType<typeof useTranslation>['t']
): ExportFieldConfig<AdminAuditEntry>[] => [
  { header: t('admin.securityActivityPage.when', 'When'), accessor: (e) => e.created_at },
  {
    header: t('admin.securityActivityPage.administrator', 'Administrator'),
    accessor: (e) => e.admin_email,
  },
  { header: t('admin.securityActivityPage.action', 'Action'), accessor: (e) => e.action },
  {
    header: t('admin.securityActivityPage.resourceType', 'Resource type'),
    accessor: (e) => e.resource_type ?? '',
  },
  {
    header: t('admin.securityActivityPage.resourceId', 'Resource ID'),
    accessor: (e) => e.resource_id ?? '',
  },
  {
    header: t('admin.securityActivityPage.result', 'Result'),
    accessor: (e) => (e.success ? 'succeeded' : 'failed'),
  },
  {
    header: t('admin.securityActivityPage.httpStatus', 'HTTP status'),
    accessor: (e) => e.response_status ?? '',
  },
  {
    header: t('admin.securityActivityPage.ipAddress', 'IP address'),
    accessor: (e) => e.ip_address ?? '',
  },
]

export default function AdminActivityPage() {
  const { t } = useTranslation()
  // The list lives in the URL (one list convention): page and its filters, so
  // the overview can link straight to "break-glass sign-ins" or "failures".
  const list = useListParams({
    filters: { kind: '', action: '', admin_email: '', outcome: '', from: '', to: '' },
  })
  // Changes by default: page views and write-ahead rows stay in the chain,
  // one click away under "All events".
  const kind = auditKind(list.filters.kind)
  const { page, setPage } = list
  const action = list.filters.action
  const adminEmail = list.filters.admin_email
  const outcome: AuditOutcome =
    list.filters.outcome === 'success' || list.filters.outcome === 'failure'
      ? list.filters.outcome
      : ''
  const dAction = useSearchQuery(action).term
  const dEmail = useSearchQuery(adminEmail).term
  const { data, error, isLoading, isValidating, mutate } = useAdminAuditLogs({
    page,
    action: dAction,
    adminEmail: dEmail,
    outcome,
    kind,
    from: dayBound(list.filters.from, false),
    to: dayBound(list.filters.to, true),
  })
  const [openId, setOpenId] = useState<string | null>(null)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  const entries = useMemo(() => data?.data ?? [], [data])
  const { handleExport } = useCsvExport(entries, exportFields(t), 'admin-activity')
  const total = data?.total ?? 0
  // The kind lens is a view, not a filter: Clear filters keeps it.
  const filtered = Boolean(action || adminEmail || outcome || list.filters.from || list.filters.to)
  const clearFilters = () => {
    for (const k of ['action', 'admin_email', 'outcome', 'from', 'to'] as const)
      list.setFilter(k, '')
  }

  // Action, administrator and the two dates live behind Add filter and show
  // as chips; the kind lens and Result are the toolbar's own selects.
  const chipFields = [
    {
      key: 'action',
      field: t('admin.securityActivityPage.action', 'Action'),
      value: action,
    },
    {
      key: 'admin_email',
      field: t('admin.securityActivityPage.administrator', 'Administrator'),
      value: adminEmail,
    },
    { key: 'from', field: t('admin.activity.fromShort', 'From'), value: list.filters.from },
    { key: 'to', field: t('admin.activity.toShort', 'To'), value: list.filters.to },
  ] as const
  const chips = chipFields.filter((c) => c.value)
  const clearChipFilters = () => {
    for (const c of chipFields) list.setFilter(c.key, '')
  }
  const chipsRow =
    chips.length > 0 ? (
      <FilterChipsRow
        data-testid="activity-filter-chips"
        label={t('common.filterChips.label', 'Active filters')}
        chips={chips.map((c) => {
          const text = t('admin.activity.chip', '{field}: {value}', {
            field: c.field,
            value: c.value,
          })
          return (
            <RemovableFilterChip
              key={c.key}
              text={text}
              onRemove={() => list.setFilter(c.key, '')}
              removeLabel={t('admin.activity.removeFilter', 'Remove filter {filter}', {
                filter: text,
              })}
            />
          )
        })}
        onClearAll={chips.length > 1 ? clearChipFilters : undefined}
      />
    ) : undefined

  const outcomeOptions = [
    { value: 'success', label: t('admin.activity.outcomeSuccess', 'Succeeded') },
    { value: 'failure', label: t('admin.activity.outcomeFailure', 'Refused or failed') },
  ] as const

  // `withResult`: the phone sheet also holds Result (a toolbar select from
  // 768), so every filter is in one place there.
  const facetPanel = (withResult: boolean) => (
    <FacetPanel
      activeCount={chips.length + (withResult && outcome ? 1 : 0)}
      onClearAll={withResult ? clearFilters : clearChipFilters}
    >
      {withResult && (
        <FacetSection
          title={t('admin.securityActivityPage.result', 'Result')}
          selectedCount={outcome ? 1 : 0}
        >
          {outcomeOptions.map((o) => (
            <FacetOption
              key={o.value}
              label={o.label}
              checked={outcome === o.value}
              onCheckedChange={(on) => list.setFilter('outcome', on ? o.value : '')}
            />
          ))}
        </FacetSection>
      )}
      <FacetSection
        title={t('admin.securityActivityPage.action', 'Action')}
        selectedCount={action ? 1 : 0}
      >
        <div className="pe-1 pt-1">
          <Input
            placeholder={t('admin.activity.actionFilter', 'Search actions')}
            value={action}
            onChange={(e) => list.setFilter('action', e.target.value)}
            aria-label={t('admin.activity.actionFilterLabel', 'Filter by action')}
          />
        </div>
      </FacetSection>
      <FacetSection
        title={t('admin.securityActivityPage.administrator', 'Administrator')}
        selectedCount={adminEmail ? 1 : 0}
      >
        <div className="pe-1 pt-1">
          <Input
            placeholder={t('admin.activity.adminFilter', 'Administrator email')}
            value={adminEmail}
            onChange={(e) => list.setFilter('admin_email', e.target.value)}
            aria-label={t('admin.activity.adminFilterLabel', 'Filter by administrator')}
          />
        </div>
      </FacetSection>
      <FacetSection
        title={t('admin.activity.dateRange', 'Date')}
        selectedCount={(list.filters.from ? 1 : 0) + (list.filters.to ? 1 : 0)}
      >
        <div className="grid gap-2 pe-1 pt-1">
          <Input
            type="date"
            value={list.filters.from}
            onChange={(e) => list.setFilter('from', e.target.value)}
            aria-label={t('admin.activity.from', 'From date')}
          />
          <Input
            type="date"
            value={list.filters.to}
            onChange={(e) => list.setFilter('to', e.target.value)}
            aria-label={t('admin.activity.to', 'To date')}
          />
        </div>
      </FacetSection>
    </FacetPanel>
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.nav.activity', 'Admin activity')}
          description={t(
            'admin.activity.description',
            'Every action taken by platform administrators, including sign-ins and refused attempts.'
          )}
        >
          {/* Whether the log verifies: one line in the header, never a row of
              its own above the list. A broken chain is said in full below. */}
          <AdminAuditChainBadge />
        </PageHeader>
        <AdminAuditChainStatus />
        <AdminActivityTable
          // The view name and count lead the toolbar row; the filters (on a
          // phone, the Filters button), Export and Display share its line.
          toolbarTitle={
            <ListToolbarTitle
              title={
                kind === 'all'
                  ? t('admin.activity.kindAll', 'All events')
                  : t('admin.activity.kindChanges', 'Changes')
              }
              count={
                <ListCount
                  total={total}
                  loading={!data && !error}
                  label={t(
                    'admin.activity.total',
                    '{count, plural, one {# event} other {# events}}',
                    { count: total }
                  )}
                />
              }
            />
          }
          // The list's own action: export the rows on this page. Labelled like
          // Display: an icon below a 64rem toolbar or while it folds.
          toolbarEnd={
            <Button
              variant="outline"
              size="sm"
              iconOnlyBelow="@5xl/toolbar"
              onClick={handleExport}
              disabled={entries.length === 0}
              aria-label={t('admin.activity.export', 'Export this page (CSV)')}
            >
              <Download aria-hidden />
              <span className="sr-only @5xl/toolbar:not-sr-only group-data-[fold=true]/toolbar:sr-only">
                {t('admin.activity.export', 'Export this page (CSV)')}
              </span>
            </Button>
          }
          entries={entries}
          caption={t('admin.nav.activity', 'Admin activity')}
          isLoading={isLoading && !data}
          isRefreshing={isValidating && !!data}
          error={error}
          onRetry={() => void mutate()}
          isFiltered={filtered}
          onClearFilters={clearFilters}
          onRowClick={(e) => setOpenId(e.id)}
          paging={{
            page,
            pageCount: data?.total_pages ?? 1,
            rowCount: total,
            onPageChange: setPage,
          }}
          // One filter entry per width: Add filter from 768, this button on a
          // phone, where it opens the sheet.
          filterToggle={{
            open: false,
            onToggle: () => setFilterSheetOpen(true),
            onOpenSheet: () => setFilterSheetOpen(true),
            activeCount: chips.length + (outcome ? 1 : 0),
            controlsId: 'admin-activity-filters',
            label: t('admin.activity.filtersLabel', 'Activity filters'),
            sheetOnly: true,
          }}
          toolbarStart={
            <>
              <AddFilterPanel>{facetPanel(false)}</AddFilterPanel>
              <AuditKindLens
                value={kind}
                onChange={(v) => list.setFilter('kind', v === 'all' ? 'all' : '')}
              />
              <FilterSelect
                label={t('admin.activity.outcomeLabel', 'Filter by result')}
                value={outcome}
                foldLabel
                onChange={(v) => list.setFilter('outcome', v)}
                allLabel={t('admin.activity.outcomeAll', 'All results')}
                options={[...outcomeOptions]}
              />
            </>
          }
          // Always mounted (an empty row is hidden): the toolbar would mount
          // again when the first chip appears, closing the Add filter panel
          // while its field is being typed in.
          toolbarBelow={chipsRow ?? <></>}
        />
        <AdminAuditDetailSheet entryId={openId} onClose={() => setOpenId(null)} />
        <FilterSheet
          open={filterSheetOpen}
          onOpenChange={setFilterSheetOpen}
          title={t('admin.activity.filtersLabel', 'Activity filters')}
        >
          {facetPanel(true)}
        </FilterSheet>
      </PageStack>
    </Main>
  )
}
