'use client'

/**
 * External attack surface: every internet-facing (exposure = public) asset,
 * served page by page by the assets API.
 *
 * Every number on this page comes from the server (RFC-036 E8). Before, the
 * page loaded the first 100 assets of scope "external" (a scope nothing sets
 * automatically), computed its cards from that page, showed "Expiring certs"
 * from a field the API never returns (always 0) and a hard-coded "94%"
 * coverage card.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Download, Eye, Pencil, Plus, RefreshCw, Search as SearchIcon, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { Main } from '@/components/layout'
import {
  DataTable,
  DataTableRowActions,
  ErrorState,
  MetricStrip,
  PageHeader,
  RelativeTime,
  RiskScoreBadge,
  StackedCell,
  type MetricStripItem,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { deleteAssetSafely } from '@/features/assets/lib/safe-delete'
import { AssetDeleteDialogShared } from '@/features/assets/components/asset-delete-dialog-shared'
import {
  createAsset,
  updateAsset,
  useAssets,
  type Asset,
  type AssetSearchFilters,
  type CreateAssetInput,
} from '@/features/assets'
import { fetchAllAssets } from '@/features/assets/hooks/use-assets'
import { ipAddresses } from '@/features/assets/lib/service-facts'
import { propertyValue } from '@/features/asset-types/lib/property-schema'
import type { AssetMetadata } from '@/features/assets/types'
import { toastIfDuplicateAsset } from '@/features/assets/lib/duplicate-asset'
import { IssuesChip, LabelChips, SurfaceFacts } from '@/features/assets/components/service-cells'
import { useExposures } from '@/features/exposures/hooks'
import { ScanAssetsDialog, type ScanCandidate } from '@/features/scans/components'
import { useTenant } from '@/context/tenant-provider'
import { useRiskThresholds } from '@/context/risk-scoring-provider'
import { useDebounce } from '@/hooks/use-debounce'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { exportToCsv } from '@/hooks/use-csv-export'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, Permission, usePermissions } from '@/lib/permissions'
import type { RiskLevelThresholds } from '@/features/shared/types'
import {
  externalSurfaceFilters,
  riskRange,
  type RiskBand,
} from '@/features/attack-surface/lib/external-filters'

const PAGE_SIZES = [20, 50, 100]

const TYPE_OPTIONS: { value: string; label: string }[] = [
  { value: 'domain', label: 'Domain' },
  { value: 'subdomain', label: 'Subdomain' },
  { value: 'ip_address', label: 'IP address' },
  { value: 'service', label: 'Service' },
  { value: 'application', label: 'Application' },
  { value: 'certificate', label: 'Certificate' },
  { value: 'host', label: 'Host' },
]

const RISK_OPTIONS: { value: RiskBand; label: string }[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
]

const CREATE_TYPES = ['domain', 'subdomain', 'ip_address', 'service', 'certificate'] as const

function sentence(s?: string): string {
  if (!s) return ''
  const t = s.replace(/_/g, ' ')
  return t.charAt(0).toUpperCase() + t.slice(1)
}

/**
 * The asset's first known IP, read through service-facts. It used to read
 * `metadata.ip_address` as a string, but ingest stores a map under that key
 * for IP assets, which rendered an object into the table.
 */
function ipOf(a: Asset): string | undefined {
  return ipAddresses(a)[0]
}

interface FormState {
  name: string
  type: (typeof CREATE_TYPES)[number]
  parentDomain: string
  ipAddress: string
  port: string
  notes: string
}

const EMPTY_FORM: FormState = {
  name: '',
  type: 'subdomain',
  parentDomain: '',
  ipAddress: '',
  port: '',
  notes: '',
}

/** A count from the assets API: one row is fetched, only `total` is used. */
function useAssetCount(filters: AssetSearchFilters) {
  const { total, isLoading } = useAssets({ ...filters, page: 1, pageSize: 1 })
  return { total, isLoading }
}

export default function ExternalSurfacePage() {
  const router = useRouter()
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const thresholds: RiskLevelThresholds = useRiskThresholds()

  const [qParam, setQParam] = useUrlFilter('q', '')
  const [typeParam, setTypeParam] = useUrlFilter('type', 'all')
  const [riskParam, setRiskParam] = useUrlFilter('risk', 'all')
  const [findingsParam, setFindingsParam] = useUrlFilter('findings', 'all')
  const list = useListParams({ pageSizes: PAGE_SIZES, defaultPageSize: 20 })
  const { pagination, setPagination, setPage } = list

  const [searchInput, setSearchInput] = useState(qParam)
  const search = useDebounce(searchInput, 300)
  // Push the debounced search into the URL and back to page 1. The ref holds
  // the last value written, so the URL echoing it back (or a new setter
  // identity) never re-triggers the reset to page 1.
  const pushedSearch = useRef(qParam)
  useEffect(() => {
    if (search === pushedSearch.current) return
    pushedSearch.current = search
    setQParam(search)
    setPage(1)
  }, [search, setQParam, setPage])

  const listFilters = useMemo(
    () =>
      externalSurfaceFilters(
        {
          search: qParam,
          type: typeParam,
          risk: riskParam as RiskBand | 'all',
          withFindings: findingsParam === 'true',
        },
        thresholds
      ),
    [qParam, typeParam, riskParam, findingsParam, thresholds]
  )

  const {
    assets,
    total,
    isLoading,
    error,
    mutate: refetchAssets,
  } = useAssets({
    ...listFilters,
    page: pagination.pageIndex + 1,
    pageSize: pagination.pageSize,
    sort: '-risk_score',
  })

  // Headline numbers: each one is a server count over ALL internet-facing
  // assets (not the current page, not the current search).
  const base = externalSurfaceFilters({}, thresholds)
  const allCount = useAssetCount(base)
  const criticalCount = useAssetCount({ ...base, ...riskRange('critical', thresholds) })
  const withFindingsCount = useAssetCount({ ...base, hasFindings: true })
  const canReadExposures = can(Permission.FindingsRead)
  const { total: expiringCerts } = useExposures(currentTenant?.id ?? null, {
    event_types: ['certificate_expiring', 'certificate_expired'],
    states: ['active'],
    per_page: 1,
  })

  const metrics: MetricStripItem[] = [
    {
      key: 'all',
      label: 'Internet-facing assets',
      value: allCount.total,
      onClick: () => {
        setRiskParam('all')
        setFindingsParam('all')
        setPage(1)
      },
      active: riskParam === 'all' && findingsParam === 'all',
    },
    {
      key: 'critical',
      label: 'Critical risk',
      value: criticalCount.total,
      tone: 'danger',
      hint: `Risk score ${thresholds.critical_min} or more`,
      onClick: () => {
        setRiskParam(riskParam === 'critical' ? 'all' : 'critical')
        setPage(1)
      },
      active: riskParam === 'critical',
    },
    {
      key: 'findings',
      label: 'With open findings',
      value: withFindingsCount.total,
      tone: 'warning',
      onClick: () => {
        setFindingsParam(findingsParam === 'true' ? 'all' : 'true')
        setPage(1)
      },
      active: findingsParam === 'true',
    },
    {
      key: 'certs',
      label: 'Expiring certificates',
      value: canReadExposures ? expiringCerts : '—',
      tone: 'warning',
      hint: canReadExposures ? 'Open, expired included' : 'Needs permission to read findings',
    },
  ]
  const metricsLoading =
    (allCount.isLoading || criticalCount.isLoading || withFindingsCount.isLoading) &&
    allCount.total === 0

  // ---- create / edit / delete -------------------------------------------
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [editAsset, setEditAsset] = useState<Asset | null>(null)
  const [deleteAsset, setDeleteAsset] = useState<Asset | null>(null)
  const [formData, setFormData] = useState<FormState>(EMPTY_FORM)
  const [scanCandidates, setScanCandidates] = useState<ScanCandidate[]>([])
  const [scanDialogOpen, setScanDialogOpen] = useState(false)

  const metadataFromForm = (): AssetMetadata => ({
    ...(formData.ipAddress ? { ip_addresses: [formData.ipAddress] } : {}),
    ...(formData.port ? { port: Number(formData.port) } : {}),
    ...(formData.parentDomain ? { parent_domain: formData.parentDomain } : {}),
  })

  const handleCreate = async () => {
    if (!formData.name) {
      toast.error('Enter an asset name')
      return
    }
    try {
      // exposure 'public' is what puts an asset on this page.
      await createAsset({
        name: formData.name,
        type: formData.type as CreateAssetInput['type'],
        scope: 'external',
        exposure: 'public',
        description: formData.notes || undefined,
        metadata: metadataFromForm(),
      })
      toast.success('External asset added')
      setIsCreateOpen(false)
      setFormData(EMPTY_FORM)
      await refetchAssets()
    } catch (e) {
      // A name that already exists is a 409 that may link to the asset.
      if (!toastIfDuplicateAsset(e, router.push)) {
        toast.error(getErrorMessage(e, 'Failed to add external asset'))
      }
    }
  }

  const handleEdit = async () => {
    if (!editAsset || !formData.name) {
      toast.error('Enter an asset name')
      return
    }
    try {
      await updateAsset(editAsset.id, {
        name: formData.name,
        description: formData.notes || undefined,
        metadata: metadataFromForm(),
      })
      toast.success('External asset updated')
      setEditAsset(null)
      setFormData(EMPTY_FORM)
      await refetchAssets()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Failed to update external asset'))
    }
  }

  const handleDelete = async () => {
    if (!deleteAsset) return
    // Refused when the asset has findings: the toast offers Archive.
    const result = await deleteAssetSafely(deleteAsset.id, deleteAsset.name, refetchAssets)
    if (result !== 'failed') setDeleteAsset(null)
  }

  const openEdit = useCallback((a: Asset) => {
    const parentDomain = propertyValue(a.metadata, 'parent_domain')
    const port = propertyValue(a.metadata, 'port')
    setFormData({
      name: a.name,
      type: (CREATE_TYPES as readonly string[]).includes(a.type)
        ? (a.type as FormState['type'])
        : 'subdomain',
      parentDomain: typeof parentDomain === 'string' ? parentDomain : '',
      ipAddress: ipOf(a) || '',
      port: port != null ? String(port) : '',
      notes: a.description || '',
    })
    setEditAsset(a)
  }, [])

  const openScanDialog = (items: Asset[]) => {
    setScanCandidates(
      items.map((a) => ({
        id: a.id,
        label: a.name || ipOf(a) || a.id,
        target: (ipOf(a) || a.name || '').trim(),
      }))
    )
    setScanDialogOpen(true)
  }

  // "+ Add label" on a row: save that asset's tags, then refetch.
  const saveRowLabels = useCallback(
    async (id: string, tags: string[]) => {
      try {
        await updateAsset(id, { tags })
        toast.success('Label added')
        await refetchAssets()
      } catch (e) {
        toast.error(getErrorMessage(e, 'Failed to add the label'))
        throw e
      }
    },
    [refetchAssets]
  )
  const canWriteAssets = can(Permission.AssetsWrite)

  const handleExport = async () => {
    try {
      const all = await fetchAllAssets(listFilters, (loaded, cap) =>
        toast.warning(`Export stopped at ${loaded} of more than ${cap} assets`)
      )
      exportToCsv(
        all,
        [
          { header: 'Name', accessor: (a) => a.name },
          { header: 'Type', accessor: (a) => a.type },
          { header: 'IP addresses', accessor: (a) => ipAddresses(a).join(';') },
          { header: 'Risk score', accessor: (a) => a.riskScore },
          { header: 'Findings', accessor: (a) => a.findingCount },
          { header: 'Last seen', accessor: (a) => a.lastSeen ?? '' },
        ],
        'external-assets'
      )
    } catch (e) {
      toast.error(getErrorMessage(e, 'Export failed'))
    }
  }

  const columns = useMemo<ColumnDef<Asset>[]>(
    () => [
      {
        id: 'name',
        header: 'Asset',
        enableSorting: false,
        cell: ({ row }) => (
          <StackedCell
            truncate
            className="max-w-[360px]"
            primary={<span className="font-medium">{row.original.name}</span>}
            secondary={sentence(row.original.type)}
          />
        ),
      },
      {
        // Status, IP / CNAME, technologies, TLS …: the shared service cells,
        // chosen per type by cellsForType. IPs are among them, so there is
        // no separate IP column.
        id: 'service',
        header: 'Service facts',
        enableSorting: false,
        cell: ({ row }) => <SurfaceFacts asset={row.original} className="max-w-[380px]" />,
      },
      {
        id: 'risk',
        header: 'Risk',
        enableSorting: false,
        cell: ({ row }) => <RiskScoreBadge score={row.original.riskScore} size="sm" />,
      },
      {
        id: 'findings',
        header: 'Findings',
        enableSorting: false,
        cell: ({ row }) =>
          row.original.findingCount > 0 ? (
            <IssuesChip assetId={row.original.id} count={row.original.findingCount} />
          ) : (
            <span className="text-muted-foreground tabular-nums">0</span>
          ),
      },
      {
        id: 'labels',
        header: 'Labels',
        enableSorting: false,
        cell: ({ row }) => (
          <LabelChips
            className="max-w-[220px]"
            labels={row.original.tags ?? []}
            onSave={canWriteAssets ? (tags) => saveRowLabels(row.original.id, tags) : undefined}
          />
        ),
      },
      {
        id: 'last_seen',
        header: 'Last seen',
        enableSorting: false,
        cell: ({ row }) =>
          row.original.lastSeen ? (
            <RelativeTime date={row.original.lastSeen} />
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
      },
      {
        id: 'actions',
        enableSorting: false,
        cell: ({ row }) => (
          <span onClick={(e) => e.stopPropagation()}>
            <DataTableRowActions
              actions={[
                {
                  label: 'Open',
                  icon: Eye,
                  onClick: () => router.push(`/assets/${row.original.id}`),
                },
                {
                  label: 'Edit',
                  icon: Pencil,
                  onClick: () => openEdit(row.original),
                  permission: Permission.AssetsWrite,
                },
                {
                  label: 'Delete',
                  icon: Trash2,
                  onClick: () => setDeleteAsset(row.original),
                  destructive: true,
                  permission: Permission.AssetsDelete,
                },
              ]}
            />
          </span>
        ),
      },
    ],
    [router, openEdit, canWriteAssets, saveRowLabels]
  )

  const filtersActive =
    !!qParam || typeParam !== 'all' || riskParam !== 'all' || findingsParam !== 'all'

  const toolbarStart = (
    <div className="flex flex-wrap items-center gap-2">
      <div className="relative w-full sm:w-64">
        <SearchIcon className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search assets"
          aria-label="Search assets"
          className="h-9 ps-9"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
        />
      </div>
      <Select
        value={typeParam}
        onValueChange={(v) => {
          setTypeParam(v)
          setPage(1)
        }}
      >
        <SelectTrigger className="h-9 w-36" aria-label="Filter by type">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All types</SelectItem>
          {TYPE_OPTIONS.map((o) => (
            <SelectItem key={o.value} value={o.value}>
              {o.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select
        value={riskParam}
        onValueChange={(v) => {
          setRiskParam(v)
          setPage(1)
        }}
      >
        <SelectTrigger className="h-9 w-32" aria-label="Filter by risk">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All risks</SelectItem>
          {RISK_OPTIONS.map((o) => (
            <SelectItem key={o.value} value={o.value}>
              {o.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )

  const toolbarEnd = (
    <Button
      variant="outline"
      size="sm"
      className="h-9"
      onClick={() => void refetchAssets()}
      aria-label="Refresh"
    >
      <RefreshCw className="h-4 w-4" />
    </Button>
  )

  const formFields = (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="ext-name">Name</Label>
          <Input
            id="ext-name"
            placeholder="api.example.com"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          />
        </div>
        {!editAsset && (
          <div className="space-y-2">
            <Label>Type</Label>
            <Select
              value={formData.type}
              onValueChange={(v) => setFormData({ ...formData, type: v as FormState['type'] })}
            >
              <SelectTrigger aria-label="Asset type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CREATE_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {sentence(t)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
      </div>
      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-2">
          <Label htmlFor="ext-parent">Parent domain</Label>
          <Input
            id="ext-parent"
            placeholder="example.com"
            value={formData.parentDomain}
            onChange={(e) => setFormData({ ...formData, parentDomain: e.target.value })}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ext-ip">IP address</Label>
          <Input
            id="ext-ip"
            placeholder="203.0.113.10"
            value={formData.ipAddress}
            onChange={(e) => setFormData({ ...formData, ipAddress: e.target.value })}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ext-port">Port</Label>
          <Input
            id="ext-port"
            type="number"
            placeholder="443"
            value={formData.port}
            onChange={(e) => setFormData({ ...formData, port: e.target.value })}
          />
        </div>
      </div>
      <div className="space-y-2">
        <Label htmlFor="ext-notes">Notes</Label>
        <Input
          id="ext-notes"
          placeholder="Optional"
          value={formData.notes}
          onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
        />
      </div>
    </div>
  )

  return (
    <>
      <Main>
        <PageHeader
          title="External attack surface"
          description="Every internet-facing asset, riskiest first."
        >
          <Can permission={Permission.ScansExecute}>
            <Button
              variant="outline"
              size="sm"
              onClick={() => openScanDialog(assets)}
              disabled={assets.length === 0}
            >
              <RefreshCw className="me-2 h-4 w-4" />
              Scan this page
            </Button>
          </Can>
          <Button variant="outline" size="sm" onClick={() => void handleExport()}>
            <Download className="me-2 h-4 w-4" />
            Export
          </Button>
          <Can permission={Permission.AssetsWrite}>
            <Button size="sm" onClick={() => setIsCreateOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              Add asset
            </Button>
          </Can>
        </PageHeader>

        <MetricStrip className="mt-5" loading={metricsLoading} items={metrics} />

        <div className="mt-5">
          {error && !isLoading ? (
            <ErrorState title="external assets" error={error} onRetry={() => refetchAssets()} />
          ) : isLoading && assets.length === 0 ? (
            <div className="space-y-2">
              <Skeleton className="h-9 w-full max-w-sm" />
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : (
            <DataTable
              columns={columns}
              data={assets}
              getRowId={(a) => a.id}
              showSearch={false}
              showColumnToggle={false}
              toolbarStart={toolbarStart}
              toolbarEnd={toolbarEnd}
              manualPagination
              rowCount={total}
              pagination={pagination}
              onPaginationChange={setPagination}
              pageSizeOptions={PAGE_SIZES}
              onRowClick={(a) => router.push(`/assets/${a.id}`)}
              emptyMessage={
                filtersActive ? 'No internet-facing assets match' : 'No internet-facing assets yet'
              }
              emptyDescription={
                filtersActive
                  ? 'Clear the search or filters to see every internet-facing asset.'
                  : 'Assets appear here once a scan, import or the certificate monitor marks them public.'
              }
            />
          )}
        </div>
      </Main>

      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add external asset</DialogTitle>
            <DialogDescription>Add an internet-facing asset to monitor.</DialogDescription>
          </DialogHeader>
          <DialogBody>{formFields}</DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate}>Add asset</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!editAsset} onOpenChange={(open) => !open && setEditAsset(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit external asset</DialogTitle>
            <DialogDescription>Update the asset&apos;s name, address and notes.</DialogDescription>
          </DialogHeader>
          <DialogBody>{formFields}</DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditAsset(null)}>
              Cancel
            </Button>
            <Button onClick={handleEdit}>Save changes</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AssetDeleteDialogShared
        open={!!deleteAsset}
        onOpenChange={(open) => !open && setDeleteAsset(null)}
        assetName={deleteAsset?.name}
        typeName="External asset"
        onConfirm={handleDelete}
      />

      <ScanAssetsDialog
        open={scanDialogOpen}
        onOpenChange={setScanDialogOpen}
        candidates={scanCandidates}
        title="Scan external assets"
      />
    </>
  )
}
