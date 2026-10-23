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
import { useTranslation } from '@/context/i18n-provider'
import { archiveAndReport, deleteAssetSafely } from '@/features/assets/lib/safe-delete'
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
import { ACTIONABLE_SEVERITIES } from '@/lib/severity'
import type { RiskLevelThresholds } from '@/features/shared/types'
import {
  externalSurfaceFilters,
  riskRange,
  type RiskBand,
} from '@/features/attack-surface/lib/external-filters'

const PAGE_SIZES = [20, 50, 100]

// The exposures list has no event-type URL filter: it opens on a search for
// certificates, open ones first.
const CERT_EXPOSURES_HREF = '/exposures?q=certificate'

const TYPE_VALUES = [
  'domain',
  'subdomain',
  'ip_address',
  'service',
  'application',
  'certificate',
  'host',
] as const

const RISK_VALUES: readonly RiskBand[] = ACTIONABLE_SEVERITIES

const CREATE_TYPES = ['domain', 'subdomain', 'ip_address', 'service', 'certificate'] as const

type TFn = ReturnType<typeof useTranslation>['t']

/** An asset type in words; an unlisted type is shown as a sentence. */
function typeLabel(t: TFn, type?: string): string {
  switch (type) {
    case 'domain':
      return t('attackSurface.external.type.domain', 'Domain')
    case 'subdomain':
      return t('attackSurface.external.type.subdomain', 'Subdomain')
    case 'ip_address':
      return t('attackSurface.external.type.ip_address', 'IP address')
    case 'service':
      return t('attackSurface.external.type.service', 'Service')
    case 'application':
      return t('attackSurface.external.type.application', 'Application')
    case 'certificate':
      return t('attackSurface.external.type.certificate', 'Certificate')
    case 'host':
      return t('attackSurface.external.type.host', 'Host')
    default: {
      const s = (type ?? '').replace(/_/g, ' ')
      return s.charAt(0).toUpperCase() + s.slice(1)
    }
  }
}

function riskLabel(t: TFn, band: RiskBand): string {
  switch (band) {
    case 'critical':
      return t('attackSurface.external.risk.critical', 'Critical')
    case 'high':
      return t('attackSurface.external.risk.high', 'High')
    case 'medium':
      return t('attackSurface.external.risk.medium', 'Medium')
    case 'low':
      return t('attackSurface.external.risk.low', 'Low')
  }
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
  const { t } = useTranslation()
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
  // GET /exposures needs findings:read and exposures:read (the hook gates on both).
  const canReadExposures = can(Permission.FindingsRead) && can(Permission.ExposuresRead)
  const { total: expiringCerts, error: certsError } = useExposures(currentTenant?.id ?? null, {
    event_types: ['certificate_expiring', 'certificate_expired'],
    states: ['active'],
    per_page: 1,
  })

  const metrics: MetricStripItem[] = [
    {
      key: 'all',
      label: t('attackSurface.external.metric.all', 'Internet-facing assets'),
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
      label: t('attackSurface.external.metric.critical', 'Critical risk'),
      value: criticalCount.total,
      tone: 'danger',
      hint: t('attackSurface.external.metric.criticalHint', 'Risk score {min} or more', {
        min: thresholds.critical_min,
      }),
      onClick: () => {
        setRiskParam(riskParam === 'critical' ? 'all' : 'critical')
        setPage(1)
      },
      active: riskParam === 'critical',
    },
    {
      key: 'findings',
      label: t('attackSurface.external.metric.findings', 'With open findings'),
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
      label: t('attackSurface.external.metric.certs', 'Expiring certificates'),
      // "—", never a false 0, when the count cannot be read.
      value: canReadExposures && !certsError ? expiringCerts : '—',
      tone: 'warning',
      hint: !canReadExposures
        ? t('attackSurface.external.metric.certsNoAccess', 'Needs permission to read exposures')
        : certsError
          ? t('attackSurface.external.metric.certsError', 'Could not be loaded')
          : t('attackSurface.external.metric.certsHint', 'Open, expired included'),
      onClick: canReadExposures ? () => router.push(CERT_EXPOSURES_HREF) : undefined,
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
  const [submitting, setSubmitting] = useState(false)
  const [scanCandidates, setScanCandidates] = useState<ScanCandidate[]>([])
  const [scanDialogOpen, setScanDialogOpen] = useState(false)

  const metadataFromForm = (): AssetMetadata => ({
    ...(formData.ipAddress ? { ip_addresses: [formData.ipAddress] } : {}),
    ...(formData.port ? { port: Number(formData.port) } : {}),
    ...(formData.parentDomain ? { parent_domain: formData.parentDomain } : {}),
  })

  const handleCreate = async () => {
    if (submitting) return
    if (!formData.name) {
      toast.error(t('attackSurface.external.enterName', 'Enter an asset name'))
      return
    }
    setSubmitting(true)
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
      toast.success(t('attackSurface.external.added', 'External asset added.'))
      setIsCreateOpen(false)
      setFormData(EMPTY_FORM)
      await refetchAssets()
    } catch (e) {
      // A name that already exists is a 409 that may link to the asset.
      if (!toastIfDuplicateAsset(e, router.push)) {
        toast.error(
          getErrorMessage(e, t('attackSurface.external.addFailed', 'Failed to add external asset'))
        )
      }
    } finally {
      setSubmitting(false)
    }
  }

  const handleEdit = async () => {
    if (submitting) return
    if (!editAsset || !formData.name) {
      toast.error(t('attackSurface.external.enterName', 'Enter an asset name'))
      return
    }
    setSubmitting(true)
    try {
      // A field the person cleared is sent as an explicit null (and the notes
      // as an empty string): leaving it out would keep the old value, since
      // the server merges properties.
      const metadata: AssetMetadata = { ...metadataFromForm() }
      const was = {
        ip_addresses: ipOf(editAsset),
        port: propertyValue(editAsset.metadata, 'port'),
        parent_domain: propertyValue(editAsset.metadata, 'parent_domain'),
      }
      for (const key of ['ip_addresses', 'port', 'parent_domain'] as const) {
        if (was[key] != null && was[key] !== '' && !(key in metadata)) {
          ;(metadata as Record<string, unknown>)[key] = null
        }
      }
      await updateAsset(editAsset.id, {
        name: formData.name,
        description: formData.notes,
        metadata,
      })
      toast.success(t('attackSurface.external.updated', 'External asset updated.'))
      setEditAsset(null)
      setFormData(EMPTY_FORM)
      await refetchAssets()
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t('attackSurface.external.updateFailed', 'Failed to update external asset')
        )
      )
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteAsset) return
    // Refused when the asset has findings: the toast offers Archive.
    const result = await deleteAssetSafely(deleteAsset.id, deleteAsset.name, refetchAssets, t)
    if (result !== 'failed') setDeleteAsset(null)
  }

  const handleArchive = async () => {
    if (!deleteAsset) return
    const res = await archiveAndReport([deleteAsset.id], refetchAssets, t)
    if (res.failed.length === 0) setDeleteAsset(null)
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
        toast.success(t('attackSurface.external.labelAdded', 'Label added.'))
        await refetchAssets()
      } catch (e) {
        toast.error(
          getErrorMessage(e, t('attackSurface.external.labelFailed', 'Failed to add the label'))
        )
        throw e
      }
    },
    [refetchAssets, t]
  )
  const canWriteAssets = can(Permission.AssetsWrite)

  const handleExport = async () => {
    try {
      const all = await fetchAllAssets(listFilters, (loaded, cap) =>
        toast.warning(
          t(
            'attackSurface.external.exportStopped',
            'Export stopped at {loaded} of more than {cap} assets',
            {
              loaded,
              cap,
            }
          )
        )
      )
      exportToCsv(
        all,
        [
          { header: t('attackSurface.external.csv.name', 'Name'), accessor: (a) => a.name },
          { header: t('attackSurface.external.csv.type', 'Type'), accessor: (a) => a.type },
          {
            header: t('attackSurface.external.csv.ip', 'IP addresses'),
            accessor: (a) => ipAddresses(a).join(';'),
          },
          {
            header: t('attackSurface.external.csv.risk', 'Risk score'),
            accessor: (a) => a.riskScore,
          },
          {
            header: t('attackSurface.external.csv.findings', 'Findings'),
            accessor: (a) => a.findingCount,
          },
          {
            header: t('attackSurface.external.csv.lastSeen', 'Last seen'),
            accessor: (a) => a.lastSeen ?? '',
          },
        ],
        'external-assets'
      )
    } catch (e) {
      toast.error(getErrorMessage(e, t('attackSurface.external.exportFailed', 'Export failed')))
    }
  }

  const columns = useMemo<ColumnDef<Asset>[]>(
    () => [
      {
        id: 'name',
        header: t('attackSurface.external.col.asset', 'Asset'),
        enableSorting: false,
        cell: ({ row }) => (
          <StackedCell
            truncate
            className="max-w-[360px]"
            primary={<span className="font-medium">{row.original.name}</span>}
            secondary={typeLabel(t, row.original.type)}
          />
        ),
      },
      {
        // Status, IP / CNAME, technologies, TLS …: the shared service cells,
        // chosen per type by cellsForType. IPs are among them, so there is
        // no separate IP column.
        id: 'service',
        header: t('attackSurface.external.col.service', 'Service facts'),
        enableSorting: false,
        cell: ({ row }) => <SurfaceFacts asset={row.original} className="max-w-[380px]" />,
      },
      {
        id: 'risk',
        header: t('attackSurface.external.col.risk', 'Risk'),
        enableSorting: false,
        cell: ({ row }) => <RiskScoreBadge score={row.original.riskScore} size="sm" />,
      },
      {
        id: 'findings',
        header: t('attackSurface.external.col.findings', 'Findings'),
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
        header: t('attackSurface.external.col.labels', 'Labels'),
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
        header: t('attackSurface.external.col.lastSeen', 'Last seen'),
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
                  label: t('attackSurface.external.action.open', 'Open'),
                  icon: Eye,
                  onClick: () => router.push(`/assets/${row.original.id}`),
                },
                {
                  label: t('attackSurface.external.action.edit', 'Edit'),
                  icon: Pencil,
                  onClick: () => openEdit(row.original),
                  permission: Permission.AssetsWrite,
                },
                {
                  label: t('attackSurface.external.action.delete', 'Delete'),
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
    [router, openEdit, canWriteAssets, saveRowLabels, t]
  )

  const filtersActive =
    !!qParam || typeParam !== 'all' || riskParam !== 'all' || findingsParam !== 'all'

  const toolbarStart = (
    <div className="flex flex-wrap items-center gap-2">
      <div className="relative w-full sm:w-64">
        <SearchIcon className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder={t('attackSurface.external.search', 'Search assets')}
          aria-label={t('attackSurface.external.search', 'Search assets')}
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
        <SelectTrigger
          className="h-9 w-36"
          aria-label={t('attackSurface.external.filterType', 'Filter by type')}
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">{t('attackSurface.external.allTypes', 'All types')}</SelectItem>
          {TYPE_VALUES.map((v) => (
            <SelectItem key={v} value={v}>
              {typeLabel(t, v)}
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
        <SelectTrigger
          className="h-9 w-32"
          aria-label={t('attackSurface.external.filterRisk', 'Filter by risk')}
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">{t('attackSurface.external.allRisks', 'All risks')}</SelectItem>
          {RISK_VALUES.map((v) => (
            <SelectItem key={v} value={v}>
              {riskLabel(t, v)}
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
      aria-label={t('attackSurface.external.refresh', 'Refresh')}
    >
      <RefreshCw className="h-4 w-4" />
    </Button>
  )

  const formFields = (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="ext-name">{t('attackSurface.external.form.name', 'Name')}</Label>
          <Input
            id="ext-name"
            placeholder="api.example.com"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          />
        </div>
        {!editAsset && (
          <div className="space-y-2">
            <Label htmlFor="ext-type">{t('attackSurface.external.form.type', 'Type')}</Label>
            <Select
              value={formData.type}
              onValueChange={(v) => setFormData({ ...formData, type: v as FormState['type'] })}
            >
              <SelectTrigger id="ext-type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CREATE_TYPES.map((v) => (
                  <SelectItem key={v} value={v}>
                    {typeLabel(t, v)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="space-y-2">
          <Label htmlFor="ext-parent">
            {t('attackSurface.external.form.parent', 'Parent domain')}
          </Label>
          <Input
            id="ext-parent"
            placeholder="example.com"
            value={formData.parentDomain}
            onChange={(e) => setFormData({ ...formData, parentDomain: e.target.value })}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ext-ip">{t('attackSurface.external.form.ip', 'IP address')}</Label>
          <Input
            id="ext-ip"
            placeholder="203.0.113.10"
            value={formData.ipAddress}
            onChange={(e) => setFormData({ ...formData, ipAddress: e.target.value })}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ext-port">{t('attackSurface.external.form.port', 'Port')}</Label>
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
        <Label htmlFor="ext-notes">{t('attackSurface.external.form.notes', 'Notes')}</Label>
        <Input
          id="ext-notes"
          placeholder={t('attackSurface.external.form.optional', 'Optional')}
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
          title={t('attackSurface.external.title', 'External attack surface')}
          description={t(
            'attackSurface.external.description',
            'Every internet-facing asset, riskiest first.'
          )}
        >
          <Can permission={Permission.ScansExecute}>
            <Button
              variant="outline"
              size="sm"
              onClick={() => openScanDialog(assets)}
              disabled={assets.length === 0}
            >
              <RefreshCw className="me-2 h-4 w-4" />
              {t('attackSurface.external.scanPage', 'Scan this page')}
            </Button>
          </Can>
          <Button variant="outline" size="sm" onClick={() => void handleExport()}>
            <Download className="me-2 h-4 w-4" />
            {t('attackSurface.external.export', 'Export')}
          </Button>
          <Can permission={Permission.AssetsWrite}>
            <Button size="sm" onClick={() => setIsCreateOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              {t('attackSurface.external.addAsset', 'Add asset')}
            </Button>
          </Can>
        </PageHeader>

        <MetricStrip className="mt-5" loading={metricsLoading} items={metrics} />

        <div className="mt-5">
          {error && !isLoading ? (
            <ErrorState
              title={t('attackSurface.external.errorTitle', 'external assets')}
              error={error}
              onRetry={() => refetchAssets()}
            />
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
                filtersActive
                  ? t('attackSurface.external.emptyFiltered', 'No internet-facing assets match')
                  : t('attackSurface.external.empty', 'No internet-facing assets yet')
              }
              emptyDescription={
                filtersActive
                  ? t(
                      'attackSurface.external.emptyFilteredDescription',
                      'Clear the search or filters to see every internet-facing asset.'
                    )
                  : t(
                      'attackSurface.external.emptyDescription',
                      'Assets appear here once a scan, import or the certificate monitor marks them public.'
                    )
              }
            />
          )}
        </div>
      </Main>

      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('attackSurface.external.addTitle', 'Add external asset')}</DialogTitle>
            <DialogDescription>
              {t(
                'attackSurface.external.addDescription',
                'Add an internet-facing asset to monitor.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>{formFields}</DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)} disabled={submitting}>
              {t('attackSurface.external.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleCreate} disabled={submitting}>
              {t('attackSurface.external.addAsset', 'Add asset')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!editAsset} onOpenChange={(open) => !open && setEditAsset(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('attackSurface.external.editTitle', 'Edit external asset')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'attackSurface.external.editDescription',
                "Update the asset's name, address and notes."
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>{formFields}</DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditAsset(null)} disabled={submitting}>
              {t('attackSurface.external.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleEdit} disabled={submitting}>
              {t('attackSurface.external.saveChanges', 'Save changes')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AssetDeleteDialogShared
        open={!!deleteAsset}
        onOpenChange={(open) => !open && setDeleteAsset(null)}
        assetName={deleteAsset?.name}
        typeName={t('assets.external.typeName', 'external asset')}
        findingCount={deleteAsset?.findingCount}
        onArchive={handleArchive}
        onConfirm={handleDelete}
      />

      <ScanAssetsDialog
        open={scanDialogOpen}
        onOpenChange={setScanDialogOpen}
        candidates={scanCandidates}
        title={t('attackSurface.external.scanTitle', 'Scan external assets')}
      />
    </>
  )
}
