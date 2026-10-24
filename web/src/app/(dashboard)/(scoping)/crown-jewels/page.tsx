'use client'

import { useState, useMemo, useEffect } from 'react'
import { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  GatedSectionTabs,
  getRiskLevel,
  MetricStrip,
  PageHeader,
  RiskScoreBadge,
  DetailCallout,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
  ErrorState,
  type MetricStripItem,
  CappedNotice,
} from '@/features/shared'
import { BUSINESS_CONTEXT_SECTION_TABS } from '@/config/section-tabs'
import { Can, Permission, useHasPermission } from '@/lib/permissions'
import { useCsvExport, type ExportFieldConfig } from '@/hooks/use-csv-export'
import { useUrlFilter } from '@/hooks/use-url-param'
import { SEVERITY_BADGE_SOLID } from '@/lib/severity-colors'
import { SEVERITY_LEVELS, severityCounts } from '@/lib/severity'
import { useRiskThresholds } from '@/context/risk-scoring-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import {
  Plus,
  Download,
  Search,
  Eye,
  Pencil,
  Trash2,
  Crown,
  Users,
  Mail,
  ShieldCheck,
  ShieldX,
} from 'lucide-react'
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
import { ConfirmDialog } from '@/components/confirm-dialog'
import { toast } from 'sonner'
import {
  type CrownJewel,
  type AssetCategory,
  type ProtectionLevel,
  type DataClassification,
} from '@/features/crown-jewels'
import {
  useCrownJewels,
  useAllAssets,
  useDesignateCrownJewel,
  useUndesignateCrownJewel,
} from '@/features/crown-jewels/api/use-crown-jewels'
import { mutate } from 'swr'
import { Progress } from '@/components/ui/progress'
import { cn } from '@/lib/utils'
import { CRITICALITY_BADGE_SOFT, type CriticalityLevel } from '@/lib/criticality-colors'
import { useTranslation } from '@/context/i18n-provider'
import { useSearchQuery } from '@/hooks/use-search-query'
import { getAssetTypeIcon } from '@/features/assets/lib/asset-type-icon'
import { ASSET_TYPE_LABELS } from '@/features/assets/types/asset.types'
import { formatDateOnly } from '@/lib/date-only'

const CROWN_JEWELS_KEY = '/api/v1/assets?is_crown_jewel=true&per_page=100'

type TFn = ReturnType<typeof useTranslation>['t']

function impactBand(score: number): 'high' | 'medium' | 'low' {
  return score >= 67 ? 'high' : score >= 34 ? 'medium' : 'low'
}

/** Asset type label: the shared English type names, else the raw type made readable. */
function assetTypeLabel(type: string | undefined): string {
  if (!type) return ASSET_TYPE_LABELS.unclassified
  return (ASSET_TYPE_LABELS as Record<string, string>)[type] ?? type.replace(/_/g, ' ')
}

// Internet-facing, the product's one definition (API internet_facing:
// exposure public or reported reachable). Exposure values are public,
// restricted, private, isolated or unknown; there is no "internet".
function isExposed(j: CrownJewel) {
  return Boolean(j.isInternetFacing)
}

// Compact findings-by-severity chips (only non-zero bands).
function SeverityChips({ sev, t }: { sev?: CrownJewel['findingSeverity']; t: TFn }) {
  if (!sev) return <span className="text-muted-foreground text-xs">—</span>
  const parts = SEVERITY_LEVELS.map((level) => ({
    n: sev[level] ?? 0,
    level,
    k: level === 'info' ? 'I' : level.charAt(0).toUpperCase(),
  })).filter((p) => p.n > 0)
  if (parts.length === 0)
    return <span className="text-muted-foreground text-xs">{t('crownJewels.none', 'None')}</span>
  return (
    <span className="inline-flex items-center gap-1">
      {parts.map((p) => (
        <span
          key={p.k}
          title={t('crownJewels.severityChip', '{count} {level}', {
            count: p.n,
            level: t(`severity.${p.level}`, p.level),
          })}
          className={cn(
            'rounded px-1.5 py-0.5 text-[10px] font-semibold tabular-nums',
            SEVERITY_BADGE_SOLID[p.level]
          )}
        >
          {p.n}
          {p.k}
        </span>
      ))}
    </span>
  )
}

export default function CrownJewelsPage() {
  const { t, locale } = useTranslation()
  const criticalityText = (c: string) => t(`criticality.${c}`, c)
  // Same bands as RiskScoreBadge, so the sheet's label matches the table's badge.
  const riskThresholds = useRiskThresholds()
  const riskLabel = (score: number) => {
    const level = getRiskLevel(score, riskThresholds)
    return t(`riskScore.level.${level.key}`, level.label)
  }
  // Fetch from API, fallback to mock if no API data
  const { data: apiCrownJewels, error: loadError, isLoading, mutate: reload } = useCrownJewels()
  const { trigger: designate, isMutating: isDesignating } = useDesignateCrownJewel()
  const { trigger: undesignate, isMutating: isUndesignating } = useUndesignateCrownJewel()

  // Asset search for the "designate" create dialog
  const [assetSearch, setAssetSearch] = useState('')
  const [selectedAssetId, setSelectedAssetId] = useState<string>('')
  const debouncedAssetSearch = useSearchQuery(assetSearch).term
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  // Only fetch candidates while the designate dialog is open.
  const { data: allAssets } = useAllAssets(debouncedAssetSearch, isCreateOpen)
  const apiMapped: CrownJewel[] = useMemo(() => {
    if (!apiCrownJewels?.data?.length) return []
    return apiCrownJewels.data.map((a: Record<string, unknown>) => {
      const props = (a.properties as Record<string, unknown>) || {}
      const sev = (a.finding_severity_counts as Record<string, number>) || {}
      const owner = a.primary_owner as { name?: string; email?: string } | undefined
      const biz = Number(props.business_impact_score ?? 0)
      const cls = (a.data_classification as string) || ''
      return {
        id: a.id,
        name: a.name,
        description: (a.description as string) || '',
        // Real fields from the assets API.
        assetType: (a.type as string) || 'asset',
        riskScore: (a.risk_score as number) || 0,
        businessImpactScore: biz,
        findingCount: (a.finding_count as number) || 0,
        findingSeverity: severityCounts(sev),
        exposure: (a.exposure as string) || 'unknown',
        isInternetFacing: Boolean(a.internet_facing),
        criticality: (a.criticality as string) || '',
        dataClassification: (cls || 'internal') as DataClassification,
        piiExposed: Boolean(a.pii_data_exposed),
        phiExposed: Boolean(a.phi_data_exposed),
        owner: owner?.name || (a.owner_ref as string) || '',
        businessImpact: (props.business_impact_notes as string) || '',
        ownerEmail: owner?.email || '',
        tags: (a.tags as string[]) || [],
        exposureCount: (a.exposure_count as number) || 0,
        dependencyCount: 0,
        createdAt: (a.created_at as string) || '',
        lastAssessed: (a.updated_at as string) || '',
        updatedAt: (a.updated_at as string) || '',
      } as unknown as CrownJewel
    })
  }, [apiCrownJewels])
  const [crownJewels, setCrownJewels] = useState<CrownJewel[]>([])
  // Only fields the assets API returns; the old category, status and business
  // unit columns were always empty.
  const exportFields: ExportFieldConfig<CrownJewel>[] = [
    { header: t('crownJewels.export.name', 'Name'), accessor: (j) => j.name },
    { header: t('crownJewels.export.type', 'Type'), accessor: (j) => j.assetType ?? '' },
    {
      header: t('crownJewels.export.criticality', 'Criticality'),
      accessor: (j) => j.criticality ?? '',
    },
    { header: t('crownJewels.export.exposure', 'Exposure'), accessor: (j) => j.exposure ?? '' },
    {
      header: t('crownJewels.export.internetFacing', 'Internet-facing'),
      accessor: (j) =>
        j.isInternetFacing ? t('crownJewels.yes', 'Yes') : t('crownJewels.no', 'No'),
    },
    { header: t('crownJewels.export.risk', 'Risk score'), accessor: (j) => j.riskScore },
    {
      header: t('crownJewels.export.businessImpact', 'Business impact score'),
      accessor: (j) => j.businessImpactScore ?? 0,
    },
    {
      header: t('crownJewels.export.findings', 'Open findings'),
      accessor: (j) => j.findingCount ?? 0,
    },
    { header: t('crownJewels.export.owner', 'Owner'), accessor: (j) => j.owner },
    { header: t('crownJewels.export.ownerEmail', 'Owner email'), accessor: (j) => j.ownerEmail },
    { header: t('crownJewels.export.tags', 'Tags'), accessor: (j) => (j.tags ?? []).join('; ') },
  ]
  const { handleExport } = useCsvExport(crownJewels, exportFields, 'crown-jewels')
  useEffect(() => {
    setCrownJewels(apiMapped)
  }, [apiMapped])
  const [viewJewel, setViewJewel] = useState<CrownJewel | null>(null)
  const canWriteAssets = useHasPermission(Permission.AssetsWrite)
  const [editJewel, setEditJewel] = useState<CrownJewel | null>(null)
  const [deleteJewel, setDeleteJewel] = useState<CrownJewel | null>(null)
  // Filters and search live in the URL so a filtered view can be linked to.
  // Exposure and asset type are what the assets API actually returns; the old
  // status/category filters matched fields it never sends, so they emptied the list.
  const [filterExposure, setFilterExposure] = useUrlFilter('exposure', 'all')
  const [filterType, setFilterType] = useUrlFilter('type', 'all')
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    category: 'data' as AssetCategory,
    protectionLevel: 'high' as ProtectionLevel,
    dataClassification: 'confidential' as DataClassification,
    businessImpact: '',
    owner: '',
    ownerEmail: '',
    businessUnit: '',
    tags: '',
  })

  const stats = useMemo(() => {
    const jewels = crownJewels
    return {
      total: jewels.length,
      exposed: jewels.filter(isExposed).length,
      withCritical: jewels.filter((j) => (j.findingSeverity?.critical ?? 0) > 0).length,
      // Guard against divide-by-zero on an empty tenant (was rendering "NaN").
      averageRiskScore: jewels.length
        ? Math.round(jewels.reduce((acc, j) => acc + (j.riskScore ?? 0), 0) / jewels.length)
        : 0,
    }
  }, [crownJewels])

  const assetTypes = useMemo(
    () => [...new Set(crownJewels.map((j) => j.assetType).filter(Boolean) as string[])].sort(),
    [crownJewels]
  )

  const filteredJewels = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return crownJewels.filter((jewel) => {
      if (filterExposure === 'exposed' && !isExposed(jewel)) return false
      if (filterExposure === 'not_exposed' && isExposed(jewel)) return false
      if (filterType !== 'all' && jewel.assetType !== filterType) return false
      if (q && !jewel.name.toLowerCase().includes(q) && !jewel.owner.toLowerCase().includes(q))
        return false
      return true
    })
  }, [crownJewels, filterExposure, filterType, searchQuery])

  const exposedOnly = filterExposure === 'exposed'
  const whyScore = viewJewel?.businessImpactScore ?? 0
  const whyLevel = whyScore >= 67 ? 'high' : whyScore >= 34 ? 'moderate' : 'limited'
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('crownJewels.metric.total', 'Crown jewels'),
      value: stats.total,
      onClick: () => {
        setFilterExposure('all')
        setFilterType('all')
      },
      active: filterExposure === 'all' && filterType === 'all',
    },
    {
      key: 'exposed',
      label: t('crownJewels.metric.exposed', 'Internet-exposed'),
      value: stats.exposed,
      tone: 'danger',
      onClick: () => setFilterExposure(exposedOnly ? 'all' : 'exposed'),
      active: exposedOnly,
    },
    {
      key: 'critical',
      label: t('crownJewels.metric.critical', 'With critical findings'),
      value: stats.withCritical,
      tone: 'danger',
    },
    {
      key: 'risk',
      label: t('crownJewels.metric.risk', 'Average risk score'),
      value: stats.averageRiskScore,
      hint: t('crownJewels.metric.riskHint', 'of 100'),
    },
  ]

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      category: 'data',
      protectionLevel: 'high',
      dataClassification: 'confidential',
      businessImpact: '',
      owner: '',
      ownerEmail: '',
      businessUnit: '',
      tags: '',
    })
  }

  const handleCreate = async () => {
    if (!selectedAssetId) {
      toast.error(t('crownJewels.toast.selectAsset', 'Select an asset to designate.'))
      return
    }
    if (!formData.businessImpact) {
      toast.error(t('crownJewels.toast.notesRequired', 'Enter the business impact notes.'))
      return
    }
    try {
      // Preserve the selected asset's existing business impact score instead of
      // clobbering it; the designate form only collects notes, not a score.
      const selectedAsset = allAssets?.data?.find((a) => a.id === selectedAssetId)
      const existingScore = Number(
        (selectedAsset?.properties as Record<string, unknown> | undefined)?.business_impact_score ??
          0
      )
      await designate({
        assetId: selectedAssetId,
        businessImpactScore: existingScore > 0 ? existingScore : 75,
        businessImpactNotes: formData.businessImpact,
      })
      await mutate(CROWN_JEWELS_KEY)
      toast.success(t('crownJewels.toast.designated', 'Asset designated as a crown jewel.'))
      setIsCreateOpen(false)
      setSelectedAssetId('')
      setAssetSearch('')
      resetForm()
    } catch {
      toast.error(t('crownJewels.toast.designateFailed', 'Could not designate the crown jewel.'))
    }
  }

  const handleEdit = async () => {
    if (!editJewel || !formData.businessImpact) {
      toast.error(t('crownJewels.toast.required', 'Fill in all required fields.'))
      return
    }
    try {
      // Keep the asset's real business impact score; the edit form only lets the
      // user change notes, so it must not overwrite the stored score with a constant.
      await designate({
        assetId: editJewel.id as string,
        businessImpactScore: editJewel.businessImpactScore ?? 75,
        businessImpactNotes: formData.businessImpact,
      })
      await mutate(CROWN_JEWELS_KEY)
      toast.success(t('crownJewels.toast.updated', 'Crown jewel updated.'))
      setEditJewel(null)
      resetForm()
    } catch {
      toast.error(t('crownJewels.toast.updateFailed', 'Could not update the crown jewel.'))
    }
  }

  const handleDelete = async () => {
    if (!deleteJewel) return
    try {
      await undesignate({ assetId: deleteJewel.id as string })
      await mutate(CROWN_JEWELS_KEY)
      toast.success(t('crownJewels.toast.removed', 'Crown jewel removed.'))
      setDeleteJewel(null)
    } catch {
      toast.error(t('crownJewels.toast.removeFailed', 'Could not remove the crown jewel.'))
    }
  }

  const openEdit = (jewel: CrownJewel) => {
    setFormData({
      name: jewel.name,
      description: jewel.description || '',
      category: jewel.category,
      protectionLevel: jewel.protectionLevel,
      dataClassification: jewel.dataClassification,
      businessImpact: jewel.businessImpact,
      owner: jewel.owner,
      ownerEmail: jewel.ownerEmail,
      businessUnit: jewel.businessUnit,
      tags: jewel.tags.join(', '),
    })
    setEditJewel(jewel)
  }

  const columns: ColumnDef<CrownJewel>[] = [
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('crownJewels.col.asset', 'Asset')} />
      ),
      cell: ({ row }) => {
        const jewel = row.original
        // Icon of the asset's real type.
        const TypeIcon = getAssetTypeIcon(jewel.assetType)
        return (
          <div className="flex min-w-0 items-center gap-2.5">
            <TypeIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
            <div className="min-w-0">
              <div className="truncate font-medium">{jewel.name}</div>
              <div className="text-xs text-muted-foreground">
                {assetTypeLabel(jewel.assetType)}
                {jewel.criticality ? ` · ${criticalityText(jewel.criticality)}` : ''}
              </div>
            </div>
          </div>
        )
      },
    },
    {
      accessorKey: 'riskScore',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('crownJewels.col.risk', 'Risk')} />
      ),
      cell: ({ row }) => <RiskScoreBadge score={row.original.riskScore} size="sm" />,
    },
    {
      accessorKey: 'businessImpactScore',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('crownJewels.col.impact', 'Business impact')}
        />
      ),
      cell: ({ row }) => {
        const b = row.original.businessImpactScore ?? 0
        return (
          <div className="flex items-center gap-2">
            <span className="w-7 text-end font-medium tabular-nums">{b}</span>
            <Progress
              value={b}
              className="h-1.5 w-16"
              aria-label={t('crownJewels.impactAria', 'Business impact {score} of 100', {
                score: b,
              })}
            />
          </div>
        )
      },
    },
    {
      id: 'findings',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('crownJewels.col.findings', 'Findings')} />
      ),
      cell: ({ row }) => <SeverityChips sev={row.original.findingSeverity} t={t} />,
    },
    {
      id: 'exposure',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('crownJewels.col.exposure', 'Exposure')} />
      ),
      cell: ({ row }) => {
        const exposed = isExposed(row.original)
        return exposed ? (
          <Badge variant="outline" className="border-destructive/30 text-destructive">
            <ShieldX className="me-1 h-3 w-3" />
            {t('crownJewels.exposed', 'Internet-exposed')}
          </Badge>
        ) : (
          <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
            <ShieldCheck className="h-3 w-3" />
            {t('crownJewels.notExposed', 'Not exposed')}
          </span>
        )
      },
    },
    {
      accessorKey: 'owner',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('crownJewels.col.owner', 'Owner')} />
      ),
      cell: ({ row }) => (
        <span className={cn('text-sm', !row.original.owner && 'text-muted-foreground')}>
          {row.original.owner || t('crownJewels.unassigned', 'Unassigned')}
        </span>
      ),
    },
    {
      id: 'actions',
      cell: ({ row }) => {
        const jewel = row.original
        return (
          <DataTableRowActions
            actions={[
              {
                label: t('crownJewels.viewDetails', 'View details'),
                icon: Eye,
                onClick: () => setViewJewel(jewel),
              },
              {
                label: t('crownJewels.action.edit', 'Edit'),
                icon: Pencil,
                onClick: () => openEdit(jewel),
                permission: Permission.AssetsWrite,
              },
              {
                label: t('crownJewels.action.remove', 'Remove'),
                icon: Trash2,
                onClick: () => setDeleteJewel(jewel),
                destructive: true,
                separatorBefore: true,
                permission: Permission.AssetsWrite,
              },
            ]}
          />
        )
      },
    },
  ]

  return (
    <>
      <Main>
        <PageHeader
          title={t('crownJewels.title', 'Crown jewels')}
          description={t(
            'crownJewels.description',
            'The assets whose compromise would hurt the business most.'
          )}
        >
          <Can permission={Permission.AssetsWrite}>
            <Button size="sm" onClick={() => setIsCreateOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              {t('crownJewels.designate', 'Designate crown jewel')}
            </Button>
          </Can>
        </PageHeader>
        <GatedSectionTabs
          tabs={BUSINESS_CONTEXT_SECTION_TABS}
          label={t('businessContext.sectionsLabel', 'Business context sections')}
          className="mt-4 mb-0"
        />

        <MetricStrip className="mt-5" loading={isLoading} items={metrics} />

        <div className="mt-5">
          <DataTable
            columns={columns}
            data={filteredJewels}
            showSearch={false}
            isLoading={isLoading}
            errorState={
              loadError ? (
                <ErrorState
                  title={t('crownJewels.loadError', 'crown jewels')}
                  error={loadError}
                  onRetry={() => reload()}
                />
              ) : undefined
            }
            toolbarStart={
              <>
                <div className="relative min-w-0 flex-1 sm:max-w-xs">
                  <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder={t('crownJewels.search.placeholder', 'Search name or owner…')}
                    aria-label={t('crownJewels.search.aria', 'Search crown jewels')}
                    className="h-9 ps-9"
                  />
                </div>
                <Select value={filterExposure} onValueChange={setFilterExposure}>
                  <SelectTrigger
                    className="h-9 w-auto min-w-36"
                    aria-label={t('crownJewels.filter.exposure.aria', 'Filter by exposure')}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">
                      {t('crownJewels.filter.exposure.any', 'Any exposure')}
                    </SelectItem>
                    <SelectItem value="exposed">
                      {t('crownJewels.exposed', 'Internet-exposed')}
                    </SelectItem>
                    <SelectItem value="not_exposed">
                      {t('crownJewels.notExposed', 'Not exposed')}
                    </SelectItem>
                  </SelectContent>
                </Select>
                {assetTypes.length > 1 && (
                  <Select value={filterType} onValueChange={setFilterType}>
                    <SelectTrigger
                      className="h-9 w-auto min-w-32"
                      aria-label={t('crownJewels.filter.type.aria', 'Filter by asset type')}
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">
                        {t('crownJewels.filter.type.all', 'All types')}
                      </SelectItem>
                      {assetTypes.map((type) => (
                        <SelectItem key={type} value={type}>
                          {assetTypeLabel(type)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </>
            }
            toolbarEnd={
              <Button
                variant="outline"
                size="sm"
                className="h-9"
                onClick={handleExport}
                disabled={crownJewels.length === 0}
              >
                <Download className="h-4 w-4 md:me-2" />
                <span className="sr-only md:not-sr-only">{t('common.export', 'Export')}</span>
              </Button>
            }
            emptyMessage={
              crownJewels.length === 0
                ? t('crownJewels.empty.none', 'No crown jewels yet')
                : t('crownJewels.empty.noMatch', 'No crown jewels match')
            }
            emptyDescription={
              crownJewels.length === 0
                ? t(
                    'crownJewels.empty.noneDesc',
                    'Designate a critical asset as a crown jewel to track it here.'
                  )
                : t('crownJewels.empty.noMatchDesc', 'Try adjusting your search or filters.')
            }
            onRowClick={(jewel) => setViewJewel(jewel)}
          />
        </div>
        <CappedNotice
          loaded={(apiCrownJewels?.data ?? []).length}
          total={apiCrownJewels?.total ?? 0}
        />
      </Main>

      {/* Create Dialog */}
      <Dialog
        open={isCreateOpen}
        onOpenChange={(open) => {
          setIsCreateOpen(open)
          if (!open) {
            setSelectedAssetId('')
            setAssetSearch('')
            resetForm()
          }
        }}
      >
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>
              {t('crownJewels.dialog.designateTitle', 'Designate crown jewel')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'crownJewels.dialog.designateDesc',
                'Select an existing asset to designate as a crown jewel that needs special protection.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="asset-search">
                  {t('crownJewels.dialog.searchAsset', 'Search asset *')}
                </Label>
                <Input
                  id="asset-search"
                  value={assetSearch}
                  onChange={(e) => {
                    setAssetSearch(e.target.value)
                    setSelectedAssetId('')
                  }}
                  placeholder={t('crownJewels.dialog.searchPh', 'Type to search assets...')}
                />
                {allAssets?.data && allAssets.data.length > 0 && (
                  <div className="border rounded-md max-h-64 overflow-y-auto overscroll-contain">
                    {allAssets.data.map((a) => (
                      <button
                        key={a.id as string}
                        type="button"
                        className={`w-full text-start px-3 py-2 text-sm hover:bg-muted transition-colors ${
                          selectedAssetId === a.id ? 'bg-muted font-medium' : ''
                        }`}
                        onClick={() => {
                          setSelectedAssetId(a.id as string)
                          setAssetSearch(a.name as string)
                        }}
                      >
                        <span className="font-medium">{a.name as string}</span>
                        {(a.type as string | undefined) && (
                          <span className="ms-2 text-xs text-muted-foreground">
                            {assetTypeLabel(a.type as string)}
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                )}
                {selectedAssetId && (
                  <p className="text-xs text-muted-foreground">
                    {t('crownJewels.dialog.selected', 'Asset selected: {name}', {
                      name: assetSearch,
                    })}
                  </p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="businessImpact">
                  {t('crownJewels.dialog.notes', 'Business impact notes *')}
                </Label>
                <Textarea
                  id="businessImpact"
                  value={formData.businessImpact}
                  onChange={(e) => setFormData({ ...formData, businessImpact: e.target.value })}
                  placeholder={t(
                    'crownJewels.dialog.notesPh',
                    'Describe the impact if this asset is compromised...'
                  )}
                  rows={3}
                />
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleCreate} disabled={isDesignating}>
              {isDesignating
                ? t('crownJewels.dialog.designating', 'Designating...')
                : t('crownJewels.dialog.designateButton', 'Designate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog
        open={!!editJewel}
        onOpenChange={(open) => {
          if (!open) {
            setEditJewel(null)
            resetForm()
          }
        }}
      >
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>{t('crownJewels.dialog.editTitle', 'Edit crown jewel')}</DialogTitle>
            <DialogDescription>
              {t('crownJewels.dialog.editDesc', 'Update the business impact notes for {name}.', {
                name: editJewel?.name ?? '',
              })}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="edit-businessImpact">
                  {t('crownJewels.dialog.notes', 'Business impact notes *')}
                </Label>
                <Textarea
                  id="edit-businessImpact"
                  value={formData.businessImpact}
                  onChange={(e) => setFormData({ ...formData, businessImpact: e.target.value })}
                  placeholder={t(
                    'crownJewels.dialog.notesPh',
                    'Describe the impact if this asset is compromised...'
                  )}
                  rows={4}
                />
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditJewel(null)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleEdit} disabled={isDesignating}>
              {isDesignating
                ? t('crownJewels.dialog.saving', 'Saving...')
                : t('crownJewels.dialog.save', 'Save changes')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* View Sheet */}
      {viewJewel && (
        <DetailSheet
          open
          onOpenChange={(open) => !open && setViewJewel(null)}
          header={
            <DetailHeader
              title={viewJewel.name}
              badges={
                <>
                  <Badge variant="outline" className="gap-1 text-xs">
                    <Crown className="h-3 w-3" />
                    {assetTypeLabel(viewJewel.assetType)}
                  </Badge>
                  {viewJewel.criticality && (
                    <Badge
                      variant="outline"
                      className={cn(
                        'text-xs',
                        CRITICALITY_BADGE_SOFT[viewJewel.criticality as CriticalityLevel]
                      )}
                    >
                      {criticalityText(viewJewel.criticality)}
                    </Badge>
                  )}
                  {isExposed(viewJewel) && (
                    <Badge
                      variant="outline"
                      className="border-destructive/30 bg-destructive/10 text-xs text-destructive"
                    >
                      {t('crownJewels.exposed', 'Internet-exposed')}
                    </Badge>
                  )}
                </>
              }
              meta={[viewJewel.description, viewJewel.owner]}
              actions={
                canWriteAssets ? (
                  <Button size="sm" variant="outline" onClick={() => openEdit(viewJewel)}>
                    <Pencil className="h-4 w-4" />
                    {t('crownJewels.action.edit', 'Edit')}
                  </Button>
                ) : undefined
              }
              menu={
                canWriteAssets
                  ? [
                      {
                        label: t('crownJewels.action.removeJewel', 'Remove crown jewel'),
                        icon: Trash2,
                        destructive: true,
                        onSelect: () => {
                          setViewJewel(null)
                          setDeleteJewel(viewJewel)
                        },
                      },
                    ]
                  : undefined
              }
              onClose={() => setViewJewel(null)}
            />
          }
        >
          <div className="space-y-5">
            {isExposed(viewJewel) && (
              <DetailCallout
                tone="destructive"
                icon={ShieldX}
                title={t(
                  'crownJewels.sheet.reachable',
                  'Reachable from the internet ({exposure})',
                  { exposure: viewJewel.exposure ?? '' }
                )}
              >
                {t(
                  'crownJewels.sheet.reachableDesc',
                  'This drives its risk. Review the attack paths in Exposure Chains.'
                )}
              </DetailCallout>
            )}

            <DetailStatGrid aria-label={t('crownJewels.sheet.keyNumbers', 'Key numbers')}>
              <DetailStat
                label={t('crownJewels.sheet.stat.risk', 'Risk')}
                value={viewJewel.riskScore}
                tone={
                  ['critical', 'high'].includes(riskLabel(viewJewel.riskScore).toLowerCase())
                    ? 'destructive'
                    : 'default'
                }
                caption={riskLabel(viewJewel.riskScore)}
              />
              <DetailStat
                label={t('crownJewels.sheet.stat.impact', 'Business impact')}
                value={viewJewel.businessImpactScore ?? 0}
                caption={t(
                  `crownJewels.impact.${impactBand(viewJewel.businessImpactScore ?? 0)}`,
                  impactBand(viewJewel.businessImpactScore ?? 0)
                )}
              />
              <DetailStat
                label={t('crownJewels.sheet.stat.findings', 'Open findings')}
                value={viewJewel.findingCount ?? 0}
                tone={(viewJewel.findingSeverity?.critical ?? 0) > 0 ? 'destructive' : 'default'}
              />
            </DetailStatGrid>

            <DetailSections>
              {viewJewel.description && (
                <DetailSection title={t('crownJewels.sheet.description', 'Description')}>
                  <p className="text-sm text-muted-foreground">{viewJewel.description}</p>
                </DetailSection>
              )}
              {/* Why it's a crown jewel: one honest sentence. */}
              <DetailSection title={t('crownJewels.sheet.why', 'Why it is critical')}>
                <p className="text-sm leading-relaxed text-muted-foreground">
                  {t(
                    `crownJewels.sheet.why.${whyLevel}${viewJewel.piiExposed ? 'Pii' : ''}`,
                    'Compromise would have {level} business impact ({score}/100).',
                    { level: whyLevel, score: viewJewel.businessImpactScore ?? 0 }
                  )}{' '}
                  {isExposed(viewJewel)
                    ? t(
                        'crownJewels.sheet.whyExposed',
                        'It is reachable from the internet, so reducing its exposure is the priority.'
                      )
                    : t(
                        'crownJewels.sheet.whyContained',
                        'It is not internet-reachable, which keeps its risk contained.'
                      )}
                </p>
                <p className="mt-2 text-sm whitespace-pre-wrap">
                  {viewJewel.businessImpact || (
                    <span className="text-muted-foreground">
                      {t('crownJewels.whyNoNotes', 'No business impact notes recorded.')}
                    </span>
                  )}
                </p>
              </DetailSection>

              <DetailSection
                title={t('crownJewels.sheet.openFindings', 'Open findings')}
                count={viewJewel.findingCount ?? 0}
              >
                {(viewJewel.findingCount ?? 0) > 0 ? (
                  <SeverityChips sev={viewJewel.findingSeverity} t={t} />
                ) : (
                  <p className="flex items-center gap-2 text-sm text-muted-foreground">
                    <ShieldCheck className="h-4 w-4" />{' '}
                    {t('crownJewels.sheet.noFindings', 'No open findings on this asset.')}
                  </p>
                )}
              </DetailSection>

              {!isExposed(viewJewel) && (
                <DetailSection title={t('crownJewels.sheet.reachability', 'Reachability')}>
                  <p className="flex items-start gap-2 text-sm text-muted-foreground">
                    <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
                    {t(
                      'crownJewels.sheet.notReachable',
                      'Not reachable from the internet: no public attack path reaches this asset.'
                    )}
                  </p>
                </DetailSection>
              )}

              <DetailSection title={t('crownJewels.sheet.details', 'Details')}>
                <DetailFieldGrid>
                  <DetailField label={t('crownJewels.sheet.type', 'Type')}>
                    <span>{assetTypeLabel(viewJewel.assetType)}</span>
                  </DetailField>
                  {viewJewel.criticality && (
                    <DetailField label={t('crownJewels.sheet.criticality', 'Criticality')}>
                      <span>{criticalityText(viewJewel.criticality)}</span>
                    </DetailField>
                  )}
                  <DetailField label={t('crownJewels.sheet.classification', 'Data classification')}>
                    <span>
                      {t(
                        `crownJewels.classification.${viewJewel.dataClassification}`,
                        viewJewel.dataClassification.replace('_', ' ')
                      )}
                    </span>
                  </DetailField>
                  {(viewJewel.piiExposed || viewJewel.phiExposed) && (
                    <DetailField label={t('crownJewels.sheet.sensitive', 'Sensitive data')}>
                      {[
                        viewJewel.piiExposed && t('crownJewels.sensitive.pii', 'PII'),
                        viewJewel.phiExposed && t('crownJewels.sensitive.phi', 'PHI'),
                      ]
                        .filter(Boolean)
                        .join(', ')}
                    </DetailField>
                  )}
                  {viewJewel.lastAssessed && (
                    <DetailField label={t('crownJewels.sheet.lastAssessed', 'Last assessed')}>
                      {formatDateOnly(viewJewel.lastAssessed, locale)}
                    </DetailField>
                  )}
                </DetailFieldGrid>
              </DetailSection>

              <DetailSection title={t('crownJewels.sheet.owner', 'Owner')} icon={Users}>
                <p className="font-medium">
                  {viewJewel.owner || t('crownJewels.unassigned', 'Unassigned')}
                </p>
                {viewJewel.ownerEmail ? (
                  <p className="flex items-center gap-1 text-sm break-all text-muted-foreground">
                    <Mail className="h-3 w-3 shrink-0" />
                    {viewJewel.ownerEmail}
                  </p>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'crownJewels.sheet.assignOwner',
                      'Assign an owner so alerts route correctly'
                    )}
                  </p>
                )}
              </DetailSection>

              {viewJewel.tags.length > 0 && (
                <DetailSection
                  title={t('crownJewels.sheet.tags', 'Tags')}
                  count={viewJewel.tags.length}
                >
                  <div className="flex flex-wrap gap-1.5">
                    {viewJewel.tags.map((tag) => (
                      <Badge key={tag} variant="secondary">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </DetailSection>
              )}
            </DetailSections>
          </div>
        </DetailSheet>
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteJewel}
        onOpenChange={(open) => !open && setDeleteJewel(null)}
        title={t('confirm.crownJewel.removeTitle', 'Remove "{name}" from your crown jewels?', {
          name: deleteJewel?.name ?? '',
        })}
        desc={t(
          'confirm.crownJewel.removeDesc',
          'Its crown-jewel tracking and protection requirements are removed. The asset itself stays, and you can designate it again later.'
        )}
        confirmText={
          isUndesignating ? t('confirm.removing', 'Removing…') : t('confirm.remove', 'Remove')
        }
        destructive
        isLoading={isUndesignating}
        handleConfirm={handleDelete}
      />
    </>
  )
}
