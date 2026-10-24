'use client'

import { useState, useMemo, useEffect } from 'react'
import { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  GatedSectionTabs,
  MetricStrip,
  PageHeader,
  RiskScoreBadge,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
  DetailTabs,
  type MetricStripItem,
  ErrorState,
  CappedNotice,
} from '@/features/shared'
import { BUSINESS_CONTEXT_SECTION_TABS } from '@/config/section-tabs'
import { Can, Permission, useHasPermission, usePermissions } from '@/lib/permissions'
import { useCsvExport, type ExportFieldConfig } from '@/hooks/use-csv-export'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import {
  Plus,
  Download,
  Eye,
  Pencil,
  Trash2,
  Building2,
  Mail,
  ChevronRight,
  ChevronsUpDown,
  Check,
  Search,
  Link2,
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
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { cn } from '@/lib/utils'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { TabsCount } from '@/components/ui/tabs'
import { BusinessUnitAssets } from '@/features/business-units/components/business-unit-assets'
import { toast } from 'sonner'
import { type BusinessUnit, type Criticality, type RiskTolerance } from '@/features/business-units'
import {
  useBusinessUnits,
  useCreateBusinessUnit,
  useUpdateBusinessUnit,
} from '@/features/business-units/api/use-business-units'
import { del } from '@/lib/api/client'
import { CRITICALITY_BADGE_SOFT, CRITICALITY_DOT_COLORS } from '@/lib/criticality-colors'
import { CRITICALITY_LABELS, RATED_CRITICALITY_LEVELS } from '@/lib/criticality'
import { useTranslation } from '@/context/i18n-provider'
import { confirmName } from '@/lib/confirm-name'

const criticalityColors: Record<Criticality, string> = CRITICALITY_BADGE_SOFT

/** English fallbacks; the display text comes from businessContext.tolerance.* keys. */
const RISK_TOLERANCE_FALLBACK: Record<RiskTolerance, string> = {
  very_low: 'Very low',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  very_high: 'Very high',
}

/**
 * Risk tolerance is an appetite, not a severity: it uses neutral Badge
 * variants (more appetite = heavier badge), not the red-to-green scale.
 */
const riskToleranceVariant: Record<RiskTolerance, 'secondary' | 'outline' | 'default'> = {
  very_low: 'secondary',
  low: 'secondary',
  medium: 'outline',
  high: 'default',
  very_high: 'default',
}

/** Filter children of a given parent from the full list */
function getChildUnits(allUnits: BusinessUnit[], parentId: string): BusinessUnit[] {
  return allUnits.filter((bu) => bu.parentId === parentId)
}

/** Collect all transitive descendant ids of a unit (to prevent parent cycles). */
function getDescendantIds(allUnits: BusinessUnit[], rootId: string): Set<string> {
  const result = new Set<string>()
  const stack = [rootId]
  while (stack.length > 0) {
    const current = stack.pop() as string
    for (const bu of allUnits) {
      if (bu.parentId === current && !result.has(bu.id)) {
        result.add(bu.id)
        stack.push(bu.id)
      }
    }
  }
  return result
}

/** Backend accepts only critical|high|medium|low for criticality. */
const CRITICALITY_OPTIONS: readonly Criticality[] = RATED_CRITICALITY_LEVELS
/** Backend accepts only low|medium|high for risk tolerance. */
const RISK_TOLERANCE_OPTIONS: RiskTolerance[] = ['low', 'medium', 'high']

/**
 * Searchable parent-unit combobox. Excludes the unit being edited (`excludeId`)
 * and all of its descendants so a cycle can't be created. The "None" option
 * clears the parent (sends `""`).
 */
function ParentUnitSelect({
  units,
  value,
  onChange,
  excludeId,
}: {
  units: BusinessUnit[]
  value: string
  onChange: (id: string) => void
  excludeId?: string
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')

  const candidates = useMemo(() => {
    const excluded = new Set<string>()
    if (excludeId) {
      excluded.add(excludeId)
      for (const id of getDescendantIds(units, excludeId)) excluded.add(id)
    }
    const q = search.trim().toLowerCase()
    return units.filter((u) => !excluded.has(u.id) && (!q || u.name.toLowerCase().includes(q)))
  }, [units, excludeId, search])

  const selected = units.find((u) => u.id === value)

  return (
    <Popover
      open={open}
      onOpenChange={(isOpen) => {
        setOpen(isOpen)
        if (!isOpen) setSearch('')
      }}
    >
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className="w-full justify-between font-normal"
        >
          <span className={selected ? '' : 'text-muted-foreground'}>
            {selected ? selected.name : t('businessContext.units.parent.none', 'None (top-level)')}
          </span>
          <ChevronsUpDown className="ms-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[var(--radix-popover-trigger-width)] p-0" align="start">
        <Command shouldFilter={false}>
          <CommandInput
            placeholder={t('businessContext.units.parent.filter', 'Filter units...')}
            value={search}
            onValueChange={setSearch}
          />
          <CommandList>
            <CommandEmpty>
              {t('businessContext.units.parent.empty', 'No business units found.')}
            </CommandEmpty>
            <CommandGroup>
              <CommandItem
                value="__none__"
                onSelect={() => {
                  onChange('')
                  setOpen(false)
                  setSearch('')
                }}
              >
                <Check className={cn('me-2 h-4 w-4', !value ? 'opacity-100' : 'opacity-0')} />
                {t('businessContext.units.parent.none', 'None (top-level)')}
              </CommandItem>
              {candidates.map((u) => (
                <CommandItem
                  key={u.id}
                  value={u.id}
                  onSelect={() => {
                    onChange(u.id)
                    setOpen(false)
                    setSearch('')
                  }}
                >
                  <Check
                    className={cn('me-2 h-4 w-4', value === u.id ? 'opacity-100' : 'opacity-0')}
                  />
                  {u.name}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

export default function BusinessUnitsPage() {
  const { t } = useTranslation()
  const criticalityLabel = (level: Criticality) =>
    t(`criticality.${level}`, CRITICALITY_LABELS[level])
  const toleranceLabel = (level: RiskTolerance) =>
    t(`businessContext.tolerance.${level}`, RISK_TOLERANCE_FALLBACK[level])
  const unassigned = t('businessContext.unassigned', 'Unassigned')
  // Fetch from API, fallback to mock data if API returns empty
  const { data: apiData, error: loadError, isLoading, mutate: refreshList } = useBusinessUnits()
  const { trigger: createBU } = useCreateBusinessUnit()
  const { trigger: updateBU } = useUpdateBusinessUnit()
  const apiBUs: BusinessUnit[] = useMemo(() => {
    if (!apiData?.data?.length) return []
    return apiData.data.map(
      (bu) =>
        ({
          id: bu.id,
          name: bu.name,
          description: bu.description || '',
          owner: bu.owner_name || '',
          ownerEmail: bu.owner_email || '',
          criticality: (bu.criticality || 'medium') as Criticality,
          riskTolerance: (bu.risk_tolerance || 'medium') as RiskTolerance,
          assetCount: bu.asset_count,
          findingCount: bu.finding_count,
          riskScore: bu.avg_risk_score,
          criticalFindingCount: bu.critical_finding_count,
          regulatoryFrameworks: [],
          tags: bu.tags || [],
          parentId: bu.parent_id ?? undefined,
          childCount: 0,
          createdAt: bu.created_at,
          updatedAt: bu.updated_at,
        }) as unknown as BusinessUnit
    )
  }, [apiData])
  const [businessUnits, setBusinessUnits] = useState<BusinessUnit[]>([])
  useEffect(() => {
    setBusinessUnits(apiBUs)
  }, [apiBUs])
  const exportFields: ExportFieldConfig<BusinessUnit>[] = [
    { header: t('businessContext.units.export.name', 'Name'), accessor: (bu) => bu.name },
    {
      header: t('businessContext.units.export.description', 'Description'),
      accessor: (bu) => bu.description ?? '',
    },
    { header: t('businessContext.units.export.owner', 'Owner'), accessor: (bu) => bu.owner },
    {
      header: t('businessContext.units.export.ownerEmail', 'Owner email'),
      accessor: (bu) => bu.ownerEmail,
    },
    { header: t('businessContext.units.export.assets', 'Assets'), accessor: (bu) => bu.assetCount },
    {
      header: t('businessContext.units.export.risk', 'Risk score'),
      accessor: (bu) => bu.riskScore ?? '',
    },
    {
      header: t('businessContext.units.export.criticality', 'Criticality'),
      accessor: (bu) => criticalityLabel(bu.criticality),
    },
    {
      header: t('businessContext.units.export.tags', 'Tags'),
      accessor: (bu) => (bu.tags ?? []).join('; '),
    },
  ]
  const { handleExport } = useCsvExport(businessUnits, exportFields, 'business-units')
  const [viewUnit, setViewUnit] = useState<BusinessUnit | null>(null)
  // Which tab the detail sheet opens on: "Manage assets" opens it on Assets.
  const [viewTab, setViewTab] = useState<'overview' | 'assets' | 'hierarchy'>('overview')
  const canWriteAssets = useHasPermission(Permission.AssetsWrite)
  const openView = (unit: BusinessUnit, tab: 'overview' | 'assets' = 'overview') => {
    setViewTab(tab)
    setViewUnit(unit)
  }
  const [editUnit, setEditUnit] = useState<BusinessUnit | null>(null)
  const [deleteUnit, setDeleteUnit] = useState<BusinessUnit | null>(null)
  // Deleting a business unit is owner/admin only (the API refuses others).
  const { isAdmin } = usePermissions()
  const canDeleteUnit = isAdmin()
  const deleteUnitReason = canDeleteUnit
    ? undefined
    : t(
        'businessContext.units.deleteReason',
        'Only an owner or administrator can delete a business unit.'
      )
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  // Filters and search live in the URL so a filtered view can be linked to.
  const [filterCriticality, setFilterCriticality] = useUrlFilter('criticality', 'all')
  const [filterRiskTolerance, setFilterRiskTolerance] = useUrlFilter('risk_tolerance', 'all')
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    parentId: '',
    criticality: 'medium' as Criticality,
    riskTolerance: 'medium' as RiskTolerance,
    owner: '',
    ownerEmail: '',
    tags: '',
  })

  const stats = useMemo(() => {
    const count = businessUnits.length
    return {
      total: count,
      critical: businessUnits.filter((bu) => bu.criticality === 'critical').length,
      totalAssets: businessUnits.reduce((acc, bu) => acc + bu.assetCount, 0),
      // Guard against divide-by-zero on an empty tenant and missing per-unit
      // fields (the API adapter doesn't always populate score fields) — both
      // were rendering "NaN".
      averageRiskScore: count
        ? Math.round(businessUnits.reduce((acc, bu) => acc + (bu.riskScore ?? 0), 0) / count)
        : 0,
    }
  }, [businessUnits])

  const filteredUnits = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return businessUnits.filter((unit) => {
      if (filterCriticality !== 'all' && unit.criticality !== filterCriticality) return false
      if (filterRiskTolerance !== 'all' && unit.riskTolerance !== filterRiskTolerance) return false
      if (q && !unit.name.toLowerCase().includes(q) && !unit.owner.toLowerCase().includes(q))
        return false
      return true
    })
  }, [businessUnits, filterCriticality, filterRiskTolerance, searchQuery])

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      parentId: '',
      criticality: 'medium',
      riskTolerance: 'medium',
      owner: '',
      ownerEmail: '',
      tags: '',
    })
  }

  const handleCreate = async () => {
    if (!formData.name || !formData.owner || !formData.ownerEmail) {
      toast.error(t('businessContext.units.toast.required', 'Fill in all required fields.'))
      return
    }
    try {
      await createBU({
        name: formData.name,
        description: formData.description || '',
        owner_name: formData.owner,
        owner_email: formData.ownerEmail,
        criticality: formData.criticality,
        risk_tolerance: formData.riskTolerance,
        parent_id: formData.parentId, // '' = top-level (no parent)
        tags: formData.tags
          ? formData.tags
              .split(',')
              .map((tag) => tag.trim())
              .filter(Boolean)
          : [],
      })
      await refreshList()
      toast.success(t('businessContext.units.toast.created', 'Business unit created.'))
      setIsCreateOpen(false)
      resetForm()
    } catch {
      toast.error(
        t('businessContext.units.toast.createFailed', 'Could not create the business unit.')
      )
    }
  }

  const handleEdit = async () => {
    if (!editUnit || !formData.name || !formData.owner || !formData.ownerEmail) {
      toast.error(t('businessContext.units.toast.required', 'Fill in all required fields.'))
      return
    }
    try {
      await updateBU({
        id: editUnit.id,
        name: formData.name,
        description: formData.description || '',
        owner_name: formData.owner,
        owner_email: formData.ownerEmail,
        criticality: formData.criticality,
        risk_tolerance: formData.riskTolerance,
        parent_id: formData.parentId, // '' = clear parent
        tags: formData.tags
          ? formData.tags
              .split(',')
              .map((tag) => tag.trim())
              .filter(Boolean)
          : [],
      })
      await refreshList()
      toast.success(t('businessContext.units.toast.updated', 'Business unit updated.'))
      setEditUnit(null)
      resetForm()
    } catch {
      toast.error(
        t('businessContext.units.toast.updateFailed', 'Could not update the business unit.')
      )
    }
  }

  const handleDelete = async () => {
    if (!deleteUnit) return
    try {
      await del(`/api/v1/business-units/${deleteUnit.id}`)
      await refreshList()
      toast.success(t('businessContext.units.toast.deleted', 'Business unit deleted.'))
      setDeleteUnit(null)
    } catch {
      toast.error(
        t('businessContext.units.toast.deleteFailed', 'Could not delete the business unit.')
      )
    }
  }

  const openEdit = (unit: BusinessUnit) => {
    setFormData({
      name: unit.name,
      description: unit.description || '',
      parentId: unit.parentId || '',
      criticality: unit.criticality,
      riskTolerance: unit.riskTolerance,
      owner: unit.owner,
      ownerEmail: unit.ownerEmail,
      tags: unit.tags.join(', '),
    })
    setEditUnit(unit)
  }

  const columns: ColumnDef<BusinessUnit>[] = [
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('businessContext.units.col.unit', 'Business unit')}
        />
      ),
      cell: ({ row }) => {
        const unit = row.original
        const children = getChildUnits(businessUnits, unit.id)
        const parent = unit.parentId ? businessUnits.find((u) => u.id === unit.parentId) : undefined
        const context = [
          parent
            ? t('businessContext.units.context.inParent', 'in {name}', { name: parent.name })
            : unit.parentId
              ? t('businessContext.units.context.subUnit', 'Sub-unit')
              : '',
          children.length > 0
            ? t(
                'businessContext.units.context.subUnits',
                '{count, plural, one {# sub-unit} other {# sub-units}}',
                { count: children.length }
              )
            : '',
        ]
          .filter(Boolean)
          .join(' · ')
        return (
          <div className="flex min-w-0 items-center gap-2.5">
            <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
            <div className="min-w-0">
              <div className="truncate font-medium">{unit.name}</div>
              {context && <div className="text-xs text-muted-foreground">{context}</div>}
            </div>
          </div>
        )
      },
    },
    {
      accessorKey: 'criticality',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('businessContext.units.col.criticality', 'Criticality')}
        />
      ),
      cell: ({ row }) => (
        <Badge variant="outline" className={criticalityColors[row.original.criticality]}>
          {criticalityLabel(row.original.criticality)}
        </Badge>
      ),
      filterFn: (row, id, value) => value.includes(row.getValue(id)),
    },
    {
      accessorKey: 'riskTolerance',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('businessContext.units.col.tolerance', 'Risk tolerance')}
        />
      ),
      cell: ({ row }) => (
        <Badge variant={riskToleranceVariant[row.original.riskTolerance]}>
          {toleranceLabel(row.original.riskTolerance)}
        </Badge>
      ),
    },
    {
      accessorKey: 'assetCount',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('businessContext.units.col.assets', 'Assets')}
        />
      ),
      cell: ({ row }) => <span className="tabular-nums">{row.original.assetCount}</span>,
    },
    {
      accessorKey: 'riskScore',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('businessContext.units.col.risk', 'Risk score')}
        />
      ),
      cell: ({ row }) => <RiskScoreBadge score={row.original.riskScore} />,
    },
    {
      accessorKey: 'owner',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('businessContext.units.col.owner', 'Owner')}
        />
      ),
      cell: ({ row }) => (
        <div className="text-sm">
          <div className="font-medium">{row.original.owner || unassigned}</div>
          <div className="text-muted-foreground text-xs">{row.original.ownerEmail}</div>
        </div>
      ),
    },
    {
      id: 'actions',
      cell: ({ row }) => {
        const unit = row.original
        return (
          <Can permission={Permission.AssetsWrite}>
            <DataTableRowActions
              actions={[
                {
                  label: t('businessContext.units.action.view', 'View details'),
                  icon: Eye,
                  onClick: () => openView(unit),
                },
                {
                  label: t('businessContext.units.action.manage', 'Manage assets'),
                  icon: Link2,
                  onClick: () => openView(unit, 'assets'),
                  permission: Permission.AssetsWrite,
                },
                {
                  label: t('businessContext.units.action.edit', 'Edit'),
                  icon: Pencil,
                  onClick: () => openEdit(unit),
                  permission: Permission.AssetsWrite,
                },
                {
                  label: t('businessContext.units.action.delete', 'Delete'),
                  icon: Trash2,
                  onClick: () => setDeleteUnit(unit),
                  disabled: !canDeleteUnit,
                  disabledReason: deleteUnitReason,
                  destructive: true,
                  separatorBefore: true,
                  permission: Permission.AssetsWrite,
                },
              ]}
            />
          </Can>
        )
      },
    },
  ]

  const criticalOnly = filterCriticality === 'critical'
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('businessContext.units.metric.total', 'Business units'),
      value: stats.total,
      onClick: () => {
        setFilterCriticality('all')
        setFilterRiskTolerance('all')
      },
      active: filterCriticality === 'all' && filterRiskTolerance === 'all',
    },
    {
      key: 'critical',
      label: t('businessContext.units.metric.critical', 'Critical units'),
      value: stats.critical,
      tone: 'danger',
      onClick: () => setFilterCriticality(criticalOnly ? 'all' : 'critical'),
      active: criticalOnly,
    },
    {
      key: 'assets',
      label: t('businessContext.units.metric.assets', 'Assets'),
      value: stats.totalAssets,
    },
    {
      key: 'risk',
      label: t('businessContext.units.metric.risk', 'Average risk score'),
      value: stats.averageRiskScore,
      hint: t('businessContext.units.metric.riskHint', 'of 100'),
    },
  ]

  const formFields = (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="name">{t('businessContext.units.form.name', 'Name *')}</Label>
        <Input
          id="name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder={t('businessContext.units.form.namePh', 'e.g., Technology & Engineering')}
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="description">
          {t('businessContext.units.form.description', 'Description')}
        </Label>
        <Textarea
          id="description"
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          placeholder={t(
            'businessContext.units.form.descriptionPh',
            'Brief description of this business unit...'
          )}
          rows={3}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="criticality">
            {t('businessContext.units.form.criticality', 'Criticality')}
          </Label>
          <Select
            value={formData.criticality}
            onValueChange={(v) => setFormData({ ...formData, criticality: v as Criticality })}
          >
            <SelectTrigger id="criticality">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CRITICALITY_OPTIONS.map((level) => (
                <SelectItem key={level} value={level}>
                  <span className="flex items-center gap-2">
                    <span className={cn('h-2 w-2 rounded-full', CRITICALITY_DOT_COLORS[level])} />
                    {criticalityLabel(level)}
                  </span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="riskTolerance">
            {t('businessContext.units.form.tolerance', 'Risk tolerance')}
          </Label>
          <Select
            value={formData.riskTolerance}
            onValueChange={(v) => setFormData({ ...formData, riskTolerance: v as RiskTolerance })}
          >
            <SelectTrigger id="riskTolerance">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {RISK_TOLERANCE_OPTIONS.map((level) => (
                <SelectItem key={level} value={level}>
                  {toleranceLabel(level)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-2">
        <Label>{t('businessContext.units.form.parent', 'Parent unit')}</Label>
        <ParentUnitSelect
          units={businessUnits}
          value={formData.parentId}
          onChange={(id) => setFormData({ ...formData, parentId: id })}
          excludeId={editUnit?.id}
        />
        <p className="text-xs text-muted-foreground">
          {t(
            'businessContext.units.form.parentHelp',
            'Optional. Nest this unit under a parent to build your org hierarchy.'
          )}
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="owner">{t('businessContext.units.form.owner', 'Owner *')}</Label>
          <Input
            id="owner"
            value={formData.owner}
            onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
            placeholder={t('businessContext.units.form.ownerPh', 'e.g., John Doe')}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ownerEmail">
            {t('businessContext.units.form.ownerEmail', 'Owner email *')}
          </Label>
          <Input
            id="ownerEmail"
            type="email"
            value={formData.ownerEmail}
            onChange={(e) => setFormData({ ...formData, ownerEmail: e.target.value })}
            placeholder={t('businessContext.units.form.ownerEmailPh', 'e.g., john@company.com')}
          />
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="tags">{t('businessContext.units.form.tags', 'Tags')}</Label>
        <Input
          id="tags"
          value={formData.tags}
          onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
          placeholder={t(
            'businessContext.units.form.tagsPh',
            'Comma-separated tags, e.g., core, technology'
          )}
        />
      </div>
    </div>
  )

  return (
    <>
      <Main>
        <PageHeader
          title={t('businessContext.units.title', 'Business units')}
          description={t(
            'businessContext.units.description',
            'Your organizational structure, so security priorities follow the business.'
          )}
        >
          <Can permission={Permission.AssetsWrite}>
            <Button size="sm" onClick={() => setIsCreateOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              {t('businessContext.units.new', 'New business unit')}
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
            data={filteredUnits}
            showSearch={false}
            isLoading={isLoading}
            errorState={
              loadError ? (
                <ErrorState
                  title={t('scope.businessUnits.loadError', 'business units')}
                  error={loadError}
                  onRetry={() => refreshList()}
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
                    placeholder={t(
                      'businessContext.units.search.placeholder',
                      'Search name or owner…'
                    )}
                    aria-label={t('businessContext.units.search.aria', 'Search business units')}
                    className="h-9 ps-9"
                  />
                </div>
                <Select value={filterCriticality} onValueChange={setFilterCriticality}>
                  <SelectTrigger
                    className="h-9 w-auto min-w-36"
                    aria-label={t(
                      'businessContext.units.filter.criticality.aria',
                      'Filter by criticality'
                    )}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">
                      {t('businessContext.units.filter.criticality.all', 'All criticalities')}
                    </SelectItem>
                    {CRITICALITY_OPTIONS.map((level) => (
                      <SelectItem key={level} value={level}>
                        {criticalityLabel(level)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={filterRiskTolerance} onValueChange={setFilterRiskTolerance}>
                  <SelectTrigger
                    className="h-9 w-auto min-w-36"
                    aria-label={t(
                      'businessContext.units.filter.tolerance.aria',
                      'Filter by risk tolerance'
                    )}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">
                      {t('businessContext.units.filter.tolerance.all', 'All risk tolerances')}
                    </SelectItem>
                    {RISK_TOLERANCE_OPTIONS.map((level) => (
                      <SelectItem key={level} value={level}>
                        {t('businessContext.tolerance.option', '{level} tolerance', {
                          level: toleranceLabel(level),
                        })}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </>
            }
            toolbarEnd={
              <Button
                variant="outline"
                size="sm"
                className="h-9"
                onClick={handleExport}
                disabled={businessUnits.length === 0}
              >
                <Download className="h-4 w-4 md:me-2" />
                <span className="sr-only md:not-sr-only">{t('common.export', 'Export')}</span>
              </Button>
            }
            emptyMessage={
              businessUnits.length === 0
                ? t('businessContext.units.empty.none', 'No business units yet')
                : t('businessContext.units.empty.noMatch', 'No business units match')
            }
            emptyDescription={
              businessUnits.length === 0
                ? t(
                    'businessContext.units.empty.noneDesc',
                    'Create a business unit to map assets to the organization.'
                  )
                : t(
                    'businessContext.units.empty.noMatchDesc',
                    'Try adjusting your search or filters.'
                  )
            }
            onRowClick={(unit) => openView(unit)}
          />
        </div>
        <CappedNotice loaded={(apiData?.data ?? []).length} total={apiData?.total ?? 0} />
      </Main>

      {/* Create Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>
              {t('businessContext.units.dialog.createTitle', 'New business unit')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'businessContext.units.dialog.createDesc',
                'Add a business unit to organize your security scope.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>{formFields}</DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleCreate}>
              {t('businessContext.units.dialog.create', 'Create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={!!editUnit} onOpenChange={(open) => !open && setEditUnit(null)}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>
              {t('businessContext.units.dialog.editTitle', 'Edit business unit')}
            </DialogTitle>
            <DialogDescription>
              {t('businessContext.units.dialog.editDesc', 'Update the business unit details.')}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>{formFields}</DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditUnit(null)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleEdit}>
              {t('businessContext.units.dialog.save', 'Save changes')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* View Sheet */}
      {viewUnit && (
        <DetailSheet
          open
          onOpenChange={(open) => !open && setViewUnit(null)}
          panel={viewTab}
          header={
            <DetailHeader
              title={viewUnit.name}
              badges={
                <>
                  <Badge variant="outline" className={criticalityColors[viewUnit.criticality]}>
                    {criticalityLabel(viewUnit.criticality)}
                  </Badge>
                  <Badge variant={riskToleranceVariant[viewUnit.riskTolerance]}>
                    {t('businessContext.tolerance.badge', '{level} risk tolerance', {
                      level: toleranceLabel(viewUnit.riskTolerance),
                    })}
                  </Badge>
                </>
              }
              meta={[viewUnit.description, viewUnit.owner || unassigned]}
              actions={
                canWriteAssets ? (
                  <Button size="sm" variant="outline" onClick={() => openEdit(viewUnit)}>
                    <Pencil className="h-4 w-4" />
                    {t('businessContext.units.sheet.edit', 'Edit')}
                  </Button>
                ) : undefined
              }
              menu={
                canDeleteUnit
                  ? [
                      {
                        label: t('businessContext.units.sheet.delete', 'Delete business unit'),
                        icon: Trash2,
                        destructive: true,
                        onSelect: () => {
                          setViewUnit(null)
                          setDeleteUnit(viewUnit)
                        },
                      },
                    ]
                  : undefined
              }
              onClose={() => setViewUnit(null)}
            />
          }
          tabs={
            <DetailTabs
              tabs={[
                {
                  value: 'overview',
                  label: t('businessContext.units.sheet.tab.overview', 'Overview'),
                },
                {
                  value: 'assets',
                  label: (
                    <>
                      {t('businessContext.units.sheet.tab.assets', 'Assets')}
                      <TabsCount
                        value={
                          // The drawer holds a snapshot; the list refreshes after a link.
                          businessUnits.find((u) => u.id === viewUnit.id)?.assetCount ??
                          viewUnit.assetCount
                        }
                      />
                    </>
                  ),
                },
                {
                  value: 'hierarchy',
                  label: t('businessContext.units.sheet.tab.hierarchy', 'Hierarchy'),
                },
              ]}
              value={viewTab}
              onValueChange={setViewTab}
            />
          }
        >
          {viewTab === 'assets' && (
            <BusinessUnitAssets unit={viewUnit} onChanged={() => void refreshList()} />
          )}

          {viewTab === 'overview' && (
            <div className="space-y-5">
              <DetailStatGrid aria-label={t('businessContext.keyNumbers', 'Key numbers')}>
                <DetailStat
                  label={t('businessContext.units.sheet.assets', 'Assets')}
                  value={viewUnit.assetCount}
                />
                <DetailStat
                  label={t('businessContext.units.sheet.risk', 'Risk score')}
                  value={viewUnit.riskScore ?? 0}
                  meter={{
                    value: viewUnit.riskScore ?? 0,
                    max: 100,
                    label: t('businessContext.units.sheet.risk', 'Risk score'),
                  }}
                />
              </DetailStatGrid>

              <DetailSections>
                {viewUnit.description && (
                  <DetailSection
                    title={t('businessContext.units.sheet.description', 'Description')}
                  >
                    <p className="text-sm text-muted-foreground">{viewUnit.description}</p>
                  </DetailSection>
                )}
                <DetailSection title={t('businessContext.units.sheet.owner', 'Owner')}>
                  <p className="text-sm font-medium">{viewUnit.owner || unassigned}</p>
                  {viewUnit.ownerEmail && (
                    <p className="flex items-center gap-1 text-xs break-all text-muted-foreground">
                      <Mail className="h-3 w-3 shrink-0" />
                      {viewUnit.ownerEmail}
                    </p>
                  )}
                </DetailSection>

                {viewUnit.tags.length > 0 && (
                  <DetailSection
                    title={t('businessContext.units.sheet.tags', 'Tags')}
                    count={viewUnit.tags.length}
                  >
                    <div className="flex flex-wrap gap-1.5">
                      {viewUnit.tags.map((tag) => (
                        <Badge key={tag} variant="secondary">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </DetailSection>
                )}
              </DetailSections>
            </div>
          )}

          {viewTab === 'hierarchy' && (
            <DetailSections>
              {viewUnit.parentId &&
                (() => {
                  const parent = businessUnits.find((u) => u.id === viewUnit.parentId)
                  return (
                    <DetailSection title={t('businessContext.units.sheet.parent', 'Parent unit')}>
                      <button
                        type="button"
                        disabled={!parent}
                        className="flex w-full items-center gap-2 rounded-lg border px-3 py-2.5 text-start enabled:hover:bg-muted/50"
                        onClick={() => parent && setViewUnit(parent)}
                      >
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium break-words">
                          {parent?.name ??
                            t('businessContext.units.sheet.unknownUnit', 'Unknown unit')}
                        </span>
                      </button>
                    </DetailSection>
                  )
                })()}

              <DetailSection
                title={t('businessContext.units.sheet.subUnits', 'Sub-units')}
                count={getChildUnits(businessUnits, viewUnit.id).length}
              >
                {getChildUnits(businessUnits, viewUnit.id).length > 0 ? (
                  <ul className="divide-y rounded-lg border">
                    {getChildUnits(businessUnits, viewUnit.id).map((child) => (
                      <li key={child.id}>
                        <button
                          type="button"
                          className="flex w-full items-center justify-between gap-2 px-3 py-2.5 text-start hover:bg-muted/50"
                          onClick={() => setViewUnit(child)}
                        >
                          <span className="flex min-w-0 items-center gap-2">
                            <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
                            <span className="font-medium break-words">{child.name}</span>
                          </span>
                          <Badge variant="outline" className={criticalityColors[child.criticality]}>
                            {criticalityLabel(child.criticality)}
                          </Badge>
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    {t('businessContext.units.sheet.noSubUnits', 'No sub-units')}
                  </p>
                )}
              </DetailSection>
            </DetailSections>
          )}
        </DetailSheet>
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteUnit}
        onOpenChange={(open) => !open && setDeleteUnit(null)}
        title={t('confirm.businessUnit.deleteTitle', 'Delete the business unit "{name}"?', {
          name: deleteUnit?.name ?? '',
        })}
        desc={
          <>
            {t(
              'confirm.businessUnit.deleteDesc',
              'Its asset links are removed, so those assets no longer take business context from it. The assets themselves stay. This cannot be undone.'
            )}
            {getChildUnits(businessUnits, deleteUnit?.id || '').length > 0 && (
              <span className="block mt-2 text-destructive">
                {t(
                  'confirm.businessUnit.deleteChildren',
                  'Its sub-units are kept and become top-level units.'
                )}
              </span>
            )}
          </>
        }
        confirmText={t('confirm.businessUnit.deleteButton', 'Delete business unit')}
        destructive
        typeToConfirm={deleteUnit ? confirmName(deleteUnit.name, deleteUnit.id) : undefined}
        handleConfirm={handleDelete}
      />
    </>
  )
}
