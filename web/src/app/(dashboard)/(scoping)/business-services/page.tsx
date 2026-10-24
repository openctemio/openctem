'use client'

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  GatedSectionTabs,
  MetricStrip,
  PageHeader,
  DetailHeader,
  DetailSheet,
  StackedCell,
  type MetricStripItem,
  ErrorState,
  CappedNotice,
} from '@/features/shared'
import { BUSINESS_CONTEXT_SECTION_TABS } from '@/config/section-tabs'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
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
import { ConfirmDialog, nameToConfirm } from '@/components/confirm-dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Plus, Pencil, Trash2, Link2 } from 'lucide-react'
import { BusinessServiceAssets } from '@/features/business-services/components/business-service-assets'
import { toast } from 'sonner'
import { post, put, del } from '@/lib/api/client'
import { useRegisterPages } from '@/lib/api/use-register-pages'
import { Can, Permission } from '@/lib/permissions'
import { CRITICALITY_BADGE_SOFT } from '@/lib/criticality-colors'
import { useUrlFilter } from '@/hooks/use-url-param'
import {
  CRITICALITY_LABELS,
  RATED_CRITICALITY_LEVELS,
  type RatedCriticality,
} from '@/lib/criticality'
import { useTranslation } from '@/context/i18n-provider'

type Criticality = RatedCriticality

interface BusinessService {
  id: string
  name: string
  description: string
  criticality: Criticality
  compliance_scope: string[]
  handles_pii: boolean
  handles_phi: boolean
  handles_financial: boolean
  availability_target?: number
  rpo_minutes?: number
  rto_minutes?: number
  owner_name: string
  owner_email: string
  /** Linked assets (business_service_assets); absent on APIs before the count shipped. */
  asset_count?: number
  created_at: string
  updated_at: string
}

const COMPLIANCE_FRAMEWORKS = ['PCI-DSS', 'HIPAA', 'SOC2', 'GDPR', 'ISO27001', 'NIST'] as const

const criticalityColors: Record<Criticality, string> = CRITICALITY_BADGE_SOFT

interface FormState {
  name: string
  description: string
  criticality: Criticality
  compliance_scope: string[]
  handles_pii: boolean
  handles_phi: boolean
  handles_financial: boolean
  availability_target: string
  rpo_minutes: string
  rto_minutes: string
  owner_name: string
  owner_email: string
}

const emptyForm: FormState = {
  name: '',
  description: '',
  criticality: 'medium',
  compliance_scope: [],
  handles_pii: false,
  handles_phi: false,
  handles_financial: false,
  availability_target: '',
  rpo_minutes: '',
  rto_minutes: '',
  owner_name: '',
  owner_email: '',
}

export default function BusinessServicesPage() {
  const { t } = useTranslation()
  const criticalityLabel = useCallback(
    (level: Criticality) => t(`criticality.${level}`, CRITICALITY_LABELS[level]),
    [t]
  )
  // Every service (up to the row cap), so the strip counts equal the list.
  const { data, mutate, isLoading, error } = useRegisterPages<BusinessService>(
    '/api/v1/business-services?per_page=100'
  )

  const allServices: BusinessService[] = useMemo(() => data?.data ?? [], [data])
  // Quick filter set from the metric strip; lives in the URL so the view links.
  const [quick, setQuick] = useUrlFilter('show', '')
  const services = useMemo(() => {
    if (quick === 'critical') return allServices.filter((s) => s.criticality === 'critical')
    if (quick === 'pii') return allServices.filter((s) => s.handles_pii)
    if (quick === 'financial') return allServices.filter((s) => s.handles_financial)
    return allServices
  }, [allServices, quick])

  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [editingService, setEditingService] = useState<BusinessService | null>(null)
  const [deletingService, setDeletingService] = useState<BusinessService | null>(null)
  // The service whose linked assets are open in the side sheet.
  const [assetsService, setAssetsService] = useState<BusinessService | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm)
  const [isSaving, setIsSaving] = useState(false)

  const stats = useMemo(() => {
    return {
      total: allServices.length,
      critical: allServices.filter((s) => s.criticality === 'critical').length,
      pii: allServices.filter((s) => s.handles_pii).length,
      financial: allServices.filter((s) => s.handles_financial).length,
    }
  }, [allServices])

  const toggleQuick = (key: string) => setQuick(quick === key ? '' : key)
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('businessContext.services.metric.total', 'Services'),
      value: stats.total,
      onClick: () => setQuick(''),
      active: !quick,
    },
    {
      key: 'critical',
      label: t('businessContext.services.metric.critical', 'Critical'),
      value: stats.critical,
      tone: 'danger',
      onClick: () => toggleQuick('critical'),
      active: quick === 'critical',
    },
    {
      key: 'pii',
      label: t('businessContext.services.metric.pii', 'Handle PII'),
      value: stats.pii,
      onClick: () => toggleQuick('pii'),
      active: quick === 'pii',
    },
    {
      key: 'financial',
      label: t('businessContext.services.metric.financial', 'Handle financial data'),
      value: stats.financial,
      onClick: () => toggleQuick('financial'),
      active: quick === 'financial',
    },
  ]

  function openCreate() {
    setEditingService(null)
    setForm(emptyForm)
    setIsDialogOpen(true)
  }

  function openEdit(service: BusinessService) {
    setEditingService(service)
    setForm({
      name: service.name,
      description: service.description ?? '',
      criticality: service.criticality,
      compliance_scope: service.compliance_scope ?? [],
      handles_pii: service.handles_pii,
      handles_phi: service.handles_phi,
      handles_financial: service.handles_financial,
      availability_target:
        service.availability_target != null ? String(service.availability_target) : '',
      rpo_minutes: service.rpo_minutes != null ? String(service.rpo_minutes) : '',
      rto_minutes: service.rto_minutes != null ? String(service.rto_minutes) : '',
      owner_name: service.owner_name ?? '',
      owner_email: service.owner_email ?? '',
    })
    setIsDialogOpen(true)
  }

  const columns = useMemo<ColumnDef<BusinessService>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('businessContext.services.col.name', 'Name')}
          />
        ),
        cell: ({ row }) => {
          const service = row.original
          return (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="cursor-help font-medium">{service.name}</span>
                </TooltipTrigger>
                {service.description && (
                  <TooltipContent className="max-w-sm">{service.description}</TooltipContent>
                )}
              </Tooltip>
            </TooltipProvider>
          )
        },
      },
      {
        accessorKey: 'criticality',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('businessContext.services.col.criticality', 'Criticality')}
          />
        ),
        cell: ({ row }) => (
          <Badge variant="outline" className={criticalityColors[row.original.criticality]}>
            {criticalityLabel(row.original.criticality)}
          </Badge>
        ),
      },
      {
        id: 'data_handling',
        header: t('businessContext.services.col.dataHandling', 'Data handling'),
        enableSorting: false,
        cell: ({ row }) => {
          const service = row.original
          return (
            <div className="flex flex-wrap gap-1">
              {service.handles_pii && (
                <Badge variant="secondary" className="text-xs">
                  {t('businessContext.services.badge.pii', 'PII')}
                </Badge>
              )}
              {service.handles_phi && (
                <Badge variant="secondary" className="text-xs">
                  {t('businessContext.services.badge.phi', 'PHI')}
                </Badge>
              )}
              {service.handles_financial && (
                <Badge variant="secondary" className="text-xs">
                  {t('businessContext.services.badge.financial', 'Financial')}
                </Badge>
              )}
            </div>
          )
        },
      },
      {
        id: 'compliance_scope',
        header: t('businessContext.services.col.compliance', 'Compliance scope'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex flex-wrap gap-1">
            {(row.original.compliance_scope ?? []).map((framework) => (
              <Badge key={framework} variant="outline" className="text-xs">
                {framework}
              </Badge>
            ))}
          </div>
        ),
      },
      {
        accessorKey: 'owner_name',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('businessContext.services.col.owner', 'Owner')}
          />
        ),
        cell: ({ row }) => (
          <StackedCell
            primary={row.original.owner_name || '—'}
            secondary={row.original.owner_email}
          />
        ),
      },
      {
        accessorKey: 'asset_count',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('businessContext.services.col.assets', 'Assets')}
          />
        ),
        cell: ({ row }) =>
          row.original.asset_count === undefined ? (
            '—'
          ) : (
            <button
              type="button"
              className="tabular-nums hover:underline"
              onClick={() => setAssetsService(row.original)}
            >
              {row.original.asset_count}
            </button>
          ),
      },
      {
        accessorKey: 'availability_target',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('businessContext.services.col.availability', 'Availability')}
          />
        ),
        cell: ({ row }) =>
          row.original.availability_target != null
            ? `${row.original.availability_target.toFixed(2)}%`
            : '—',
      },
      {
        id: 'actions',
        header: '',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => (
          <Can permission={[Permission.BusinessServicesRead, Permission.BusinessServicesWrite]}>
            <DataTableRowActions
              actions={[
                {
                  label: t('businessContext.services.action.linked', 'Linked assets'),
                  icon: Link2,
                  onClick: () => setAssetsService(row.original),
                },
                {
                  label: t('businessContext.services.action.edit', 'Edit'),
                  icon: Pencil,
                  onClick: () => openEdit(row.original),
                  permission: Permission.BusinessServicesWrite,
                  separatorBefore: true,
                },
                {
                  label: t('businessContext.services.action.delete', 'Delete'),
                  icon: Trash2,
                  onClick: () => setDeletingService(row.original),
                  destructive: true,
                  permission: Permission.BusinessServicesWrite,
                },
              ]}
            />
          </Can>
        ),
      },
    ],

    [t, criticalityLabel]
  )

  function toggleCompliance(framework: string) {
    setForm((prev) => {
      const exists = prev.compliance_scope.includes(framework)
      return {
        ...prev,
        compliance_scope: exists
          ? prev.compliance_scope.filter((f) => f !== framework)
          : [...prev.compliance_scope, framework],
      }
    })
  }

  async function handleSave() {
    if (!form.name.trim()) {
      toast.error(t('businessContext.services.toast.nameRequired', 'Name is required.'))
      return
    }

    const payload: Record<string, unknown> = {
      name: form.name.trim(),
      description: form.description.trim(),
      criticality: form.criticality,
      compliance_scope: form.compliance_scope,
      handles_pii: form.handles_pii,
      handles_phi: form.handles_phi,
      handles_financial: form.handles_financial,
      owner_name: form.owner_name.trim(),
      owner_email: form.owner_email.trim(),
    }

    if (form.availability_target) {
      const val = Number(form.availability_target)
      if (!Number.isNaN(val)) payload.availability_target = val
    }
    if (form.rpo_minutes) {
      const val = Number(form.rpo_minutes)
      if (!Number.isNaN(val)) payload.rpo_minutes = val
    }
    if (form.rto_minutes) {
      const val = Number(form.rto_minutes)
      if (!Number.isNaN(val)) payload.rto_minutes = val
    }

    setIsSaving(true)
    try {
      if (editingService) {
        await put(`/api/v1/business-services/${editingService.id}`, payload)
        toast.success(t('businessContext.services.toast.updated', 'Business service updated.'))
      } else {
        await post('/api/v1/business-services', payload)
        toast.success(t('businessContext.services.toast.created', 'Business service created.'))
      }
      setIsDialogOpen(false)
      setEditingService(null)
      setForm(emptyForm)
      await mutate()
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : t('businessContext.services.toast.saveFailed', 'Could not save the business service.')
      toast.error(message)
    } finally {
      setIsSaving(false)
    }
  }

  async function handleDelete() {
    if (!deletingService) return
    try {
      await del(`/api/v1/business-services/${deletingService.id}`)
      toast.success(t('businessContext.services.toast.deleted', 'Business service deleted.'))
      setDeletingService(null)
      await mutate()
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : t(
              'businessContext.services.toast.deleteFailed',
              'Could not delete the business service.'
            )
      toast.error(message)
    }
  }

  return (
    <Main>
      <PageHeader
        title={t('businessContext.services.title', 'Business services')}
        description={t(
          'businessContext.services.description',
          'Business services and their compliance, data handling and availability requirements.'
        )}
      >
        <Can permission={Permission.BusinessServicesWrite}>
          <Button size="sm" onClick={openCreate}>
            <Plus className="me-2 h-4 w-4" />
            {t('businessContext.services.new', 'New service')}
          </Button>
        </Can>
      </PageHeader>
      <GatedSectionTabs
        tabs={BUSINESS_CONTEXT_SECTION_TABS}
        label={t('businessContext.sectionsLabel', 'Business context sections')}
        className="mt-4 mb-0"
      />

      <MetricStrip className="mt-5" loading={isLoading} items={metrics} />

      {isLoading ? (
        <div className="mt-5 space-y-2 rounded-xl border p-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-9 w-full" />
          ))}
        </div>
      ) : error ? (
        <div className="mt-5">
          <ErrorState
            title={t('scope.businessServices.loadError', 'business services')}
            error={error}
            onRetry={() => void mutate()}
          />
        </div>
      ) : (
        <div className="mt-5">
          <DataTable
            columns={columns}
            data={services}
            searchPlaceholder={t(
              'businessContext.services.search.placeholder',
              'Search services...'
            )}
            onRowClick={(service) => setAssetsService(service)}
            emptyMessage={
              quick
                ? t('businessContext.services.empty.noMatch', 'No services match this filter')
                : t('businessContext.services.empty.none', 'No business services yet')
            }
            emptyDescription={
              quick
                ? t(
                    'businessContext.services.empty.noMatchDesc',
                    'Clear the filter to see every service.'
                  )
                : t('businessContext.services.empty.noneDesc', 'Create a service to get started.')
            }
          />
        </div>
      )}

      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>
              {editingService
                ? t('businessContext.services.dialog.editTitle', 'Edit business service')
                : t('businessContext.services.dialog.createTitle', 'New business service')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'businessContext.services.dialog.desc',
                'Define the business service and its compliance and data handling properties.'
              )}
            </DialogDescription>
          </DialogHeader>

          <DialogBody>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="name">{t('businessContext.services.form.name', 'Name *')}</Label>
                <Input
                  id="name"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder={t(
                    'businessContext.services.form.namePh',
                    'e.g. Customer Payment Service'
                  )}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="description">
                  {t('businessContext.services.form.description', 'Description')}
                </Label>
                <Textarea
                  id="description"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder={t(
                    'businessContext.services.form.descriptionPh',
                    'Briefly describe what this service does'
                  )}
                  rows={3}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="criticality">
                  {t('businessContext.services.form.criticality', 'Criticality')}
                </Label>
                <Select
                  value={form.criticality}
                  onValueChange={(value) => setForm({ ...form, criticality: value as Criticality })}
                >
                  <SelectTrigger id="criticality">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {RATED_CRITICALITY_LEVELS.map((c) => (
                      <SelectItem key={c} value={c}>
                        {criticalityLabel(c)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-2">
                <Label>{t('businessContext.services.form.compliance', 'Compliance scope')}</Label>
                <div className="flex flex-wrap gap-2">
                  {COMPLIANCE_FRAMEWORKS.map((framework) => {
                    const selected = form.compliance_scope.includes(framework)
                    return (
                      <Badge
                        key={framework}
                        variant={selected ? 'default' : 'outline'}
                        className="cursor-pointer"
                        onClick={() => toggleCompliance(framework)}
                      >
                        {framework}
                      </Badge>
                    )
                  })}
                </div>
              </div>

              <div className="grid gap-3 rounded-md border p-3">
                <Label className="text-sm font-semibold">
                  {t('businessContext.services.form.dataHandling', 'Data handling')}
                </Label>
                <div className="flex items-center justify-between">
                  <Label htmlFor="handles_pii" className="font-normal">
                    {t('businessContext.services.form.handlesPii', 'Handles PII')}
                  </Label>
                  <Switch
                    id="handles_pii"
                    checked={form.handles_pii}
                    onCheckedChange={(checked) => setForm({ ...form, handles_pii: checked })}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="handles_phi" className="font-normal">
                    {t('businessContext.services.form.handlesPhi', 'Handles PHI')}
                  </Label>
                  <Switch
                    id="handles_phi"
                    checked={form.handles_phi}
                    onCheckedChange={(checked) => setForm({ ...form, handles_phi: checked })}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="handles_financial" className="font-normal">
                    {t('businessContext.services.form.handlesFinancial', 'Handles financial data')}
                  </Label>
                  <Switch
                    id="handles_financial"
                    checked={form.handles_financial}
                    onCheckedChange={(checked) => setForm({ ...form, handles_financial: checked })}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <div className="grid gap-2">
                  <Label htmlFor="availability_target">
                    {t('businessContext.services.form.availability', 'Availability (%)')}
                  </Label>
                  <Input
                    id="availability_target"
                    type="number"
                    step="0.01"
                    value={form.availability_target}
                    onChange={(e) => setForm({ ...form, availability_target: e.target.value })}
                    placeholder="99.99"
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="rpo_minutes">
                    {t('businessContext.services.form.rpo', 'RPO (min)')}
                  </Label>
                  <Input
                    id="rpo_minutes"
                    type="number"
                    value={form.rpo_minutes}
                    onChange={(e) => setForm({ ...form, rpo_minutes: e.target.value })}
                    placeholder="60"
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="rto_minutes">
                    {t('businessContext.services.form.rto', 'RTO (min)')}
                  </Label>
                  <Input
                    id="rto_minutes"
                    type="number"
                    value={form.rto_minutes}
                    onChange={(e) => setForm({ ...form, rto_minutes: e.target.value })}
                    placeholder="120"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="grid gap-2">
                  <Label htmlFor="owner_name">
                    {t('businessContext.services.form.ownerName', 'Owner name')}
                  </Label>
                  <Input
                    id="owner_name"
                    value={form.owner_name}
                    onChange={(e) => setForm({ ...form, owner_name: e.target.value })}
                    placeholder={t('businessContext.services.form.ownerNamePh', 'Jane Doe')}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="owner_email">
                    {t('businessContext.services.form.ownerEmail', 'Owner email')}
                  </Label>
                  <Input
                    id="owner_email"
                    type="email"
                    value={form.owner_email}
                    onChange={(e) => setForm({ ...form, owner_email: e.target.value })}
                    placeholder={t(
                      'businessContext.services.form.ownerEmailPh',
                      'jane@example.com'
                    )}
                  />
                </div>
              </div>
            </div>
          </DialogBody>

          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDialogOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleSave} disabled={isSaving}>
              {isSaving
                ? t('businessContext.services.form.saving', 'Saving...')
                : editingService
                  ? t('businessContext.services.form.update', 'Update')
                  : t('businessContext.services.form.create', 'Create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {assetsService && (
        <DetailSheet
          open
          onOpenChange={(open) => !open && setAssetsService(null)}
          width="lg"
          header={
            <DetailHeader
              title={assetsService.name}
              meta={[
                t(
                  'businessContext.services.sheet.meta',
                  'The assets this service runs on. A cycle scoped to the service covers them.'
                ),
              ]}
              onClose={() => setAssetsService(null)}
            />
          }
        >
          <BusinessServiceAssets service={assetsService} onChanged={() => void mutate()} />
        </DetailSheet>
      )}

      <ConfirmDialog
        open={!!deletingService}
        onOpenChange={(open) => !open && setDeletingService(null)}
        title={t('confirm.businessService.deleteTitle', 'Delete the business service "{name}"?', {
          name: deletingService?.name ?? '',
        })}
        desc={t(
          'confirm.businessService.deleteDesc',
          'Its asset links are removed, so those assets no longer take business context from it. The assets themselves stay. This cannot be undone.'
        )}
        confirmText={t('confirm.businessService.deleteButton', 'Delete business service')}
        destructive
        typeToConfirm={
          deletingService ? nameToConfirm(deletingService.name, deletingService.id) : undefined
        }
        handleConfirm={handleDelete}
      />
      <CappedNotice loaded={allServices.length} total={data?.total ?? 0} />
    </Main>
  )
}
