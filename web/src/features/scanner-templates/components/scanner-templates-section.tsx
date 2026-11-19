'use client'

import * as React from 'react'
import { useState, useMemo, useCallback } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import {
  Plus,
  FileCode2,
  Loader2,
  Trash2,
  Download,
  CheckCircle,
  XCircle,
  Archive,
  FileWarning,
  Upload,
  GitBranch,
  Cloud,
  Globe,
  ShieldCheck,
} from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { RefreshButton, TableSkeleton } from '@/components/list-page-parts'
import { useUrlFilter } from '@/hooks/use-url-param'

import { AddScannerTemplateDialog } from './add-scanner-template-dialog'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  ErrorState,
  PageHeader,
  type RowAction,
  PageStack,
} from '@/features/shared'

import { Can, Permission } from '@/lib/permissions'
import {
  useScannerTemplates,
  useDeleteScannerTemplate,
  useDeprecateScannerTemplate,
  approveScannerTemplate,
  invalidateScannerTemplatesCache,
} from '@/lib/api/scanner-template-hooks'
import type {
  ScannerTemplate,
  TemplateType,
  TemplateStatus,
  SyncSource,
} from '@/lib/api/scanner-template-types'
import {
  TEMPLATE_TYPE_DISPLAY_NAMES,
  TEMPLATE_STATUS_DISPLAY_NAMES,
  TEMPLATE_TYPES,
  isManuallyUploadedTemplate,
} from '@/lib/api/scanner-template-types'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'
import { useSearchQuery } from '@/hooks/use-search-query'
import { formatDate } from '@/lib/app-locale'

function TemplateStatusBadge({ status }: { status: TemplateStatus }) {
  const { t } = useTranslation()
  const IconMap: Record<TemplateStatus, React.ElementType> = {
    active: CheckCircle,
    pending_review: FileWarning,
    deprecated: Archive,
    revoked: XCircle,
  }
  const Icon = IconMap[status]

  // Only a revoked template is a problem worth colour; the icon carries the rest.
  return (
    <Badge variant={status === 'revoked' ? 'destructive' : 'outline'} className="gap-1">
      <Icon className="h-3 w-3" />
      {t(`scans.templates.status.${status}`, TEMPLATE_STATUS_DISPLAY_NAMES[status])}
    </Badge>
  )
}

function TemplateSourceBadge({ template }: { template: ScannerTemplate }) {
  const { t } = useTranslation()
  const isManual = isManuallyUploadedTemplate(template)
  const syncSource = template.sync_source || (isManual ? 'manual' : undefined)

  const sourceConfig: Record<SyncSource, { icon: React.ElementType; label: string }> = {
    manual: { icon: Upload, label: t('scans.templates.source.uploaded', 'Uploaded') },
    git: { icon: GitBranch, label: 'Git' },
    s3: { icon: Cloud, label: 'S3' },
    http: { icon: Globe, label: 'HTTP' },
  }

  const config = syncSource ? sourceConfig[syncSource] : sourceConfig.manual
  const Icon = config.icon

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant="outline" className="gap-1">
          <Icon className="h-3 w-3" />
          {config.label}
        </Badge>
      </TooltipTrigger>
      <TooltipContent>
        {isManual ? (
          <p>{t('scans.templates.uploaded', 'Uploaded here')}</p>
        ) : (
          <p>
            {template.source_path
              ? t('scans.templates.source.syncedFromPath', 'Synced from {source} source: {path}', {
                  source: config.label,
                  path: template.source_path,
                })
              : t('scans.templates.source.syncedFrom', 'Synced from {source} source', {
                  source: config.label,
                })}
          </p>
        )}
      </TooltipContent>
    </Tooltip>
  )
}

export function ScannerTemplatesSection() {
  const { t } = useTranslation()
  // Dialog states
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [deprecateDialogOpen, setDeprecateDialogOpen] = useState(false)

  // Selected template for dialogs
  const [selectedTemplate, setSelectedTemplate] = useState<ScannerTemplate | null>(null)

  // Filter states
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const searchTerm = useSearchQuery(searchQuery).term
  const [typeParam, setTypeFilter] = useUrlFilter('type', 'all')
  const [statusParam, setStatusFilter] = useUrlFilter('status', 'all')
  const typeFilter = typeParam as TemplateType | 'all'
  const statusFilter = statusParam as TemplateStatus | 'all'
  const anyFilter = !!searchQuery || typeFilter !== 'all' || statusFilter !== 'all'

  // API data
  const filters = useMemo(
    () => ({
      template_type: typeFilter !== 'all' ? typeFilter : undefined,
      status: statusFilter !== 'all' ? statusFilter : undefined,
      search: searchTerm || undefined,
      per_page: 100,
    }),
    [typeFilter, statusFilter, searchTerm]
  )

  const { data: templatesData, error, isLoading, mutate } = useScannerTemplates(filters)
  const templates: ScannerTemplate[] = useMemo(
    () => templatesData?.items ?? [],
    [templatesData?.items]
  )

  // Usage/quota data

  // Mutations
  const { trigger: deleteTemplate, isMutating: isDeleting } = useDeleteScannerTemplate(
    selectedTemplate?.id || ''
  )
  const { trigger: deprecateTemplate, isMutating: isDeprecating } = useDeprecateScannerTemplate(
    selectedTemplate?.id || ''
  )

  // Handlers
  const handleRefresh = useCallback(async () => {
    await invalidateScannerTemplatesCache()
    await mutate()
    toast.success(t('scans.templates.refreshed', 'Templates refreshed'))
  }, [mutate, t])

  const handleDeleteClick = useCallback((template: ScannerTemplate) => {
    setSelectedTemplate(template)
    setDeleteDialogOpen(true)
  }, [])

  const handleDeleteConfirm = useCallback(async () => {
    if (!selectedTemplate) return
    try {
      await deleteTemplate()
      toast.success(
        t('scans.templates.deleted', 'Template "{name}" deleted', { name: selectedTemplate.name })
      )
      await invalidateScannerTemplatesCache()
      setDeleteDialogOpen(false)
      setSelectedTemplate(null)
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('scans.templates.deleteFailed', 'Failed to delete template'))
      )
    }
  }, [selectedTemplate, deleteTemplate, t])

  const handleDeprecateClick = useCallback((template: ScannerTemplate) => {
    setSelectedTemplate(template)
    setDeprecateDialogOpen(true)
  }, [])

  const handleDeprecateConfirm = useCallback(async () => {
    if (!selectedTemplate) return
    try {
      await deprecateTemplate()
      toast.success(
        t('scans.templates.deprecated', 'Template "{name}" deprecated', {
          name: selectedTemplate.name,
        })
      )
      await invalidateScannerTemplatesCache()
      setDeprecateDialogOpen(false)
      setSelectedTemplate(null)
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('scans.templates.deprecateFailed', 'Failed to deprecate template'))
      )
    }
  }, [selectedTemplate, deprecateTemplate, t])

  // Approving a version for sensors: once the organization's approval count
  // is reached, the job signer records it and sensors may run it.
  // Approving lets every sensor of the organization run the template (the
  // server asks for a recent sign-in), so it is confirmed first.
  const [approveTarget, setApproveTarget] = useState<ScannerTemplate | null>(null)
  const handleApproveClick = useCallback((template: ScannerTemplate) => {
    setApproveTarget(template)
  }, [])
  const handleApproveConfirm = useCallback(async () => {
    const template = approveTarget
    setApproveTarget(null)
    if (!template) return
    try {
      const updated = await approveScannerTemplate(template.id)
      toast.success(
        updated?.sensor_approval?.approved
          ? t('scans.templates.approved', undefined, { name: template.name })
          : t('scans.templates.approvalRecorded', undefined, { name: template.name })
      )
      await invalidateScannerTemplatesCache()
    } catch (err) {
      toast.error(getErrorMessage(err, t('scans.templates.approveFailed')))
    }
  }, [approveTarget, t])

  const handleDownload = useCallback(
    async (template: ScannerTemplate) => {
      try {
        const response = await fetch(`/api/v1/scanner-templates/${template.id}/download`)
        if (!response.ok) throw new Error('Failed to download')
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = template.name
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
        toast.success(
          t('scans.templates.downloaded', 'Downloaded "{name}"', { name: template.name })
        )
      } catch (err) {
        toast.error(
          getErrorMessage(err, t('scans.templates.downloadFailed', 'Failed to download template'))
        )
      }
    },
    [t]
  )

  const columns = useMemo<ColumnDef<ScannerTemplate>[]>(
    () => [
      {
        id: 'name',
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scans.templates.col.template', 'Template')}
          />
        ),
        cell: ({ row }) => {
          const template = row.original
          return (
            <div className="min-w-0">
              <div className="truncate font-medium">{template.name}</div>
              {template.description && (
                <p
                  className="max-w-xs truncate text-sm text-muted-foreground"
                  title={template.description}
                >
                  {template.description}
                </p>
              )}
            </div>
          )
        },
      },
      {
        id: 'type',
        accessorFn: (t) => TEMPLATE_TYPE_DISPLAY_NAMES[t.template_type],
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.templates.col.type', 'Type')} />
        ),
        cell: ({ getValue }) => <Badge variant="outline">{getValue<string>()}</Badge>,
      },
      {
        id: 'source',
        enableSorting: false,
        header: t('scans.templates.col.source', 'Source'),
        cell: ({ row }) => <TemplateSourceBadge template={row.original} />,
      },
      {
        id: 'rules',
        accessorKey: 'rule_count',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.templates.col.rules', 'Rules')} />
        ),
        cell: ({ row }) => (
          <span className="text-sm tabular-nums text-muted-foreground">
            {row.original.rule_count === 1
              ? t('scans.templates.ruleOne', '{count} rule', { count: row.original.rule_count })
              : t('scans.templates.ruleMany', '{count} rules', { count: row.original.rule_count })}
          </span>
        ),
      },
      {
        id: 'version',
        accessorKey: 'version',
        header: t('scans.templates.col.version', 'Version'),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-xs tabular-nums text-muted-foreground">
            v{row.original.version}
          </span>
        ),
      },
      {
        id: 'status',
        accessorKey: 'status',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scans.templates.col.status', 'Status')}
          />
        ),
        cell: ({ row }) => {
          const approval = row.original.sensor_approval
          const awaiting = row.original.status === 'active' && approval && !approval.approved
          return (
            <div className="flex flex-wrap items-center gap-1.5">
              <TemplateStatusBadge status={row.original.status} />
              {awaiting && (
                <Badge
                  variant="outline"
                  className="text-xs font-normal"
                  title={t(
                    'scans.templates.awaitingHint',
                    'Sensors refuse this version until it is approved for sensors'
                  )}
                >
                  {t('scans.templates.awaiting', 'Awaiting approval {done}/{needed}', {
                    done: approval.approvals.length,
                    needed: Math.max(approval.approvals_required, 1),
                  })}
                </Badge>
              )}
            </div>
          )
        },
      },
      {
        id: 'updated',
        accessorKey: 'updated_at',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scans.templates.col.updated', 'Updated')}
          />
        ),
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {formatDate(new Date(row.original.updated_at))}
          </span>
        ),
      },
      {
        id: 'actions',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const template = row.original
          return (
            <DataTableRowActions
              title={template.name}
              label={t('common.rowActions.actionsFor', 'Actions for {name}', {
                name: template.name,
              })}
              actions={[
                {
                  label: t('scans.templates.row.download'),
                  icon: Download,
                  onClick: () => handleDownload(template),
                },
                ...(template.status === 'active' &&
                template.sensor_approval &&
                !template.sensor_approval.approved
                  ? ([
                      {
                        label: t('scans.templates.row.approve'),
                        icon: ShieldCheck,
                        onClick: () => handleApproveClick(template),
                        permission: Permission.ScopeApprove,
                      },
                    ] satisfies RowAction[])
                  : []),
                ...(template.status === 'active'
                  ? ([
                      {
                        label: t('scans.templates.row.deprecate'),
                        icon: Archive,
                        onClick: () => handleDeprecateClick(template),
                        permission: Permission.ScannerTemplatesWrite,
                      },
                    ] satisfies RowAction[])
                  : []),
                {
                  label: t('scans.templates.row.delete'),
                  icon: Trash2,
                  onClick: () => handleDeleteClick(template),
                  destructive: true,
                  separatorBefore: true,
                  permission: Permission.ScannerTemplatesDelete,
                },
              ]}
            />
          )
        },
      },
    ],
    [handleDownload, handleDeprecateClick, handleDeleteClick, handleApproveClick, t]
  )

  // Search and filters are applied by the API, so the table gets its own
  // server-backed search box instead of its built-in client filter.
  const toolbarStart = (
    <>
      <Select value={typeFilter} onValueChange={setTypeFilter}>
        <SelectTrigger
          className="w-[140px]"
          aria-label={t('scans.templates.filter.type', 'Template type')}
        >
          <SelectValue placeholder={t('scans.templates.filter.allTypes', 'All types')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">{t('scans.templates.filter.allTypes', 'All types')}</SelectItem>
          {TEMPLATE_TYPES.map((type) => (
            <SelectItem key={type} value={type}>
              {TEMPLATE_TYPE_DISPLAY_NAMES[type]}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select value={statusFilter} onValueChange={setStatusFilter}>
        <SelectTrigger className="w-[150px]" aria-label={t('scans.templates.col.status', 'Status')}>
          <SelectValue placeholder={t('scans.templates.filter.allStatuses', 'All statuses')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">
            {t('scans.templates.filter.allStatuses', 'All statuses')}
          </SelectItem>
          <SelectItem value="active">{t('scans.templates.status.active', 'Active')}</SelectItem>
          <SelectItem value="pending_review">
            {t('scans.templates.status.pending_review', 'Pending review')}
          </SelectItem>
          <SelectItem value="deprecated">
            {t('scans.templates.status.deprecated', 'Deprecated')}
          </SelectItem>
          <SelectItem value="revoked">{t('scans.templates.status.revoked', 'Revoked')}</SelectItem>
        </SelectContent>
      </Select>
    </>
  )

  let body: React.ReactNode
  if (error) {
    body = (
      <ErrorState
        title={t('scans.templates.errorTitle', 'scanner templates')}
        error={error}
        onRetry={handleRefresh}
      />
    )
  } else if (isLoading && !anyFilter) {
    body = <TableSkeleton rows={4} />
  } else if (!isLoading && templates.length === 0 && !anyFilter) {
    body = (
      <EmptyState
        icon={FileCode2}
        title={t('scans.templates.empty.title', 'No scanner templates')}
        description={t(
          'scans.templates.empty.description',
          'Upload custom templates for Nuclei, Semgrep, or Betterleaks scanners.'
        )}
        action={
          <Can permission={Permission.ScannerTemplatesWrite}>
            <Button size="sm" onClick={() => setAddDialogOpen(true)}>
              <Plus className="h-4 w-4" />
              {t('scans.templates.upload', 'Upload template')}
            </Button>
          </Can>
        }
      />
    )
  } else {
    // While a filter change is in flight the toolbar stays mounted (the search
    // box keeps focus); only the rows wait.
    body = (
      <DataTable
        columns={columns}
        data={templates}
        getRowId={(t) => t.id}
        showSearch={false}
        search={{
          value: searchQuery,
          onChange: setSearchQuery,
          placeholder: t('scans.templates.search.placeholder', 'Search templates…'),
          label: t('scans.templates.search.label', 'Search templates'),
        }}
        toolbarStart={toolbarStart}
        toolbarEnd={<RefreshButton onClick={handleRefresh} loading={isLoading} />}
        emptyMessage={
          isLoading
            ? t('scans.templates.loading', 'Loading templates…')
            : t('scans.templates.noMatch', 'No templates match these filters')
        }
      />
    )
  }

  return (
    <PageStack>
      <PageHeader
        title={t('scans.templates.title', 'Scanner templates')}
        description={t(
          'scans.templates.description',
          'Custom Nuclei, Semgrep and Betterleaks templates, uploaded here or synced from template sources.'
        )}
      >
        <Can permission={Permission.ScannerTemplatesWrite}>
          <Button size="sm" onClick={() => setAddDialogOpen(true)}>
            <Plus className="h-4 w-4" />
            {t('scans.templates.upload', 'Upload template')}
          </Button>
        </Can>
      </PageHeader>

      {body}

      {/* Dialogs */}
      <AddScannerTemplateDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
        onSuccess={handleRefresh}
      />

      <ConfirmDialog
        open={approveTarget !== null}
        onOpenChange={(open) => !open && setApproveTarget(null)}
        title={t('confirm.scannerTemplate.approveTitle', undefined, {
          name: approveTarget?.name ?? '',
        })}
        desc={t('confirm.scannerTemplate.approveDesc')}
        confirmText={t('confirm.scannerTemplate.approveBtn')}
        handleConfirm={handleApproveConfirm}
      />

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title={t('confirm.scannerTemplate.deleteTitle', 'Delete the scanner template {name}?', {
          name: selectedTemplate?.name ?? '',
        })}
        desc={t(
          'confirm.scannerTemplate.deleteDesc',
          'It can no longer be chosen for scans. To only stop new scans from using it, deprecate it instead. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        isLoading={isDeleting}
        handleConfirm={handleDeleteConfirm}
      />

      {/* Deprecate Confirmation */}
      <ConfirmDialog
        open={deprecateDialogOpen}
        onOpenChange={setDeprecateDialogOpen}
        title={t(
          'confirm.scannerTemplate.deprecateTitle',
          'Deprecate the scanner template {name}?',
          {
            name: selectedTemplate?.name ?? '',
          }
        )}
        desc={t(
          'confirm.scannerTemplate.deprecateDesc',
          'Deprecated templates cannot be used in new scans.'
        )}
        confirmText={
          <>
            {isDeprecating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('confirm.scannerTemplate.deprecate', 'Deprecate')}
          </>
        }
        isLoading={isDeprecating}
        handleConfirm={handleDeprecateConfirm}
      />
    </PageStack>
  )
}
