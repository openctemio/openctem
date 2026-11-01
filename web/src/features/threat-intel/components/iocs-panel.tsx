'use client'

/**
 * IOCs (Indicators of Compromise) management tab.
 *
 * Backed by /api/v1/iocs (list/create/get/delete — delete soft-deactivates,
 * no update endpoint). Read gated by threat_intel:read, create/delete by
 * threat_intel:write. The list endpoint has no server-side type/status filter
 * and returns no total, so both filters are applied client-side over the
 * fetched page; they live in the URL (?ioc_type=, ?ioc_status=) so a filtered
 * view is linkable.
 */

import { useMemo, useState } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { Plus, Eye, Trash2, ShieldAlert, Loader2, AlertCircle, RefreshCw, Copy } from 'lucide-react'
import { toast } from 'sonner'

import {
  PageHeader,
  PageStack,
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  type DetailMenuItem,
} from '@/features/shared'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import { Can, Permission, usePermissions } from '@/lib/permissions'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
import { getErrorMessage } from '@/lib/api/error-handler'
import { useUrlFilter } from '@/hooks/use-url-param'
import {
  useIOCs,
  useCreateIOC,
  useDeleteIOC,
  useIOCMatches,
  IOC_TYPES,
  iocTypeLabel,
  IOC_SOURCES,
  iocSourceLabel,
  type IOC,
  type IOCType,
  type IOCSource,
  type CreateIOCInput,
} from '../api/use-iocs-api'
import { useTranslation } from '@/context/i18n-provider'

const ALL = 'all'

function formatDate(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString()
}

function formatDateTime(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

export function IOCsPanel() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.ThreatIntelRead)

  const { data, error, isLoading, mutate } = useIOCs(canRead ? { limit: 200 } : undefined)
  const [typeFilter, setTypeFilter] = useUrlFilter('ioc_type', ALL)
  const [statusFilter, setStatusFilter] = useUrlFilter('ioc_status', ALL)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<IOC | null>(null)

  const iocs = useMemo(() => {
    let rows = data?.items ?? []
    if (typeFilter !== ALL) rows = rows.filter((i) => i.type === typeFilter)
    if (statusFilter !== ALL) {
      const wantActive = statusFilter === 'active'
      rows = rows.filter((i) => i.active === wantActive)
    }
    return rows
  }, [data, typeFilter, statusFilter])

  const selected = useMemo(
    () => (data?.items ?? []).find((i) => i.id === selectedId) ?? null,
    [data, selectedId]
  )

  const columns = useMemo<ColumnDef<IOC>[]>(
    () => [
      {
        accessorKey: 'value',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('threatIntel.iocs.col.value', 'Value')} />
        ),
        cell: ({ row }) => (
          <span className="font-mono text-xs break-all">{row.original.value}</span>
        ),
      },
      {
        accessorKey: 'type',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('threatIntel.iocs.col.type', 'Type')} />
        ),
        cell: ({ row }) => <Badge variant="outline">{iocTypeLabel(t, row.original.type)}</Badge>,
      },
      {
        accessorKey: 'source',
        header: t('threatIntel.iocs.col.source', 'Source'),
        cell: ({ row }) =>
          row.original.source ? (
            <Badge variant="secondary">{iocSourceLabel(t, row.original.source)}</Badge>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
      },
      {
        accessorKey: 'confidence',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('threatIntel.iocs.col.confidence', 'Confidence')}
          />
        ),
        cell: ({ row }) => <span className="tabular-nums text-sm">{row.original.confidence}%</span>,
      },
      {
        accessorKey: 'active',
        header: t('threatIntel.iocs.col.status', 'Status'),
        cell: ({ row }) => (
          <Badge variant={row.original.active ? 'default' : 'outline'}>
            {row.original.active
              ? t('threatIntel.iocs.active', 'Active')
              : t('threatIntel.iocs.inactive', 'Inactive')}
          </Badge>
        ),
      },
      {
        accessorKey: 'last_seen_at',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('threatIntel.iocs.col.lastSeen', 'Last seen')}
          />
        ),
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {formatDate(row.original.last_seen_at)}
          </span>
        ),
      },
      {
        id: 'actions',
        cell: ({ row }) => (
          <DataTableRowActions
            actions={[
              {
                label: t('threatIntel.iocs.viewDetails', 'View details'),
                icon: Eye,
                onClick: () => setSelectedId(row.original.id),
              },
              {
                label: t('confirm.ioc.menu', 'Deactivate'),
                icon: Trash2,
                destructive: true,
                separatorBefore: true,
                permission: Permission.ThreatIntelWrite,
                onClick: () => setDeleteTarget(row.original),
              },
            ]}
          />
        ),
      },
    ],
    [t]
  )

  if (!canRead) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title={t('threatIntel.iocs.noAccessTitle', 'No access to indicators')}
        description={t(
          'threatIntel.iocs.noAccessDescription',
          'You need the View Threat Intel permission to see the IOC catalogue.'
        )}
      />
    )
  }

  const filterSelects = (
    <>
      <Select value={typeFilter} onValueChange={setTypeFilter}>
        <SelectTrigger
          className="h-9 w-36"
          aria-label={t('threatIntel.iocs.filterType', 'Filter by type')}
        >
          <SelectValue placeholder={t('threatIntel.iocs.allTypes', 'All types')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>{t('threatIntel.iocs.allTypes', 'All types')}</SelectItem>
          {IOC_TYPES.map((ty) => (
            <SelectItem key={ty} value={ty}>
              {iocTypeLabel(t, ty)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select value={statusFilter} onValueChange={setStatusFilter}>
        <SelectTrigger
          className="h-9 w-36"
          aria-label={t('threatIntel.iocs.filterStatus', 'Filter by status')}
        >
          <SelectValue placeholder={t('threatIntel.iocs.allStatuses', 'All statuses')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>{t('threatIntel.iocs.allStatuses', 'All statuses')}</SelectItem>
          <SelectItem value="active">{t('threatIntel.iocs.active', 'Active')}</SelectItem>
          <SelectItem value="inactive">{t('threatIntel.iocs.inactive', 'Inactive')}</SelectItem>
        </SelectContent>
      </Select>
    </>
  )

  return (
    <PageStack>
      <PageHeader
        title={t('threatIntel.iocs.title', 'Indicators of compromise')}
        description={t(
          'threatIntel.iocs.description',
          'Indicators correlated against runtime telemetry to reopen the findings they belong to.'
        )}
      >
        <Can permission={Permission.ThreatIntelWrite} mode="disable">
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4 sm:me-2" />
            <span className="sr-only sm:not-sr-only">{t('threatIntel.iocs.add', 'Add IOC')}</span>
          </Button>
        </Can>
      </PageHeader>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : error ? (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>{t('threatIntel.iocs.loadFailed', 'Failed to load indicators')}</AlertTitle>
          <AlertDescription>
            <p>{getErrorMessage(error, t('threatIntel.iocs.tryAgain', 'Please try again.'))}</p>
            <Button variant="outline" size="sm" className="mt-2" onClick={() => mutate()}>
              <RefreshCw className="me-2 h-4 w-4" />
              {t('threatIntel.iocs.retry', 'Retry')}
            </Button>
          </AlertDescription>
        </Alert>
      ) : (
        <DataTable
          columns={columns}
          data={iocs}
          searchPlaceholder={t('threatIntel.iocs.search', 'Search indicators…')}
          emptyMessage={t('threatIntel.iocs.emptyTitle', 'No indicators')}
          emptyDescription={t(
            'threatIntel.iocs.emptyDescription',
            'Add an indicator of compromise to start correlating runtime telemetry.'
          )}
          onRowClick={(row) => setSelectedId(row.id)}
          toolbarEnd={filterSelects}
        />
      )}

      <IOCDetailSheet
        ioc={selected}
        open={!!selected}
        onOpenChange={(open) => !open && setSelectedId(null)}
        onDelete={(i) => {
          setSelectedId(null)
          setDeleteTarget(i)
        }}
      />

      <CreateIOCDialog open={createOpen} onOpenChange={setCreateOpen} onCreated={() => mutate()} />

      <DeleteIOCConfirm
        ioc={deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        onDeleted={() => {
          setDeleteTarget(null)
          mutate()
        }}
      />
    </PageStack>
  )
}

// ── Detail sheet ────────────────────────────────────────────────────────────
function IOCDetailSheet({
  ioc,
  open,
  onOpenChange,
  onDelete,
}: {
  ioc: IOC | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onDelete: (ioc: IOC) => void
}) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canWrite = can(Permission.ThreatIntelWrite)
  if (!ioc) return null

  const typeLabel = iocTypeLabel(t, ioc.type)
  const menu: DetailMenuItem[] = [
    {
      label: t('threatIntel.iocs.copyValue', 'Copy value'),
      icon: Copy,
      onSelect: () => {
        copyToClipboard(ioc.value)
        toast.success(t('threatIntel.iocs.copied', 'Indicator copied to clipboard'))
      },
    },
  ]
  if (canWrite) {
    menu.push({
      label: t('threatIntel.iocs.deleteIndicator', 'Delete indicator'),
      icon: Trash2,
      destructive: true,
      separatorBefore: true,
      onSelect: () => onDelete(ioc),
    })
  }

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      width="lg"
      header={
        <DetailHeader
          title={<span className="font-mono break-all">{ioc.value}</span>}
          badges={
            <>
              <Badge variant="outline" className="text-xs">
                {typeLabel}
              </Badge>
              <Badge
                variant="outline"
                className={cn(
                  'text-xs',
                  ioc.active && 'border-success/30 bg-success/10 text-success'
                )}
              >
                {ioc.active
                  ? t('threatIntel.iocs.active', 'Active')
                  : t('threatIntel.iocs.inactive', 'Inactive')}
              </Badge>
              {ioc.source && (
                <Badge variant="secondary" className="text-xs">
                  {iocSourceLabel(t, ioc.source)}
                </Badge>
              )}
            </>
          }
          meta={[
            t('threatIntel.iocs.detail.confidenceMeta', '{n}% confidence', { n: ioc.confidence }),
            t('threatIntel.iocs.detail.lastSeenMeta', 'Last seen {date}', {
              date: formatDate(ioc.last_seen_at),
            }),
          ]}
          menu={menu}
          onClose={() => onOpenChange(false)}
        />
      }
    >
      <DetailSections>
        <DetailSection title={t('threatIntel.iocs.detail.indicator', 'Indicator')}>
          <DetailFieldGrid>
            <DetailField label={t('threatIntel.iocs.detail.type', 'Type')}>{typeLabel}</DetailField>
            <DetailField label={t('threatIntel.iocs.detail.confidence', 'Confidence')}>
              {ioc.confidence}%
            </DetailField>
            <DetailField label={t('threatIntel.iocs.detail.normalized', 'Normalized')} full>
              <span className="font-mono text-xs break-all">{ioc.normalized}</span>
            </DetailField>
            {ioc.source_finding_id && (
              <DetailField
                label={t('threatIntel.iocs.detail.sourceFinding', 'Source finding')}
                full
              >
                <Link
                  href={`/findings/${ioc.source_finding_id}`}
                  className="font-mono text-xs break-all text-primary hover:underline"
                >
                  {ioc.source_finding_id}
                </Link>
              </DetailField>
            )}
            <DetailField label={t('threatIntel.iocs.detail.firstSeen', 'First seen')}>
              {formatDate(ioc.first_seen_at)}
            </DetailField>
            <DetailField label={t('threatIntel.iocs.detail.lastSeen', 'Last seen')}>
              {formatDate(ioc.last_seen_at)}
            </DetailField>
          </DetailFieldGrid>
        </DetailSection>

        <IOCMatchesSection iocId={ioc.id} />
      </DetailSections>
    </DetailSheet>
  )
}

// ── Matches (runtime-reopen signal) ─────────────────────────────────────────
// The whole point of the IOC catalogue: which runtime telemetry hits matched
// this indicator, and which findings that reopened (invariant B6). Backed by
// GET /iocs/{id}/matches. Degrades to a neutral empty state on error, so a
// deployment where that endpoint isn't live yet reads as "no matches" rather
// than an error.
function IOCMatchesSection({ iocId }: { iocId: string }) {
  const { t } = useTranslation()
  const { data, isLoading } = useIOCMatches(iocId)
  const matches = data?.items ?? []

  return (
    <DetailSection
      title={t('threatIntel.iocs.matches.title', 'Runtime matches')}
      count={isLoading ? undefined : matches.length}
    >
      {isLoading ? (
        <Skeleton className="h-12 w-full" />
      ) : matches.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t(
            'threatIntel.iocs.matches.empty',
            'No runtime telemetry has matched this indicator yet.'
          )}
        </p>
      ) : (
        <ul className="divide-y rounded-lg border">
          {matches.map((m) => (
            <li key={m.id} className="px-3 py-2.5 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">{formatDateTime(m.matched_at)}</span>
                {m.reopened && (
                  <Badge
                    variant="outline"
                    className="border-destructive/30 bg-destructive/10 text-xs text-destructive"
                  >
                    {t('threatIntel.iocs.matches.reopened', 'Reopened finding')}
                  </Badge>
                )}
              </div>
              {m.finding_id && (
                <Link
                  href={`/findings/${m.finding_id}`}
                  className="mt-1 inline-block break-all text-primary hover:underline"
                >
                  {m.finding_title || m.finding_id}
                </Link>
              )}
            </li>
          ))}
        </ul>
      )}
    </DetailSection>
  )
}

// ── Create dialog ───────────────────────────────────────────────────────────
function CreateIOCDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: () => void
}) {
  const { t } = useTranslation()
  const { trigger } = useCreateIOC()
  const [submitting, setSubmitting] = useState(false)
  const [type, setType] = useState<IOCType>('ip')
  const [value, setValue] = useState('')
  const [source, setSource] = useState<IOCSource>('manual')
  const [confidence, setConfidence] = useState('75')

  const reset = () => {
    setType('ip')
    setValue('')
    setSource('manual')
    setConfidence('75')
  }

  const handleSubmit = async () => {
    if (!value.trim()) {
      toast.error(t('threatIntel.iocs.create.valueRequired', 'Value is required'))
      return
    }
    const conf = Number(confidence)
    if (Number.isNaN(conf) || conf < 0 || conf > 100) {
      toast.error(
        t('threatIntel.iocs.create.confidenceRange', 'Confidence must be between 0 and 100')
      )
      return
    }
    const payload: CreateIOCInput = {
      type,
      value: value.trim(),
      source,
      confidence: conf,
    }
    setSubmitting(true)
    try {
      await trigger(payload)
      toast.success(t('threatIntel.iocs.create.added', 'Indicator added'))
      reset()
      onOpenChange(false)
      onCreated()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('threatIntel.iocs.create.addFailed', 'Failed to add indicator'))
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('threatIntel.iocs.create.title', 'Add indicator')}</DialogTitle>
          <DialogDescription>
            {t(
              'threatIntel.iocs.create.description',
              "Add an IOC to correlate against runtime telemetry. The value must match the selected type's format."
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="ioc-type">{t('threatIntel.iocs.create.type', 'Type')}</Label>
              <Select value={type} onValueChange={(v) => setType(v as IOCType)}>
                <SelectTrigger id="ioc-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {IOC_TYPES.map((ty) => (
                    <SelectItem key={ty} value={ty}>
                      {iocTypeLabel(t, ty)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="ioc-value">{t('threatIntel.iocs.create.value', 'Value *')}</Label>
              <Input
                id="ioc-value"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={t('threatIntel.iocs.create.valuePlaceholder', 'e.g. 203.0.113.10')}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="ioc-source">{t('threatIntel.iocs.create.source', 'Source')}</Label>
                <Select value={source} onValueChange={(v) => setSource(v as IOCSource)}>
                  <SelectTrigger id="ioc-source">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {IOC_SOURCES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {iocSourceLabel(t, s)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="ioc-confidence">
                  {t('threatIntel.iocs.create.confidence', 'Confidence (0-100)')}
                </Label>
                <Input
                  id="ioc-confidence"
                  type="number"
                  min={0}
                  max={100}
                  value={confidence}
                  onChange={(e) => setConfidence(e.target.value)}
                />
              </div>
            </div>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            {t('threatIntel.iocs.create.cancel', 'Cancel')}
          </Button>
          <Button onClick={handleSubmit} disabled={submitting}>
            {submitting && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('threatIntel.iocs.create.submit', 'Add IOC')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Delete confirm ──────────────────────────────────────────────────────────
function DeleteIOCConfirm({
  ioc,
  onOpenChange,
  onDeleted,
}: {
  ioc: IOC | null
  onOpenChange: (open: boolean) => void
  onDeleted: () => void
}) {
  const { t } = useTranslation()
  const { trigger } = useDeleteIOC(ioc?.id ?? '')
  const [deleting, setDeleting] = useState(false)

  const handleConfirm = async () => {
    if (!ioc) return
    setDeleting(true)
    try {
      await trigger()
      toast.success(t('confirm.ioc.deactivated', 'Indicator deactivated'))
      onDeleted()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('confirm.ioc.deactivateFailed', 'Failed to deactivate the indicator')
        )
      )
    } finally {
      setDeleting(false)
    }
  }

  return (
    <ConfirmDialog
      open={!!ioc}
      onOpenChange={onOpenChange}
      title={t('confirm.ioc.deleteTitle', 'Deactivate the indicator "{value}"?', {
        value: ioc?.value ?? '',
      })}
      desc={t(
        'confirm.ioc.deleteDesc',
        'It stops matching new findings and assets. Its match history is kept for the audit trail.'
      )}
      confirmText={
        deleting
          ? t('confirm.ioc.deactivating', 'Deactivating…')
          : t('confirm.ioc.deactivateButton', 'Deactivate indicator')
      }
      destructive
      handleConfirm={handleConfirm}
    />
  )
}
