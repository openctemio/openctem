'use client'

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Shield, Plus, Send, Trash2, Loader2, CheckCircle, XCircle } from 'lucide-react'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
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
import { ConfirmDialog } from '@/components/confirm-dialog'
import { toast } from 'sonner'
import { csrfFetch, del } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can } from '@/lib/permissions'
import {
  useNotificationIntegrationsApi,
  useCreateNotificationIntegrationApi,
  invalidateNotificationIntegrationsCache,
} from '@/features/integrations'
import { siemIntegrationsOnly } from '@/features/integrations/lib/integration-routing'
import type { Integration } from '@/features/integrations'
import {
  DataTable,
  DataTableRowActions,
  EmptyState,
  ErrorState,
  PageHeader,
  StackedCell,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'

const META = (i: Integration, k: string): string => {
  const v = i.metadata?.[k]
  return typeof v === 'string' ? v : ''
}

function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation()
  const ok = status === 'connected'
  return (
    <Badge variant={ok ? 'default' : 'secondary'} className="gap-1">
      {ok ? <CheckCircle className="size-3" /> : <XCircle className="size-3" />}
      {t(`siemIntegration.status.${status}`, status)}
    </Badge>
  )
}

export default function SIEMIntegrationPage() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useNotificationIntegrationsApi()
  const { trigger: createIntegration, isMutating: creating } = useCreateNotificationIntegrationApi()

  const splunkIntegrations = useMemo(() => siemIntegrationsOnly(data?.data ?? []), [data])

  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', hecUrl: '', token: '', index: '', sourcetype: '' })
  const [testingId, setTestingId] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Integration | null>(null)
  const [deleting, setDeleting] = useState(false)

  const resetForm = () => setForm({ name: '', hecUrl: '', token: '', index: '', sourcetype: '' })

  const handleCreate = useCallback(async () => {
    if (!form.name.trim() || !form.hecUrl.trim() || !form.token.trim()) {
      toast.error(
        t('siemIntegration.toast.required', 'Name, HEC endpoint URL, and HEC token are required')
      )
      return
    }
    try {
      await createIntegration({
        name: form.name.trim(),
        provider: 'splunk',
        auth_type: 'token',
        credentials: form.token.trim(),
        metadata: {
          hec_url: form.hecUrl.trim(),
          index: form.index.trim(),
          sourcetype: form.sourcetype.trim(),
        },
      })
      toast.success(t('siemIntegration.toast.created', 'Splunk HEC integration created'))
      resetForm()
      setShowForm(false)
      await invalidateNotificationIntegrationsCache()
      await mutate()
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }, [form, createIntegration, mutate, t])

  const handleTest = useCallback(
    async (integration: Integration) => {
      setTestingId(integration.id)
      try {
        const res = await csrfFetch(`/api/v1/integrations/${integration.id}/test-notification`, {
          method: 'POST',
        })
        if (res.ok) {
          toast.success(t('siemIntegration.toast.testDelivered', 'Test event delivered to Splunk'))
        } else {
          const body = await res.json().catch(() => ({}))
          toast.error(
            body?.error ||
              t('siemIntegration.toast.testFailed', 'Test failed (HTTP {status})', {
                status: res.status,
              })
          )
        }
        await mutate()
      } catch (err) {
        toast.error(getErrorMessage(err))
      } finally {
        setTestingId(null)
      }
    },
    [mutate, t]
  )

  const handleDelete = useCallback(async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      // apiClient path: a STEP_UP_REQUIRED answer opens the re-authentication dialog and retries.
      await del(`/api/v1/integrations/${deleteTarget.id}`)
      toast.success(t('siemIntegration.toast.deleted', 'Integration deleted'))
      setDeleteTarget(null)
      await invalidateNotificationIntegrationsCache()
      await mutate()
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setDeleting(false)
    }
  }, [deleteTarget, mutate, t])

  const endpointSummary = (integration: Integration) =>
    [
      META(integration, 'hec_url'),
      META(integration, 'index') &&
        t('siemIntegration.summary.index', 'index: {value}', { value: META(integration, 'index') }),
      META(integration, 'sourcetype') &&
        t('siemIntegration.summary.sourcetype', 'sourcetype: {value}', {
          value: META(integration, 'sourcetype'),
        }),
    ]
      .filter(Boolean)
      .join(' · ')

  const columns: ColumnDef<Integration>[] = [
    {
      accessorKey: 'name',
      header: t('siemIntegration.columns.name', 'Name'),
      cell: ({ row }) => (
        <StackedCell primary={row.original.name} secondary={row.original.status_message} truncate />
      ),
    },
    {
      id: 'endpoint',
      header: t('siemIntegration.columns.endpoint', 'HEC endpoint'),
      accessorFn: (i) => endpointSummary(i),
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">{endpointSummary(row.original)}</span>
      ),
    },
    {
      accessorKey: 'status',
      header: t('siemIntegration.columns.status', 'Status'),
      cell: ({ row }) => <StatusBadge status={row.original.status} />,
    },
    {
      id: 'actions',
      enableSorting: false,
      cell: ({ row }) => (
        <DataTableRowActions
          actions={[
            {
              label:
                testingId === row.original.id
                  ? t('siemIntegration.actions.sendingTest', 'Sending test…')
                  : t('siemIntegration.actions.sendTest', 'Send test event'),
              icon: Send,
              onClick: () => void handleTest(row.original),
              disabled: testingId === row.original.id,
              route: 'PUT /api/v1/integrations/{id}',
            },
            {
              label: t('siemIntegration.actions.delete', 'Delete'),
              icon: Trash2,
              onClick: () => setDeleteTarget(row.original),
              destructive: true,
              separatorBefore: true,
              route: 'PUT /api/v1/integrations/{id}',
            },
          ]}
        />
      ),
    },
  ]

  const closeForm = () => {
    setShowForm(false)
    resetForm()
  }

  return (
    <Main>
      <PageHeader
        title={t('siemIntegration.title', 'SIEM')}
        description={t(
          'siemIntegration.description',
          'Forward findings, exposures, scans and SLA breaches to Splunk through the HTTP Event Collector (HEC).'
        )}
      >
        <Can route="PUT /api/v1/integrations/{id}">
          <Button size="sm" onClick={() => setShowForm(true)}>
            <Plus className="me-2 h-4 w-4" />
            {t('siemIntegration.add', 'Add Splunk HEC')}
          </Button>
        </Can>
      </PageHeader>

      <div className="mt-5">
        {error ? (
          <ErrorState
            title={t('siemIntegration.errorTitle', 'SIEM integrations')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-9 w-full max-w-sm" />
            <Skeleton className="h-48 w-full" />
          </div>
        ) : splunkIntegrations.length === 0 ? (
          <EmptyState
            icon={Shield}
            title={t('siemIntegration.empty.title', 'No SIEM integrations yet')}
            description={t(
              'siemIntegration.empty.description',
              'Add a Splunk HTTP Event Collector to start forwarding security events to your SIEM.'
            )}
            action={
              <Can route="PUT /api/v1/integrations/{id}">
                <Button size="sm" onClick={() => setShowForm(true)}>
                  <Plus className="me-2 h-4 w-4" />
                  {t('siemIntegration.add', 'Add Splunk HEC')}
                </Button>
              </Can>
            }
          />
        ) : (
          <DataTable
            columns={columns}
            data={splunkIntegrations}
            getRowId={(i) => i.id}
            searchPlaceholder={t('siemIntegration.searchPlaceholder', 'Search integrations...')}
            showSelectionCount={false}
          />
        )}
      </div>

      <Dialog open={showForm} onOpenChange={(open) => (open ? setShowForm(true) : closeForm())}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('siemIntegration.form.title', 'New Splunk HEC integration')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'siemIntegration.form.description',
                'The HEC token is stored encrypted. The endpoint, index and sourcetype are non-sensitive routing config.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="siem-name">{t('siemIntegration.form.name', 'Name')}</Label>
                <Input
                  id="siem-name"
                  placeholder={t('siemIntegration.form.namePlaceholder', 'Production Splunk')}
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="siem-url">
                  {t('siemIntegration.form.url', 'HEC endpoint URL')}
                </Label>
                <Input
                  id="siem-url"
                  placeholder="https://splunk.example.com:8088"
                  value={form.hecUrl}
                  onChange={(e) => setForm({ ...form, hecUrl: e.target.value })}
                />
              </div>
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="siem-token">{t('siemIntegration.form.token', 'HEC token')}</Label>
                <Input
                  id="siem-token"
                  type="password"
                  placeholder="00000000-0000-0000-0000-000000000000"
                  value={form.token}
                  onChange={(e) => setForm({ ...form, token: e.target.value })}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="siem-index">
                  {t('siemIntegration.form.index', 'Index (optional)')}
                </Label>
                <Input
                  id="siem-index"
                  placeholder="main"
                  value={form.index}
                  onChange={(e) => setForm({ ...form, index: e.target.value })}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="siem-sourcetype">
                  {t('siemIntegration.form.sourcetype', 'Sourcetype (optional)')}
                </Label>
                <Input
                  id="siem-sourcetype"
                  placeholder="openctem:notification"
                  value={form.sourcetype}
                  onChange={(e) => setForm({ ...form, sourcetype: e.target.value })}
                />
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={closeForm}>
              {t('siemIntegration.form.cancel', 'Cancel')}
            </Button>
            <Button onClick={() => void handleCreate()} disabled={creating}>
              {creating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              {t('siemIntegration.form.create', 'Create integration')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title={t('confirm.siem.deleteTitle', 'Delete the SIEM integration "{name}"?', {
          name: deleteTarget?.name ?? '',
        })}
        desc={t(
          'confirm.siem.deleteDesc',
          'Events stop being forwarded to it at once and its settings are deleted. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        isLoading={deleting}
        handleConfirm={() => void handleDelete()}
      />
    </Main>
  )
}
