'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { AlertCircle, Plus, Pencil, Trash2, ShieldCheck, ShieldPlus, Timer } from 'lucide-react'

import { Main } from '@/components/layout'
import { PageHeader, DataTable, DataTableColumnHeader, EmptyState } from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Can, Permission } from '@/lib/permissions'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'

import { SlaPolicyDialog } from '@/features/sla/components/sla-policy-dialog'
import { SlaWindows } from '@/features/sla/components/sla-windows'
import {
  useSlaPoliciesApi,
  useDeleteSlaPolicy,
  useUpdateSlaPolicy,
  invalidateSlaPoliciesCache,
  type SlaPolicy,
} from '@/features/sla/api/use-sla-policies-api'
import { useTranslation } from '@/context/i18n-provider'

export default function SlaPoliciesPage() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useSlaPoliciesApi()
  const policies = useMemo(() => data?.data ?? [], [data])
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<SlaPolicy | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<SlaPolicy | null>(null)
  const [defaultTarget, setDefaultTarget] = useState<SlaPolicy | null>(null)

  const { trigger: deletePolicy, isMutating: isDeleting } = useDeleteSlaPolicy()
  const { trigger: updatePolicy, isMutating: isSettingDefault } = useUpdateSlaPolicy()

  const openCreate = () => {
    setEditing(null)
    setDialogOpen(true)
  }
  const openEdit = (policy: SlaPolicy) => {
    setEditing(policy)
    setDialogOpen(true)
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await deletePolicy({ id: deleteTarget.id })
      toast.success(
        t('settings.slaPolicies.page.deleted', 'Policy "{name}" deleted', {
          name: deleteTarget.name,
        })
      )
      await invalidateSlaPoliciesCache()
      setDeleteTarget(null)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('settings.slaPolicies.page.deleteFailed', 'Failed to delete SLA policy')
        )
      )
    }
  }

  const handleMakeDefault = async () => {
    if (!defaultTarget) return
    try {
      await updatePolicy({ id: defaultTarget.id, is_default: true })
      toast.success(
        t('settings.slaPolicies.page.defaultDone', '"{name}" is now the default policy', {
          name: defaultTarget.name,
        })
      )
      await invalidateSlaPoliciesCache()
      setDefaultTarget(null)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('settings.slaPolicies.page.defaultFailed', 'Failed to change the default policy')
        )
      )
    }
  }

  const columns = useMemo<ColumnDef<SlaPolicy>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('settings.slaPolicies.page.colPolicy', 'Policy')}
          />
        ),
        cell: ({ row }) => {
          const p = row.original
          return (
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-2">
                <span className="font-medium">{p.name}</span>
                {p.is_default && (
                  <Badge variant="secondary" className="gap-1">
                    <ShieldCheck className="h-3 w-3" />
                    {t('settings.slaPolicies.page.badgeDefault', 'Default')}
                  </Badge>
                )}
                {p.asset_id && (
                  <Badge variant="outline" className="text-xs">
                    {t('settings.slaPolicies.page.badgeAsset', 'Asset override')}
                  </Badge>
                )}
                {!p.is_default && !p.asset_id && (
                  <Badge
                    variant="outline"
                    className="text-xs text-muted-foreground"
                    title={t(
                      'settings.slaPolicies.page.badgeNotAppliedHint',
                      'Only the default policy applies to findings. Make this the default to use it.'
                    )}
                  >
                    {t('settings.slaPolicies.page.badgeNotApplied', 'Not applied')}
                  </Badge>
                )}
              </div>
              {p.description && (
                <span className="text-xs text-muted-foreground line-clamp-1">{p.description}</span>
              )}
            </div>
          )
        },
      },
      {
        id: 'windows',
        header: t('settings.slaPolicies.page.colWindows', 'Remediation windows'),
        enableSorting: false,
        cell: ({ row }) => <SlaWindows policy={row.original} />,
      },
      {
        accessorKey: 'warning_threshold_pct',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('settings.slaPolicies.page.colWarning', 'Warning at')}
          />
        ),
        cell: ({ row }) => (
          <span className="tabular-nums">{row.original.warning_threshold_pct}%</span>
        ),
      },
      {
        accessorKey: 'escalation_enabled',
        header: t('settings.slaPolicies.page.colNotifications', 'Notifications'),
        cell: ({ row }) =>
          row.original.escalation_enabled ? (
            <Badge variant="outline">{t('settings.slaPolicies.page.on', 'On')}</Badge>
          ) : (
            <span className="text-muted-foreground text-sm">
              {t('settings.slaPolicies.page.off', 'Off')}
            </span>
          ),
      },
      {
        id: 'actions',
        header: () => (
          <span className="sr-only">{t('settings.slaPolicies.page.colActions', 'Actions')}</span>
        ),
        enableSorting: false,
        cell: ({ row }) => {
          const p = row.original
          return (
            <div className="flex items-center justify-end gap-1">
              <Can permission={Permission.SLAWrite}>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  aria-label={t('settings.slaPolicies.page.edit', 'Edit {name}', { name: p.name })}
                  onClick={() => openEdit(p)}
                >
                  <Pencil className="h-4 w-4" />
                </Button>
              </Can>
              {!p.is_default && !p.asset_id && p.is_active && (
                <Can permission={Permission.SLAWrite}>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    aria-label={t(
                      'settings.slaPolicies.page.makeDefault',
                      'Make {name} the default',
                      { name: p.name }
                    )}
                    onClick={() => setDefaultTarget(p)}
                  >
                    <ShieldPlus className="h-4 w-4" />
                  </Button>
                </Can>
              )}
              {/* The server refuses to delete the default policy: show why. */}
              <Can permission={Permission.SLADelete}>
                <span
                  title={
                    p.is_default
                      ? t(
                          'settings.slaPolicies.page.defaultNoDelete',
                          'The default policy cannot be deleted. Make another policy the default first.'
                        )
                      : undefined
                  }
                >
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-destructive"
                    aria-label={t('settings.slaPolicies.page.delete', 'Delete {name}', {
                      name: p.name,
                    })}
                    disabled={p.is_default}
                    onClick={() => setDeleteTarget(p)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </span>
              </Can>
            </div>
          )
        },
      },
    ],
    [t]
  )

  return (
    <Main>
      <PageHeader
        title={t('settings.slaPolicies.title', 'SLA policies')}
        description={t(
          'settings.slaPolicies.description',
          'Remediation windows per priority class (P0–P3), and per severity for findings without a class.'
        )}
      >
        {!isLoading && !error && (
          <Can permission={Permission.SLAWrite}>
            <Button size="sm" onClick={openCreate}>
              <Plus className="h-4 w-4" />
              {t('settings.slaPolicies.page.newPolicy', 'New policy')}
            </Button>
          </Can>
        )}
      </PageHeader>

      <div className="mt-5">
        {error ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>
              {t('settings.slaPolicies.page.loadFailedTitle', 'Failed to load SLA policies')}
            </AlertTitle>
            <AlertDescription>
              <p>
                {getErrorMessage(
                  error,
                  t('settings.slaPolicies.page.loadFailedBody', 'The SLA policies request failed.')
                )}
              </p>
              <Button variant="outline" size="sm" className="mt-2" onClick={() => void mutate()}>
                {t('common.retry', 'Retry')}
              </Button>
            </AlertDescription>
          </Alert>
        ) : isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-9 w-full max-w-sm" />
            <Skeleton className="h-64 w-full rounded-md" />
          </div>
        ) : policies.length === 0 ? (
          <EmptyState
            icon={Timer}
            title={t('settings.slaPolicies.page.emptyTitle', 'No SLA policies yet')}
            description={t(
              'settings.slaPolicies.page.emptyBody',
              'Without a policy the platform defaults apply (P0 2 days, P1 5, P2 15, P3 30). Create a policy, then make it the default to set your own windows.'
            )}
            action={
              <Can permission={Permission.SLAWrite}>
                <Button size="sm" onClick={openCreate}>
                  <Plus className="h-4 w-4" />
                  {t('settings.slaPolicies.page.newPolicy', 'New policy')}
                </Button>
              </Can>
            }
          />
        ) : (
          <DataTable
            columns={columns}
            data={policies}
            searchKey="name"
            searchPlaceholder={t('settings.slaPolicies.page.searchPlaceholder', 'Search policies…')}
          />
        )}
      </div>

      <SlaPolicyDialog open={dialogOpen} onOpenChange={setDialogOpen} policy={editing} />

      <ConfirmDialog
        open={Boolean(defaultTarget)}
        onOpenChange={(o) => !o && setDefaultTarget(null)}
        title={t('confirm.slaPolicy.makeDefaultTitle', 'Make "{name}" the default SLA policy?', {
          name: defaultTarget?.name ?? '',
        })}
        desc={t(
          'confirm.slaPolicy.makeDefaultDesc',
          'New deadlines will follow this policy from now on. Open findings are re-scored right away: where this policy has tighter windows their deadlines move earlier; they are never moved later, so switching back does not restore the old deadlines.'
        )}
        confirmText={t('confirm.slaPolicy.makeDefaultConfirm', 'Make default')}
        isLoading={isSettingDefault}
        handleConfirm={handleMakeDefault}
      />

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        onOpenChange={(o) => !o && setDeleteTarget(null)}
        title={t('confirm.slaPolicy.deleteTitle', 'Delete the SLA policy "{name}"?', {
          name: deleteTarget?.name ?? '',
        })}
        desc={t(
          'confirm.slaPolicy.deleteDesc',
          'It does not apply to any finding (only the default policy does). This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        isLoading={isDeleting}
        handleConfirm={handleDelete}
      />
    </Main>
  )
}
