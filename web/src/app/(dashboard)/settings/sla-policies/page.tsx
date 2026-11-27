'use client'

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Plus, Pencil, Trash2, ShieldCheck, ShieldPlus, Timer } from 'lucide-react'

import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  SettingsPage,
  type RowAction,
} from '@/features/shared'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { PersonPhoneCard } from '@/features/organization/components/person-phone-card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Can, useCanMutate } from '@/lib/permissions'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useUrlFilter } from '@/hooks/use-url-param'
import { toDisplayText } from '@/lib/untrusted-text'

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

/**
 * SLA policies (board P4-Settings-SlaPolicies): one list with search; a
 * policy opens in its edit dialog (`?policy=<id>`), the row menu edits, makes
 * it the default or deletes it. Only the default policy (and an asset
 * override, for its asset) applies to findings, so each row says whether it
 * applies. The list is small and unpaged: search runs on the client.
 */

const policyHref = (id: string) => `/settings/sla-policies?policy=${encodeURIComponent(id)}`

/** Whether findings follow this policy: the default, or an asset's override. */
const applies = (p: SlaPolicy) => p.is_default || !!p.asset_id

/** Table frame widths (px) under which a column folds away; the policy, its windows and the actions stay. */
const SLA_HIDE_BELOW = { notify: 820, warning: 700 } as const

export default function SlaPoliciesPage() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useSlaPoliciesApi()
  const policies = useMemo(() => data?.data ?? [], [data])
  const canCreate = useCanMutate('POST /api/v1/sla-policies')
  const canEdit = useCanMutate('PUT /api/v1/sla-policies/{id}')

  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const [policyParam, setPolicyParam] = useUrlFilter('policy', '')
  const [creating, setCreating] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<SlaPolicy | null>(null)
  const [defaultTarget, setDefaultTarget] = useState<SlaPolicy | null>(null)

  // The edit dialog follows `?policy=<id>` (a shareable link); a reader who
  // may not edit gets no dialog, the row already shows every window.
  const editing = useMemo(
    () => (canEdit && policyParam ? (policies.find((p) => p.id === policyParam) ?? null) : null),
    [canEdit, policyParam, policies]
  )
  const openEdit = useCallback((p: SlaPolicy) => setPolicyParam(p.id), [setPolicyParam])
  const currentDefault = policies.find((p) => p.is_default && !p.asset_id) ?? null

  const { trigger: deletePolicy, isMutating: isDeleting } = useDeleteSlaPolicy()
  const { trigger: updatePolicy, isMutating: isSettingDefault } = useUpdateSlaPolicy()

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return policies
    return policies.filter(
      (p) => p.name.toLowerCase().includes(q) || !!p.description?.toLowerCase().includes(q)
    )
  }, [policies, searchQuery])

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await deletePolicy({ id: deleteTarget.id })
      toast.success(
        t('settings.slaPolicies.page.deleted', 'Policy "{name}" deleted', {
          name: toDisplayText(deleteTarget.name, 120),
        })
      )
      await invalidateSlaPoliciesCache()
      setDeleteTarget(null)
    } catch (err) {
      // The dialog stays open: the policy is still there and can be tried again.
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
          name: toDisplayText(defaultTarget.name, 120),
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

  const rowMenu = useCallback(
    (p: SlaPolicy) => {
      const name = toDisplayText(p.name, 120)
      const actions: RowAction[] = [
        {
          label: t('settings.slaPolicies.page.editPolicy', 'Edit'),
          icon: Pencil,
          route: 'PUT /api/v1/sla-policies/{id}',
          onClick: () => openEdit(p),
        },
        ...(!p.is_default && !p.asset_id && p.is_active
          ? [
              {
                label: t('settings.slaPolicies.page.makeDefaultItem', 'Make default'),
                icon: ShieldPlus,
                route: 'PUT /api/v1/sla-policies/{id}' as const,
                onClick: () => setDefaultTarget(p),
              },
            ]
          : []),
        {
          label: t('settings.slaPolicies.page.deletePolicy', 'Delete'),
          icon: Trash2,
          destructive: true,
          separatorBefore: true,
          route: 'DELETE /api/v1/sla-policies/{id}',
          // The server refuses to delete the default policy: say why.
          disabled: p.is_default,
          disabledReason: p.is_default
            ? t(
                'settings.slaPolicies.page.defaultNoDelete',
                'The default policy cannot be deleted. Make another policy the default first.'
              )
            : undefined,
          onClick: () => setDeleteTarget(p),
        },
      ]
      return (
        <DataTableRowActions
          title={name}
          label={t('common.rowActions.actionsFor', 'Actions for {name}', { name })}
          actions={actions}
        />
      )
    },
    [t, openEdit]
  )

  const badges = useCallback(
    (p: SlaPolicy) => (
      <>
        {p.is_default && (
          <Badge variant="secondary">
            <ShieldCheck aria-hidden />
            {t('settings.slaPolicies.page.badgeDefault', 'Default')}
          </Badge>
        )}
        {p.asset_id && (
          <Badge variant="outline">
            {t('settings.slaPolicies.page.badgeAsset', 'Asset override')}
          </Badge>
        )}
        {p.practice === 'compliance' && (
          <Badge
            variant="outline"
            title={t(
              'settings.slaPolicies.page.badgeComplianceHint',
              'Governs compliance findings only; vulnerability policies never govern them.'
            )}
          >
            {t('settings.slaPolicies.practice.compliance', 'Compliance')}
          </Badge>
        )}
        {!applies(p) && (
          <Badge
            variant="outline"
            title={t(
              'settings.slaPolicies.page.badgeNotAppliedHint',
              'Only the default policy applies to findings. Make this the default to use it.'
            )}
          >
            {t('settings.slaPolicies.page.badgeNotApplied', 'Not applied')}
          </Badge>
        )}
      </>
    ),
    [t]
  )

  const policyLabel = t('settings.slaPolicies.page.colPolicy', 'Policy')
  const windowsLabel = t('settings.slaPolicies.page.colWindows', 'Remediation windows')
  const warningLabel = t('settings.slaPolicies.page.colWarning', 'Warning at')
  const notifyLabel = t('settings.slaPolicies.page.colNotifications', 'Notifications')
  const onOff = useCallback(
    (on: boolean) =>
      on ? t('settings.slaPolicies.page.on', 'On') : t('settings.slaPolicies.page.off', 'Off'),
    [t]
  )

  const columns = useMemo<ColumnDef<SlaPolicy>[]>(
    () => [
      {
        accessorKey: 'name',
        meta: { kind: 'name', pin: 'start', minWidth: 240, label: policyLabel },
        enableHiding: false,
        header: ({ column }) => <DataTableColumnHeader column={column} title={policyLabel} />,
        cell: ({ row }) => {
          const p = row.original
          const name = toDisplayText(p.name, 200)
          return (
            <div className="min-w-0 space-y-1">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                {canEdit ? (
                  <RowNameLink href={policyHref(p.id)} onOpen={() => openEdit(p)} title={name}>
                    {name}
                  </RowNameLink>
                ) : (
                  <span className="min-w-0 truncate font-medium">{name}</span>
                )}
                {badges(p)}
              </div>
              {p.description && (
                <p className="text-cap text-muted-foreground truncate">
                  {toDisplayText(p.description, 300)}
                </p>
              )}
            </div>
          )
        },
      },
      {
        id: 'windows',
        meta: { kind: 'text', minWidth: 260, label: windowsLabel },
        header: windowsLabel,
        enableSorting: false,
        cell: ({ row }) => <SlaWindows policy={row.original} />,
      },
      {
        accessorKey: 'warning_threshold_pct',
        meta: { kind: 'number', label: warningLabel, hideBelow: SLA_HIDE_BELOW.warning },
        header: ({ column }) => <DataTableColumnHeader column={column} title={warningLabel} />,
        cell: ({ row }) => (
          <span className="tabular-nums">{row.original.warning_threshold_pct}%</span>
        ),
      },
      {
        accessorKey: 'escalation_enabled',
        meta: { kind: 'status', label: notifyLabel, hideBelow: SLA_HIDE_BELOW.notify },
        header: notifyLabel,
        enableSorting: false,
        cell: ({ row }) =>
          row.original.escalation_enabled ? (
            <Badge variant="outline">{onOff(true)}</Badge>
          ) : (
            <span className="text-sm text-muted-foreground">{onOff(false)}</span>
          ),
      },
      {
        id: 'actions',
        meta: { kind: 'actions' },
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => rowMenu(row.original),
      },
    ],
    [
      canEdit,
      openEdit,
      badges,
      rowMenu,
      onOff,
      policyLabel,
      windowsLabel,
      warningLabel,
      notifyLabel,
    ]
  )

  const newPolicy = (
    <Can route="POST /api/v1/sla-policies">
      <Button onClick={() => setCreating(true)}>
        <Plus aria-hidden />
        {t('settings.slaPolicies.page.newPolicy', 'New policy')}
      </Button>
    </Can>
  )

  const deleteDesc = deleteTarget?.asset_id
    ? t(
        'confirm.slaPolicy.deleteAssetDesc',
        "Findings on its asset follow the organization's default policy again. This cannot be undone."
      )
    : t(
        'confirm.slaPolicy.deleteDesc',
        'It does not apply to any finding (only the default policy does). This cannot be undone.'
      )

  return (
    <>
      <SettingsPage
        wide
        title={t('settings.slaPolicies.title', 'SLA policies')}
        description={t(
          'settings.slaPolicies.description',
          'Remediation windows per priority class (P0–P3), and per severity for findings without a class.'
        )}
        readOnly={
          !canCreate && !canEdit
            ? t(
                'settings.slaPolicies.page.readOnly',
                'View only. Only owners and administrators can change SLA policies.'
              )
            : undefined
        }
        actions={policies.length > 0 ? newPolicy : undefined}
      >
        <DataTable
          columns={columns}
          data={filtered}
          getRowId={(p) => p.id}
          isLoading={isLoading && policies.length === 0}
          error={error ?? undefined}
          onRetry={() => void mutate()}
          errorTitle={t('settings.slaPolicies.page.errorTitle', 'SLA policies')}
          // No policies yet (or a refused read): nothing to search or arrange,
          // so no search box or Display button above the empty state.
          showToolbar={policies.length > 0}
          pinActions
          showSearch={false}
          search={{
            value: searchQuery,
            onChange: setSearchQuery,
            placeholder: t('settings.slaPolicies.page.searchPlaceholder', 'Search policies…'),
            label: t('settings.slaPolicies.page.searchLabel', 'Search SLA policies'),
          }}
          showColumnToggle={false}
          onRowClick={canEdit ? openEdit : undefined}
          showPagination={filtered.length > 25}
          paginationNoun={t('settings.slaPolicies.page.noun', 'policies')}
          mobileRow={(p) => (
            <PersonPhoneCard
              title={
                <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="min-w-0">{toDisplayText(p.name, 200)}</span>
                  {badges(p)}
                </span>
              }
              address={p.description ? toDisplayText(p.description, 300) : undefined}
              onOpen={canEdit ? () => openEdit(p) : undefined}
              menu={rowMenu(p)}
              facts={
                <span className="block w-full space-y-1">
                  <SlaWindows policy={p} />
                  <span className="block text-cap text-muted-foreground">
                    {t(
                      'settings.slaPolicies.page.card.facts',
                      'Warning at {pct}%, notifications {state}',
                      {
                        pct: p.warning_threshold_pct,
                        state: onOff(p.escalation_enabled).toLowerCase(),
                      }
                    )}
                  </span>
                </span>
              }
            />
          )}
          isFiltered={searchQuery.trim() !== ''}
          onClearFilters={() => setSearchQuery('')}
          emptyState={{
            nothingYet: (
              <EmptyState
                icon={Timer}
                title={t('settings.slaPolicies.page.emptyTitle', 'No SLA policies yet')}
                description={t(
                  'settings.slaPolicies.page.emptyBody',
                  'Without a policy the platform defaults apply (P0 2 days, P1 5, P2 15, P3 30). Create a policy, then make it the default to set your own windows.'
                )}
                action={newPolicy}
              />
            ),
            noMatch: {
              title: t('settings.slaPolicies.page.noMatch', 'No policies match this search'),
              hint: t(
                'settings.slaPolicies.page.noMatchHint',
                'Try another name or clear the search.'
              ),
            },
          }}
        />
      </SettingsPage>

      <SlaPolicyDialog
        open={creating || !!editing}
        onOpenChange={(open) => {
          if (open) return
          setCreating(false)
          if (editing) setPolicyParam('')
        }}
        policy={editing}
      />

      <ConfirmDialog
        open={Boolean(defaultTarget)}
        onOpenChange={(o) => !o && setDefaultTarget(null)}
        title={t('confirm.slaPolicy.makeDefaultTitle', 'Make "{name}" the default SLA policy?', {
          name: defaultTarget ? toDisplayText(defaultTarget.name, 120) : '',
        })}
        desc={
          <>
            <span className="block">
              {t(
                'confirm.slaPolicy.makeDefaultDesc',
                'New deadlines will follow this policy from now on. Open findings are re-scored right away: where this policy has tighter windows their deadlines move earlier; they are never moved later, so switching back does not restore the old deadlines.'
              )}
            </span>
            {currentDefault && (
              <span className="mt-2 block">
                {t(
                  'confirm.slaPolicy.makeDefaultUndo',
                  'To go back, make "{name}" the default again.',
                  { name: toDisplayText(currentDefault.name, 120) }
                )}
              </span>
            )}
          </>
        }
        confirmText={t('confirm.slaPolicy.makeDefaultConfirm', 'Make default')}
        isLoading={isSettingDefault}
        handleConfirm={handleMakeDefault}
      />

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        onOpenChange={(o) => !o && setDeleteTarget(null)}
        title={t('confirm.slaPolicy.deleteTitle', 'Delete the SLA policy "{name}"?', {
          name: deleteTarget ? toDisplayText(deleteTarget.name, 120) : '',
        })}
        desc={deleteDesc}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        isLoading={isDeleting}
        handleConfirm={handleDelete}
      />
    </>
  )
}
