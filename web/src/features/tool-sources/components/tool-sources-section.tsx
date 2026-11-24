'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { KeyRound, Pencil, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { HealthStatus } from '@/components/ui/health-status'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  RelativeTime,
  SettingsPage,
} from '@/features/shared'
import { DataTableRowActions } from '@/features/shared/components/data-table-row-actions'
import { PersonPhoneCard } from '@/features/organization/components/person-phone-card'
import { toDisplayText } from '@/lib/untrusted-text'
import { removeToolSourceKey, setToolSourceEnabled, useToolSources } from '../api/use-tool-sources'
import type { ToolSource } from '../types'
import { SetKeyDialog } from './set-key-dialog'

export function ToolSourcesSection() {
  const { t } = useTranslation()
  const { can, isAdmin } = usePermissions()
  // The API also requires an owner or administrator for every change.
  const admin = isAdmin()
  const canWrite = admin && can(Permission.SecretStoreWrite)
  const canDelete = admin && can(Permission.SecretStoreDelete)
  const { data, error, isLoading, mutate } = useToolSources()
  const [editing, setEditing] = useState<ToolSource | null>(null)
  const [removing, setRemoving] = useState<ToolSource | null>(null)
  const [busy, setBusy] = useState(false)
  const sources = useMemo(() => data?.sources ?? [], [data])

  const toggle = async (s: ToolSource, enabled: boolean) => {
    try {
      await setToolSourceEnabled(s.id, enabled)
      await mutate()
    } catch (err) {
      toast.error(getErrorMessage(err, t('toolSources.toggleFailed', 'Could not change the key')))
    }
  }

  const confirmRemove = async () => {
    if (!removing) return
    setBusy(true)
    try {
      await removeToolSourceKey(removing.id)
      toast.success(t('toolSources.removed', 'Key removed for {name}', { name: removing.name }))
      setRemoving(null)
      await mutate()
    } catch (err) {
      toast.error(getErrorMessage(err, t('toolSources.removeFailed', 'Could not remove the key')))
    } finally {
      setBusy(false)
    }
  }

  const nameLabel = t('toolSources.col.source', 'Source')
  const toolsLabel = t('toolSources.col.tools', 'Used by')
  const keyLabel = t('toolSources.col.key', 'Key')
  const updatedLabel = t('toolSources.col.updated', 'Updated')
  const lastUsedLabel = t('toolSources.col.lastUsed', 'Last used')
  const enabledLabel = t('toolSources.col.enabled', 'Enabled')

  const keyStatus = (s: ToolSource) =>
    s.key?.set ? (
      <span className="inline-flex min-w-0 items-center gap-2">
        <HealthStatus state="ok" label={t('toolSources.keySet', 'Set')} />
        <span className="font-mono text-cap text-muted-foreground">{`•••• ${s.key.last4 ?? ''}`}</span>
      </span>
    ) : (
      <HealthStatus state="off" label={t('toolSources.notSet', 'Not set')} />
    )

  const lastUsed = (s: ToolSource) =>
    s.key?.set && s.key.last_used_at ? (
      <RelativeTime date={s.key.last_used_at} />
    ) : (
      <span className="text-muted-foreground">{t('toolSources.neverUsed', 'Never')}</span>
    )

  // Without a key there is nothing to switch on: the cell offers to set one
  // (or stays empty for a reader) instead of a greyed, dead switch.
  const enableSwitch = (s: ToolSource) =>
    s.key?.set ? (
      <Switch
        checked={!!s.key.enabled}
        disabled={!canWrite}
        onCheckedChange={(v) => void toggle(s, v)}
        aria-label={t('toolSources.enableAria', 'Use the key for {name}', { name: s.name })}
      />
    ) : canWrite ? (
      <Button
        variant="ghost"
        size="sm"
        onClick={() => setEditing(s)}
        aria-label={t('toolSources.setNamed', 'Set the key for {name}', { name: s.name })}
      >
        {t('toolSources.set', 'Set key')}
      </Button>
    ) : (
      <span className="text-muted-foreground">-</span>
    )

  const rowMenu = (s: ToolSource) => {
    const hasKey = !!s.key?.set
    const actions = [
      ...(canWrite
        ? [
            {
              label: hasKey
                ? t('toolSources.rotate', 'Rotate key')
                : t('toolSources.set', 'Set key'),
              icon: Pencil,
              onClick: () => setEditing(s),
            },
          ]
        : []),
      ...(canDelete && hasKey
        ? [
            {
              label: t('toolSources.remove', 'Remove key'),
              icon: Trash2,
              destructive: true,
              separatorBefore: canWrite,
              onClick: () => setRemoving(s),
            },
          ]
        : []),
    ]
    if (actions.length === 0) return null
    return (
      <DataTableRowActions
        title={s.name}
        label={t('toolSources.actionsFor', 'Actions for {name}', { name: s.name })}
        actions={actions}
      />
    )
  }

  const columns = useMemo<ColumnDef<ToolSource>[]>(
    () => [
      {
        id: 'name',
        accessorFn: (s) => s.name,
        meta: { kind: 'name', pin: 'start', minWidth: 160, label: nameLabel },
        enableHiding: false,
        enableSorting: false,
        header: ({ column }) => <DataTableColumnHeader column={column} title={nameLabel} />,
        cell: ({ row }) => (
          <span className="block truncate font-medium">
            {toDisplayText(row.original.name, 200)}
          </span>
        ),
      },
      {
        id: 'tools',
        meta: { kind: 'tags', minWidth: 120, hideBelow: 660, label: toolsLabel },
        enableSorting: false,
        header: toolsLabel,
        cell: ({ row }) => (
          <span className="block truncate text-sm" title={row.original.tools.join(', ')}>
            {row.original.tools.join(', ')}
          </span>
        ),
      },
      {
        id: 'key',
        meta: { kind: 'masked', width: 160, label: keyLabel },
        enableSorting: false,
        header: keyLabel,
        cell: ({ row }) => keyStatus(row.original),
      },
      {
        id: 'updated',
        // Dropped first when the frame is narrow: a column is never cut or scrolled.
        meta: { kind: 'text', minWidth: 120, maxWidth: 200, hideBelow: 1000, label: updatedLabel },
        enableSorting: false,
        header: updatedLabel,
        cell: ({ row }) => {
          const key = row.original.key
          if (!key?.set || !key.updated_at) return <span className="text-muted-foreground">—</span>
          return (
            <div className="min-w-0 text-sm text-muted-foreground">
              <RelativeTime date={key.updated_at} />
              {key.updated_by_name && (
                <div className="truncate" title={key.updated_by_name}>
                  {t('toolSources.updatedBy', 'by {name}', { name: key.updated_by_name })}
                </div>
              )}
            </div>
          )
        },
      },
      {
        id: 'lastUsed',
        meta: { kind: 'datetime-recent', width: 120, hideBelow: 780, label: lastUsedLabel },
        enableSorting: false,
        header: lastUsedLabel,
        cell: ({ row }) => lastUsed(row.original),
      },
      {
        id: 'enabled',
        meta: { kind: 'status', width: 112, label: enabledLabel },
        enableSorting: false,
        header: enabledLabel,
        cell: ({ row }) => enableSwitch(row.original),
      },
      {
        id: 'actions',
        meta: { kind: 'actions' },
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => rowMenu(row.original),
      },
    ],
    // The cell helpers close over t, the permissions and the page's handlers.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      t,
      canWrite,
      canDelete,
      nameLabel,
      toolsLabel,
      keyLabel,
      updatedLabel,
      lastUsedLabel,
      enabledLabel,
    ]
  )

  return (
    <SettingsPage
      wide
      title={t('toolSources.title', 'Tool source keys')}
      description={t(
        'toolSources.desc',
        'Keys are encrypted and never shown again. Only your organization’s scans use them, and a key reaches the sensor only for the task that needs it.'
      )}
    >
      {/* The page re-reads on focus; a failed read shows Retry in the list. */}
      <DataTable
        columns={columns}
        data={sources}
        getRowId={(s) => s.id}
        error={error}
        onRetry={() => void mutate()}
        errorTitle={t('toolSources.errorTitle', 'tool source keys')}
        isLoading={isLoading && !data}
        showToolbar={false}
        showSearch={false}
        showColumnToggle={false}
        showPagination={false}
        pinActions
        pageSize={500}
        caption={t('toolSources.title', 'Tool source keys')}
        mobileRow={(s) => {
          const tools = s.tools.join(', ')
          return (
            <PersonPhoneCard
              title={toDisplayText(s.name, 200)}
              address={t('toolSources.usedBy', 'Used by {tools}', { tools })}
              menu={
                <div className="flex items-center gap-1">
                  {enableSwitch(s)}
                  {rowMenu(s)}
                </div>
              }
              facts={
                <>
                  {keyStatus(s)}
                  <span className="text-cap text-muted-foreground">
                    {lastUsedLabel} {lastUsed(s)}
                  </span>
                </>
              }
            />
          )
        }}
        emptyState={
          <EmptyState
            icon={KeyRound}
            title={t('toolSources.empty.title', 'No sources')}
            description={t('toolSources.empty.desc', 'No scan tool source accepts a key yet.')}
            card={false}
          />
        }
      />

      {editing && (
        <SetKeyDialog
          key={editing.id}
          source={editing}
          open
          onOpenChange={(o) => !o && setEditing(null)}
          onSaved={() => void mutate()}
        />
      )}
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={t('toolSources.confirm.title', 'Remove the key for {name}?', {
          name: removing?.name ?? '',
        })}
        desc={t(
          'toolSources.confirm.desc',
          'Scans stop using this source until a new key is set. The key cannot be recovered.'
        )}
        confirmText={t('toolSources.remove', 'Remove key')}
        destructive
        isLoading={busy}
        handleConfirm={confirmRemove}
      />
    </SettingsPage>
  )
}
