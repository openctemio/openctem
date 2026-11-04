'use client'

import { useState } from 'react'
import { ExternalLink, KeyRound } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { RefreshButton, TableSkeleton } from '@/components/list-page-parts'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import { EmptyState, ErrorState, PageHeader, PageStack, RelativeTime } from '@/features/shared'
import { removeToolSourceKey, setToolSourceEnabled, useToolSources } from '../api/use-tool-sources'
import type { ToolSource } from '../types'
import { SetKeyDialog } from './set-key-dialog'

export function ToolSourcesSection() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canWrite = can(Permission.SecretStoreWrite)
  const canDelete = can(Permission.SecretStoreDelete)
  const { data, error, isLoading, mutate } = useToolSources()
  const [editing, setEditing] = useState<ToolSource | null>(null)
  const [removing, setRemoving] = useState<ToolSource | null>(null)
  const [busy, setBusy] = useState(false)
  const sources = data?.sources ?? []

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

  let body: React.ReactNode
  if (error) {
    body = (
      <ErrorState
        title={t('toolSources.errorTitle', 'tool source keys')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  } else if (isLoading) {
    body = <TableSkeleton rows={4} />
  } else if (sources.length === 0) {
    body = (
      <EmptyState
        icon={KeyRound}
        title={t('toolSources.empty.title', 'No sources')}
        description={t('toolSources.empty.desc', 'No scan tool source accepts a key yet.')}
      />
    )
  } else {
    body = (
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t('toolSources.col.source', 'Source')}</TableHead>
            <TableHead>{t('toolSources.col.tools', 'Used by')}</TableHead>
            <TableHead>{t('toolSources.col.key', 'Key')}</TableHead>
            <TableHead>{t('toolSources.col.updated', 'Updated')}</TableHead>
            <TableHead>{t('toolSources.col.lastUsed', 'Last used')}</TableHead>
            <TableHead>{t('toolSources.col.enabled', 'Enabled')}</TableHead>
            <TableHead className="text-right">
              <span className="sr-only">{t('toolSources.col.actions', 'Actions')}</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sources.map((s) => {
            const key = s.key?.set ? s.key : null
            return (
              <TableRow key={s.id}>
                <TableCell>
                  <div className="font-medium">{s.name}</div>
                  {s.docs_url && (
                    <a
                      href={s.docs_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:underline"
                    >
                      {t('toolSources.docs', 'Get a key')}
                      <ExternalLink className="h-3 w-3" aria-hidden />
                    </a>
                  )}
                </TableCell>
                <TableCell className="text-sm">{s.tools.join(', ')}</TableCell>
                <TableCell className="text-sm">
                  {key ? (
                    <span>{`•••• ${key.last4 ?? ''}`}</span>
                  ) : (
                    <span className="text-muted-foreground">
                      {t('toolSources.notSet', 'Not set')}
                    </span>
                  )}
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {key?.updated_at ? (
                    <>
                      <RelativeTime date={key.updated_at} />
                      {key.updated_by_name && (
                        <div>
                          {t('toolSources.updatedBy', 'by {name}', { name: key.updated_by_name })}
                        </div>
                      )}
                    </>
                  ) : (
                    '—'
                  )}
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {key?.last_used_at ? (
                    <RelativeTime date={key.last_used_at} />
                  ) : (
                    t('toolSources.neverUsed', 'Never')
                  )}
                </TableCell>
                <TableCell>
                  <Switch
                    checked={!!key?.enabled}
                    disabled={!key || !canWrite}
                    onCheckedChange={(v) => void toggle(s, v)}
                    aria-label={t('toolSources.enableAria', 'Use the key for {name}', {
                      name: s.name,
                    })}
                  />
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-2">
                    {canWrite && (
                      <Button size="sm" variant="outline" onClick={() => setEditing(s)}>
                        {key
                          ? t('toolSources.rotate', 'Rotate key')
                          : t('toolSources.set', 'Set key')}
                      </Button>
                    )}
                    {canDelete && key && (
                      <Button size="sm" variant="outline" onClick={() => setRemoving(s)}>
                        {t('toolSources.remove', 'Remove key')}
                      </Button>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    )
  }

  return (
    <PageStack>
      <PageHeader
        title={t('toolSources.title', 'Tool source keys')}
        description={t(
          'toolSources.desc',
          'Keys are encrypted and never shown again. Only your organization’s scans use them, and a key reaches the sensor only for the task that needs it.'
        )}
      >
        <RefreshButton onClick={() => void mutate()} loading={isLoading} />
      </PageHeader>

      {body}

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
    </PageStack>
  )
}
