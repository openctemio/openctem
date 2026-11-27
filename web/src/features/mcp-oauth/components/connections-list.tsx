'use client'

import { useState } from 'react'
import { Bot, Database, Loader2, ShieldMinus, ShieldQuestion, Terminal, Unplug } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, ErrorState } from '@/features/shared'
import {
  DataTableRowActions,
  type RowAction,
} from '@/features/shared/components/data-table-row-actions'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe, formatRelative } from '@/lib/format-date'

import { type McpConnection } from '../api/connections'
import { useMcpLabels } from '../lib/use-mcp-labels'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

interface ConnectionsListProps {
  connections: McpConnection[] | undefined
  isLoading: boolean
  /** The list failed to load: shown as an error with Retry, never as empty. */
  error?: unknown
  onRetry?: () => void
  /** Show whose connection each row is (organization view). */
  showUser?: boolean
  onRevoke: (id: string) => Promise<void>
  /** Sets a connection that reads all organization data back to its person's scope. */
  onScope?: (id: string) => Promise<void>
  emptyTitle: string
  emptyDescription: string
}

/** Rows shown at first, and added by each "Show more". */
const STEP = 20

/**
 * Connected AI applications (RFC-062 §12): which application, where it is
 * published, what it may read, since when, last use, and a disconnect that
 * ends the connection at once. Shared by the person's own page and the
 * organization view.
 */
export function ConnectionsList({
  connections,
  isLoading,
  error,
  onRetry,
  showUser = false,
  onRevoke,
  onScope,
  emptyTitle,
  emptyDescription,
}: ConnectionsListProps) {
  const { t } = useTranslation()
  const { scopeShort } = useMcpLabels()
  const [pending, setPending] = useState<McpConnection | null>(null)
  const [busy, setBusy] = useState(false)
  const [scoping, setScoping] = useState<string | null>(null)
  const [shown, setShown] = useState(STEP)

  if (isLoading) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </div>
    )
  }
  if (error && !connections) {
    return (
      <ErrorState
        title={t('mcp.connections.loadFailed', 'connected applications')}
        error={error}
        onRetry={onRetry}
      />
    )
  }
  if (!connections || connections.length === 0) {
    return <EmptyState icon={Bot} title={emptyTitle} description={emptyDescription} />
  }

  const confirm = async () => {
    if (!pending) return
    setBusy(true)
    try {
      await onRevoke(pending.id)
      toast.success(
        t('mcp.connections.disconnected', '{name} disconnected', { name: pending.client_name })
      )
      setPending(null)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('mcp.connections.disconnectFailed', 'Could not disconnect the application')
        )
      )
    } finally {
      setBusy(false)
    }
  }

  const limit = async (c: McpConnection) => {
    if (!onScope) return
    setScoping(c.id)
    try {
      await onScope(c.id)
      toast.success(
        t('mcp.connections.limited', '{name} now reads only the data scope of its person', {
          name: c.client_name,
        })
      )
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('mcp.connections.limitFailed', 'Could not limit the application'))
      )
    } finally {
      setScoping(null)
    }
  }

  // One row menu, as on the other lists: limiting to the person's own data
  // (only for a connection that reads everything) and disconnecting.
  const rowActions = (c: McpConnection): RowAction[] => [
    ...(c.full_data && onScope
      ? [
          {
            label: t('mcp.connections.limit', 'Limit to own data'),
            icon: scoping === c.id ? Loader2 : ShieldMinus,
            disabled: scoping === c.id,
            onClick: () => void limit(c),
          },
        ]
      : []),
    {
      label: t('mcp.connections.disconnect', 'Disconnect'),
      icon: Unplug,
      destructive: true,
      separatorBefore: !!(c.full_data && onScope),
      onClick: () => setPending(c),
    },
  ]

  return (
    <>
      <ul className="divide-y rounded-md border">
        {connections.slice(0, shown).map((c) => (
          <li key={c.id} className="flex items-start justify-between gap-3 p-4">
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium break-words">{c.client_name}</span>
                {c.flow === 'device' ? (
                  <Badge variant="outline" className="gap-1">
                    <Terminal className="h-3 w-3" aria-hidden />
                    {t('mcp.connections.terminal', 'Terminal sign-in')}
                  </Badge>
                ) : c.client_kind === 'dynamic' ? (
                  <Badge variant="outline" className="gap-1">
                    <ShieldQuestion className="h-3 w-3" aria-hidden />
                    {t('mcp.client.unverified', 'Unverified')}
                  </Badge>
                ) : c.client_host ? (
                  <span className="text-muted-foreground text-xs">
                    {t('mcp.client.publishedBy', 'Published by {host}', { host: c.client_host })}
                  </span>
                ) : (
                  <span className="text-muted-foreground text-xs">
                    {t('mcp.client.registeredByOrg', 'Registered by your organization')}
                  </span>
                )}
                {c.full_data && (
                  <Badge variant="outline" className="gap-1">
                    <Database className="h-3 w-3" aria-hidden />
                    {t('mcp.connections.fullData', 'All organization data')}
                  </Badge>
                )}
              </div>
              {showUser && (
                <p className="text-muted-foreground text-sm break-words">
                  {c.user_name || c.user_email}
                </p>
              )}
              <div className="flex flex-wrap gap-1">
                {c.scopes.map((s) => (
                  <Badge key={s} variant="secondary" className="text-xs">
                    {scopeShort(s)}
                  </Badge>
                ))}
              </div>
              <p className="text-muted-foreground text-xs">
                {[
                  t('mcp.connections.connectedOn', 'Connected {date}', {
                    date: formatDateSafe(c.created_at),
                  }),
                  c.last_used_at
                    ? c.last_used_ip
                      ? t('mcp.connections.lastUsedFrom', 'last used {when} from {ip}', {
                          when: formatRelative(c.last_used_at),
                          ip: c.last_used_ip,
                        })
                      : t('mcp.connections.lastUsed', 'last used {when}', {
                          when: formatRelative(c.last_used_at),
                        })
                    : t('mcp.connections.neverUsed', 'never used'),
                  t('mcp.connections.endsOn', 'ends {date}', {
                    date: formatDateSafe(c.expires_at),
                  }),
                ].join(', ')}
              </p>
            </div>
            <div className="shrink-0">
              <DataTableRowActions
                title={c.client_name}
                label={t('mcp.connections.actionsFor', 'Actions for {name}', {
                  name: c.client_name,
                })}
                actions={rowActions(c)}
              />
            </div>
          </li>
        ))}
      </ul>
      {connections.length > shown && (
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          <p className="text-cap text-muted-foreground">
            {t('mcp.connections.shownOf', '{shown} of {total}', {
              shown,
              total: connections.length,
            })}
          </p>
          <Button variant="outline" onClick={() => setShown((n) => n + STEP)}>
            {t('mcp.connections.showMore', 'Show {count} more', {
              count: Math.min(STEP, connections.length - shown),
            })}
          </Button>
        </div>
      )}

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => !open && !busy && setPending(null)}
        destructive
        title={t('mcp.connections.disconnectTitle', 'Disconnect {name}?', {
          name: pending?.client_name ?? '',
        })}
        desc={t(
          'mcp.connections.disconnectDesc',
          'It loses access at once. To use it again, connect it again from the application.'
        )}
        confirmText={
          <>
            {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
            {t('mcp.connections.disconnect', 'Disconnect')}
          </>
        }
        isLoading={busy}
        handleConfirm={() => confirm()}
      />
    </>
  )
}
