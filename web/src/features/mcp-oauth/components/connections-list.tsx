'use client'

import { useState } from 'react'
import { Bot, Loader2, ShieldQuestion, Unplug } from 'lucide-react'
import { toast } from 'sonner'

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe, formatRelative } from '@/lib/format-date'

import { type McpConnection, scopeLabel } from '../api/connections'

interface ConnectionsListProps {
  connections: McpConnection[] | undefined
  isLoading: boolean
  /** Show whose connection each row is (organization view). */
  showUser?: boolean
  onRevoke: (id: string) => Promise<void>
  emptyTitle: string
  emptyDescription: string
}

/**
 * Connected AI applications (RFC-062 §12): which application, where it is
 * published, what it may read, since when, last use, and a disconnect that
 * ends the connection at once. Shared by the person's own page and the
 * organization view.
 */
export function ConnectionsList({
  connections,
  isLoading,
  showUser = false,
  onRevoke,
  emptyTitle,
  emptyDescription,
}: ConnectionsListProps) {
  const [pending, setPending] = useState<McpConnection | null>(null)
  const [busy, setBusy] = useState(false)

  if (isLoading) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </div>
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
      toast.success(`${pending.client_name} disconnected`)
      setPending(null)
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not disconnect the application'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <ul className="divide-y rounded-md border">
        {connections.map((c) => (
          <li
            key={c.id}
            className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between"
          >
            <div className="min-w-0 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium break-words">{c.client_name}</span>
                {c.client_kind === 'dynamic' ? (
                  <Badge variant="outline" className="gap-1">
                    <ShieldQuestion className="h-3 w-3" aria-hidden />
                    Unverified
                  </Badge>
                ) : c.client_host ? (
                  <span className="text-muted-foreground text-xs">{c.client_host}</span>
                ) : (
                  <span className="text-muted-foreground text-xs">
                    Registered by your organization
                  </span>
                )}
              </div>
              {showUser && (
                <p className="text-muted-foreground text-sm break-all">
                  {c.user_name || c.user_email}
                </p>
              )}
              <div className="flex flex-wrap gap-1">
                {c.scopes.map((s) => (
                  <Badge key={s} variant="secondary" className="text-xs">
                    {scopeLabel(s)}
                  </Badge>
                ))}
              </div>
              <p className="text-muted-foreground text-xs">
                Connected {formatDateSafe(c.created_at)} · last used{' '}
                {c.last_used_at ? formatRelative(c.last_used_at) : 'never'}
                {c.last_used_ip ? ` from ${c.last_used_ip}` : ''} · ends{' '}
                {formatDateSafe(c.expires_at)}
              </p>
            </div>
            <Button variant="outline" size="sm" className="shrink-0" onClick={() => setPending(c)}>
              <Unplug className="mr-2 h-4 w-4" aria-hidden />
              Disconnect
            </Button>
          </li>
        ))}
      </ul>

      <AlertDialog
        open={pending !== null}
        onOpenChange={(open) => !open && !busy && setPending(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Disconnect {pending?.client_name}?</AlertDialogTitle>
            <AlertDialogDescription>
              It loses access at once. To use it again, connect it again from the application.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                void confirm()
              }}
              disabled={busy}
            >
              {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
              Disconnect
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
