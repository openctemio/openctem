'use client'

/**
 * The roles a team carries (api research/58): every member holds them while
 * in the team, on top of their own roles. Only custom roles can be bound. The
 * API is the authority on who may change them: nobody grants beyond what they
 * hold, only an owner changes a team that carries a privileged role, and a
 * team with a full-data role admits no external member or service account.
 */

import { useMemo, useState } from 'react'
import { KeyRound, Loader2, Plus, ShieldAlert, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { EmptyState, ErrorState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { bindGroupRole, unbindGroupRole, useGroupRoles } from '../../api/use-group-roles'
import { useRoles } from '../../api/use-roles'

export function RolesTab({
  groupId,
  canBind,
  canUnbind,
  onChanged,
}: {
  groupId: string
  canBind: boolean
  canUnbind: boolean
  onChanged?: () => void
}) {
  const { roles: bound, error, isLoading, mutate } = useGroupRoles(groupId)
  const { roles: allRoles } = useRoles({ skip: !canBind })
  const [selected, setSelected] = useState('')
  const [busy, setBusy] = useState(false)
  const [toRemove, setToRemove] = useState<{ id: string; name: string } | null>(null)

  // Only custom roles can be bound, each once.
  const candidates = useMemo(
    () => allRoles.filter((r) => !r.is_system && !bound.some((b) => b.role_id === r.id)),
    [allRoles, bound]
  )
  const fullData = useMemo(
    () => new Set(allRoles.filter((r) => r.has_full_data_access).map((r) => r.id)),
    [allRoles]
  )

  async function handleBind() {
    if (!selected) return
    setBusy(true)
    try {
      await bindGroupRole(groupId, selected)
      toast.success('Role added to the team')
      setSelected('')
      onChanged?.()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not add the role'))
    } finally {
      setBusy(false)
    }
  }

  async function handleUnbind() {
    if (!toRemove) return
    setBusy(true)
    try {
      await unbindGroupRole(groupId, toRemove.id)
      toast.success('Role removed from the team')
      setToRemove(null)
      onChanged?.()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not remove the role'))
    } finally {
      setBusy(false)
    }
  }

  if (error) return <ErrorState title="Team roles" error={error} onRetry={() => void mutate()} />

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Every member holds these roles while in the team, and loses them on leaving it.
      </p>

      {canBind && (
        <div className="flex flex-wrap items-center gap-2">
          <Select value={selected} onValueChange={setSelected} disabled={busy}>
            <SelectTrigger className="w-64" aria-label="Role to add">
              <SelectValue placeholder="Choose a custom role..." />
            </SelectTrigger>
            <SelectContent>
              {candidates.length === 0 ? (
                <SelectItem value="none" disabled>
                  No other custom role
                </SelectItem>
              ) : (
                candidates.map((r) => (
                  <SelectItem key={r.id} value={r.id}>
                    {r.name}
                  </SelectItem>
                ))
              )}
            </SelectContent>
          </Select>
          <Button size="sm" onClick={() => void handleBind()} disabled={busy || !selected}>
            {busy ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <Plus className="me-2 h-4 w-4" />
            )}
            Add role
          </Button>
        </div>
      )}

      {isLoading ? (
        <div className="space-y-2" aria-hidden>
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </div>
      ) : bound.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title="No roles"
          description="Members hold only their own roles."
          card={false}
        />
      ) : (
        <ul className="space-y-2">
          {bound.map((b) => (
            <li key={b.role_id} className="flex items-center justify-between rounded-lg border p-3">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <span className="text-sm font-medium break-words">{b.name}</span>
                {b.privileged && (
                  <Badge
                    variant="outline"
                    className="gap-1 text-xs"
                    title="Grants an administrator-level permission: only an owner changes this team"
                  >
                    <ShieldAlert className="h-3 w-3" />
                    Privileged
                  </Badge>
                )}
                {fullData.has(b.role_id) && (
                  <Badge
                    variant="outline"
                    className="text-xs"
                    title="Members see every asset; external members and service accounts cannot join"
                  >
                    Full data access
                  </Badge>
                )}
              </div>
              {canUnbind && (
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={`Remove role ${b.name}`}
                  title="Remove"
                  className="text-destructive hover:text-destructive"
                  onClick={() => setToRemove({ id: b.role_id, name: b.name })}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}

      <ConfirmDialog
        open={!!toRemove}
        onOpenChange={(o) => !o && setToRemove(null)}
        title={`Remove ${toRemove?.name ?? 'role'} from the team?`}
        desc="Members who hold it only through this team lose its permissions at once."
        confirmText={busy ? 'Removing...' : 'Remove'}
        destructive
        isLoading={busy}
        handleConfirm={() => void handleUnbind()}
      />
    </div>
  )
}
