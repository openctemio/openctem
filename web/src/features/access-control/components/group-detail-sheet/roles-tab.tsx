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
import { useTranslation } from '@/context/i18n-provider'

export function RolesTab({
  groupId,
  canBind,
  canUnbind,
  memberCount,
  onChanged,
}: {
  groupId: string
  canBind: boolean
  canUnbind: boolean
  /** Members now in the team, when the caller knows it. */
  memberCount?: number
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const { roles: bound, error, isLoading, mutate } = useGroupRoles(groupId)
  const { roles: allRoles } = useRoles({ skip: !canBind })
  const [selected, setSelected] = useState('')
  const [busy, setBusy] = useState(false)
  const [confirmBind, setConfirmBind] = useState(false)
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
    setConfirmBind(false)
    setBusy(true)
    try {
      await bindGroupRole(groupId, selected)
      toast.success(t('org.teamRoles.added', 'Role added to the team'))
      setSelected('')
      onChanged?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('org.teamRoles.addFailed', 'Could not add the role')))
    } finally {
      setBusy(false)
    }
  }

  async function handleUnbind() {
    if (!toRemove) return
    setBusy(true)
    try {
      await unbindGroupRole(groupId, toRemove.id)
      toast.success(t('org.teamRoles.removed', 'Role removed from the team'))
      setToRemove(null)
      onChanged?.()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('org.teamRoles.removeFailed', 'Could not remove the role'))
      )
    } finally {
      setBusy(false)
    }
  }

  if (error)
    return (
      <ErrorState
        title={t('org.teamRoles.errorTitle', 'Team roles')}
        error={error}
        onRetry={() => void mutate()}
      />
    )

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        {t(
          'org.teamRoles.intro',
          'Every member holds these roles while in the team, and loses them on leaving it.'
        )}
      </p>

      {canBind && (
        <div className="flex flex-wrap items-center gap-2">
          <Select value={selected} onValueChange={setSelected} disabled={busy}>
            <SelectTrigger className="w-64" aria-label={t('org.teamRoles.toAdd', 'Role to add')}>
              <SelectValue placeholder={t('org.teamRoles.choose', 'Choose a custom role...')} />
            </SelectTrigger>
            <SelectContent>
              {candidates.length === 0 ? (
                <SelectItem value="none" disabled>
                  {t('org.teamRoles.noOther', 'No other custom role')}
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
          <Button size="sm" onClick={() => setConfirmBind(true)} disabled={busy || !selected}>
            {busy ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <Plus className="me-2 h-4 w-4" />
            )}
            {t('org.teamRoles.addButton', 'Add role')}
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
          title={t('org.teamRoles.emptyTitle', 'No roles')}
          description={t('org.teamRoles.emptyDesc', 'Members hold only their own roles.')}
          card={false}
        />
      ) : (
        <ul className="space-y-2">
          {bound.map((b) => (
            <li key={b.role_id} className="flex items-center justify-between rounded-lg border p-3">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <span className="text-sm font-medium break-words">{b.name}</span>
                {b.managed && (
                  <Badge
                    variant="outline"
                    className="text-xs"
                    title={t(
                      'org.teamRoles.managedHint',
                      'Set by the Access tab; it cannot be changed here'
                    )}
                  >
                    {t('org.teamRoles.managed', 'Preset')}
                  </Badge>
                )}
                {b.privileged && (
                  <Badge
                    variant="outline"
                    className="gap-1 text-xs"
                    title={t(
                      'org.teamRoles.privilegedHint',
                      'Grants an administrator-level permission: only an owner changes this team'
                    )}
                  >
                    <ShieldAlert className="h-3 w-3" />
                    {t('org.teamRoles.privileged', 'Privileged')}
                  </Badge>
                )}
                {fullData.has(b.role_id) && (
                  <Badge
                    variant="outline"
                    className="text-xs"
                    title={t(
                      'org.teamRoles.fullDataHint',
                      'Members see every asset; external members and service accounts cannot join'
                    )}
                  >
                    {t('org.teamRoles.fullData', 'Full data access')}
                  </Badge>
                )}
              </div>
              {canUnbind && !b.managed && (
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={t('org.teamRoles.removeAria', 'Remove role {name}', { name: b.name })}
                  title={t('org.teamRoles.removeTitle', 'Remove')}
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
        open={confirmBind}
        onOpenChange={setConfirmBind}
        title={t('confirm.team.bindRoleTitle', 'Add the role {name} to the team?', {
          name: allRoles.find((r) => r.id === selected)?.name ?? '',
        })}
        desc={
          memberCount !== undefined
            ? t(
                'confirm.team.bindRoleDescCount',
                'All {count} members of the team get every permission of this role at once, and so does everyone who joins later. You can remove the role again.',
                { count: memberCount }
              )
            : t(
                'confirm.team.bindRoleDesc',
                'Every member of the team gets every permission of this role at once, and so does everyone who joins later. You can remove the role again.'
              )
        }
        confirmText={t('confirm.team.bindRoleConfirm', 'Add role')}
        handleConfirm={handleBind}
      />

      <ConfirmDialog
        open={!!toRemove}
        onOpenChange={(o) => !o && setToRemove(null)}
        title={t('confirm.team.removeRoleTitle', 'Remove the role {name} from the team?', {
          name: toRemove?.name ?? '',
        })}
        desc={t(
          'confirm.team.removeRoleDesc',
          'Members who hold it only through this team lose its permissions at once.'
        )}
        confirmText={
          busy
            ? t('confirm.removing', 'Removing…')
            : t('confirm.team.removeRoleButton', 'Remove role')
        }
        destructive
        isLoading={busy}
        handleConfirm={() => void handleUnbind()}
      />
    </div>
  )
}
