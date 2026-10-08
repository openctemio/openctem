'use client'

/**
 * Who can see this asset besides its groups: explicit per-user data-scope
 * grants. Being an owner gives no access (owner decision O1); a group
 * assignment or one of these grants does. Shown to team:groups:read, edited
 * with team:groups:write, the permissions that already manage data scope.
 */

import { PICKER_MEMBER_STATUS } from '@/features/organization/api/use-members'
import { useMemo, useState } from 'react'
import useSWR from 'swr'
import { KeyRound, Trash2, UserPlus } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { get } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTenant } from '@/context/tenant-provider'
import { useDebounce } from '@/hooks/use-debounce'
import {
  useAssetAccessGrants,
  createAssetAccessGrant,
  deleteAssetAccessGrant,
  type AssetAccessGrant,
} from '../hooks/use-asset-access-grants'

interface MemberOption {
  user_id: string
  email: string
  name: string
}

interface MembersResponse {
  data: MemberOption[]
}

export function AssetAccessGrantsSection({ assetId }: { assetId: string }) {
  const { can } = usePermissions()
  const canRead = can(Permission.GroupsRead)
  const canWrite = can(Permission.GroupsWrite)
  const { grants, isLoading, mutate } = useAssetAccessGrants(canRead ? assetId : null)

  const [adding, setAdding] = useState(false)
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebounce(search, 250)
  const [busy, setBusy] = useState(false)
  const [revokeTarget, setRevokeTarget] = useState<AssetAccessGrant | null>(null)

  const { currentTenant } = useTenant()
  const membersUrl =
    adding && currentTenant?.slug && debouncedSearch.trim()
      ? `/api/v1/tenants/${currentTenant.slug}/members?${new URLSearchParams({
          include: 'user',
          per_page: '10',
          search: debouncedSearch.trim(),
          // Grant picker: active members only (the API refuses anyone else).
          status: PICKER_MEMBER_STATUS,
        }).toString()}`
      : null
  const { data: members } = useSWR<MembersResponse>(membersUrl, (url: string) =>
    get<MembersResponse>(url)
  )

  const granted = useMemo(() => new Set(grants.map((g) => g.userId)), [grants])
  const options = (members?.data ?? []).filter((m) => m.user_id && !granted.has(m.user_id))

  if (!canRead) return null

  const grant = async (userId: string) => {
    setBusy(true)
    try {
      await createAssetAccessGrant(assetId, userId)
      toast.success('Access granted')
      setSearch('')
      setAdding(false)
      await mutate()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to grant access'))
    } finally {
      setBusy(false)
    }
  }

  const revoke = async () => {
    if (!revokeTarget) return
    setBusy(true)
    try {
      await deleteAssetAccessGrant(assetId, revokeTarget.id)
      toast.success('Access revoked')
      setRevokeTarget(null)
      await mutate()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to revoke access'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-3 border-t pt-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-muted-foreground" />
          <h3 className="text-sm font-medium">Direct access ({isLoading ? '…' : grants.length})</h3>
        </div>
        {canWrite && !adding && (
          <Button variant="outline" size="sm" onClick={() => setAdding(true)}>
            <UserPlus className="me-1.5 h-3.5 w-3.5" />
            Grant access
          </Button>
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        Members who see this asset (and its findings) without a group that holds it. Restricted
        members see only the assets of their groups and these grants.
      </p>

      {adding && (
        <div className="space-y-2 rounded-lg border p-3">
          <Input
            autoFocus
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search members by name or email…"
            className="h-8 text-sm"
            aria-label="Search members"
          />
          {debouncedSearch.trim() && options.length === 0 && (
            <p className="text-xs text-muted-foreground">No member without access matches.</p>
          )}
          <ul className="space-y-1">
            {options.map((m) => (
              <li key={m.user_id} className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <p className="truncate text-sm">{m.name?.trim() || m.email}</p>
                  {m.name?.trim() && (
                    <p className="truncate text-xs text-muted-foreground">{m.email}</p>
                  )}
                </div>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={busy}
                  onClick={() => grant(m.user_id)}
                >
                  Grant
                </Button>
              </li>
            ))}
          </ul>
          <div className="flex justify-end">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setAdding(false)
                setSearch('')
              }}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {!isLoading && grants.length === 0 ? (
        <p className="text-sm text-muted-foreground">No direct access grants.</p>
      ) : (
        <ul className="space-y-2">
          {grants.map((g) => (
            <li key={g.id} className="flex items-center justify-between rounded-lg border p-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium">
                    {g.userName || g.userEmail || 'Unknown user'}
                  </span>
                  {g.source === 'migration' && (
                    <Badge variant="outline" title="Created from this member's former owner access">
                      From ownership
                    </Badge>
                  )}
                </div>
                {g.userEmail && g.userName && (
                  <p className="truncate text-xs text-muted-foreground">{g.userEmail}</p>
                )}
                {g.grantedByName && (
                  <p className="text-xs text-muted-foreground">Granted by {g.grantedByName}</p>
                )}
              </div>
              {canWrite && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-destructive hover:text-destructive"
                  aria-label={`Revoke access for ${g.userName || g.userEmail || 'user'}`}
                  onClick={() => setRevokeTarget(g)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}

      <ConfirmDialog
        open={!!revokeTarget}
        onOpenChange={(open) => !open && setRevokeTarget(null)}
        title="Revoke access"
        desc={
          <>
            {revokeTarget?.userName || revokeTarget?.userEmail || 'This member'} will no longer see
            this asset unless one of their groups holds it.
          </>
        }
        confirmText={busy ? 'Revoking...' : 'Revoke'}
        destructive
        isLoading={busy}
        handleConfirm={revoke}
      />
    </div>
  )
}
