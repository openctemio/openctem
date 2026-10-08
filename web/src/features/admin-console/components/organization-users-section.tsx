'use client'

import type { ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import {
  DataTable,
  ErrorState,
  PendingSetupBadge,
  RelativeTime,
  StackedCell,
} from '@/features/shared'
import { useOrganizationUsers } from '../api/use-admin-organizations'
import type { AdminOrganizationUser } from '../types'
import { CreateFirstOwnerDialog } from './create-first-owner-dialog'
import { OwnerRecoveryDialog } from './owner-recovery-dialog'

const columns: ColumnDef<AdminOrganizationUser>[] = [
  {
    accessorKey: 'name',
    header: 'User',
    cell: ({ row }) => (
      <StackedCell
        primary={row.original.name || row.original.email}
        secondary={row.original.email}
      />
    ),
  },
  {
    accessorKey: 'role',
    header: 'Role',
    cell: ({ row }) => (
      <Badge variant="secondary" className="capitalize">
        {row.original.role}
      </Badge>
    ),
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) =>
      row.original.pending_setup && row.original.status !== 'suspended' ? (
        <PendingSetupBadge />
      ) : (
        <Badge
          variant={row.original.status === 'active' ? 'secondary' : 'outline'}
          className="capitalize"
        >
          {row.original.status}
        </Badge>
      ),
  },
  {
    accessorKey: 'joined_at',
    header: 'Joined',
    cell: ({ row }) => <RelativeTime date={row.original.joined_at} className="text-sm" />,
  },
]

/**
 * People in one organization. The platform console only bootstraps an
 * organization: "Create first owner" appears while it has no owner. A
 * suspended owner still counts (the API answers 409); recovering an
 * organization whose owners are all suspended is a super admin's explicit
 * API request (RFC-022 revision 7). After that the owner and its
 * administrators add users themselves.
 */
export function OrganizationUsersSection({
  tenantId,
  orgName,
  canManage,
  canRecover = false,
  onChanged,
}: {
  tenantId: string
  orgName: string
  canManage: boolean
  /** Super admin: may run an owner recovery when every owner is suspended. */
  canRecover?: boolean
  /** The organization's member count changed. */
  onChanged?: () => void
}) {
  const { data, error, isLoading, mutate } = useOrganizationUsers(tenantId)
  const refresh = () => void mutate()
  const users = data?.data ?? []
  const hasOwner = users.some((u) => u.role === 'owner')
  const ownersAllSuspended =
    hasOwner && !users.some((u) => u.role === 'owner' && u.status === 'active')
  const canBootstrap = canManage && !isLoading && !error && !hasOwner

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <h2 className="text-base font-semibold">Users</h2>
          <p className="text-sm text-muted-foreground">
            {ownersAllSuspended
              ? 'Every owner of this organization is suspended. A suspended owner still owns the organization, so the console cannot create another one; a super admin can recover ownership (with a reason and an authenticator code; the new owner gets a set-password link by email only).'
              : hasOwner
                ? "People with an account in this organization. The organization's owner and administrators invite or create users; the platform console only creates an organization's first owner."
                : 'This organization has no owner yet. Create its first owner; they add everyone else.'}
          </p>
        </div>
        {canRecover && ownersAllSuspended && (
          <OwnerRecoveryDialog
            tenantId={tenantId}
            orgName={orgName}
            onRecovered={() => {
              refresh()
              onChanged?.()
            }}
          />
        )}
        {canBootstrap && (
          <CreateFirstOwnerDialog
            tenantId={tenantId}
            onCreated={() => {
              refresh()
              onChanged?.()
            }}
          />
        )}
      </div>
      {error ? (
        <ErrorState title="users" error={error} onRetry={refresh} />
      ) : (
        <DataTable
          columns={columns}
          data={users}
          getRowId={(u) => u.user_id}
          isLoading={isLoading}
          showSearch={false}
          showColumnToggle={false}
          showSelectionCount={false}
          mobileCards
          emptyMessage="No users yet"
        />
      )}
    </section>
  )
}
