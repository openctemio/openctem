'use client'

import { useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import type { ColumnDef } from '@tanstack/react-table'
import { Link2 } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { OneTimeLinkDialog } from '@/components/one-time-link-dialog'
import {
  DataTable,
  ErrorState,
  PendingSetupBadge,
  RelativeTime,
  StackedCell,
} from '@/features/shared'
import { issueOwnerSetupLink, useOrganizationUsers } from '../api/use-admin-organizations'
import { AdminConfirmDialog } from './admin-confirm-dialog'
import type { AdminOrganizationUser, AdminOwnerInvitation } from '../types'
import { CreateFirstOwnerDialog } from './create-first-owner-dialog'
import { OwnerInvitationPanel } from './owner-invitation'
import { OwnerRecoveryDialog } from './owner-recovery-dialog'

function useUserColumns(
  onSetupLink?: (u: AdminOrganizationUser) => void
): ColumnDef<AdminOrganizationUser>[] {
  const { t } = useTranslation()
  const columns: ColumnDef<AdminOrganizationUser>[] = [
    {
      accessorKey: 'name',
      header: t('admin.organizationUsersSection.user', 'User'),
      cell: ({ row }) => (
        <StackedCell
          primary={row.original.name || row.original.email}
          secondary={row.original.email}
        />
      ),
    },
    {
      accessorKey: 'role',
      header: t('admin.organizationUsersSection.role', 'Role'),
      cell: ({ row }) => (
        <Badge variant="secondary" className="capitalize">
          {row.original.role}
        </Badge>
      ),
    },
    {
      accessorKey: 'status',
      header: t('admin.organizationUsersSection.status', 'Status'),
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
      header: t('admin.organizationUsersSection.joined', 'Joined'),
      cell: ({ row }) => <RelativeTime date={row.original.joined_at} className="text-sm" />,
    },
  ]
  if (onSetupLink) {
    columns.push({
      id: 'actions',
      header: () => <span className="sr-only">{t('common.table.actionsColumn', 'Actions')}</span>,
      cell: ({ row }) =>
        needsHandOverLink(row.original) ? (
          <Button size="sm" variant="outline" onClick={() => onSetupLink(row.original)}>
            <Link2 className="me-2 size-4" aria-hidden="true" />
            {t('admin.org.users.setupLink', 'New setup link')}
          </Button>
        ) : null,
    })
  }
  return columns
}

/** A new owner the console created who has not set a password yet. */
function needsHandOverLink(u: AdminOrganizationUser): boolean {
  return u.role === 'owner' && u.pending_setup && u.status === 'active'
}

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
  ownerInvitation,
  emailDelivery,
  onChanged,
}: {
  tenantId: string
  orgName: string
  canManage: boolean
  /** Super admin: may run an owner recovery when every owner is suspended. */
  canRecover?: boolean
  /** The organization's ownership invitation, while it waits for its first owner. */
  ownerInvitation?: AdminOwnerInvitation
  /** The organization's member count changed. */
  onChanged?: () => void
  /**
   * False: the installation cannot send email. A new owner who lost the
   * one-time link gets a new one from here, handed over by the administrator.
   */
  emailDelivery?: boolean
}) {
  const { t } = useTranslation()
  const noEmail = emailDelivery === false
  const [linkFor, setLinkFor] = useState<AdminOrganizationUser | null>(null)
  // Held only in this component's state; dropped when the dialog closes.
  const [handOver, setHandOver] = useState<{
    link: string
    expiresAt?: string
    email: string
  } | null>(null)
  const columns = useUserColumns(noEmail && canManage ? setLinkFor : undefined)

  const { data, error, isLoading, mutate } = useOrganizationUsers(tenantId)
  const refresh = () => void mutate()
  const users = data?.data ?? []
  const redacted = !!data?.redacted
  const hasOwner = users.some((u) => u.role === 'owner') || (data?.by_role?.owner ?? 0) > 0
  // The server counts the owners who can act (active membership, account
  // active and not erased); a read-only administrator gets no rows, so only
  // the count can tell. Older responses without it fall back to the rows.
  const ownersAllSuspended =
    hasOwner &&
    (data?.active_owner_count !== undefined
      ? data.active_owner_count === 0
      : !users.some((u) => u.role === 'owner' && u.status === 'active'))
  const canBootstrap = canManage && !isLoading && !error && !hasOwner
  const invitation = !isLoading && !hasOwner ? ownerInvitation : undefined
  const changed = () => {
    refresh()
    onChanged?.()
  }

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <h2 className="text-base font-semibold">
            {t('admin.organizationUsersSection.users', 'Users')}
          </h2>
          <p className="text-sm text-muted-foreground">
            {ownersAllSuspended
              ? t(
                  'admin.organizationUsersSection.everyOwnerOfThisOrganization',
                  'Every owner of this organization is suspended, blocked or erased. Such an owner still owns the organization, so the console cannot create another one; a super admin can recover ownership (with a reason and an authenticator code; the new owner gets a set-password link by email only).'
                )
              : invitation
                ? t(
                    'admin.ownerInvitation.usersHelp',
                    'This organization was created for someone who already has an account. It has no owner until they accept the invitation.'
                  )
                : hasOwner
                  ? t(
                      'admin.organizationUsersSection.peopleWithAnAccountIn',
                      "People with an account in this organization. The organization's owner and administrators invite or create users; the platform console only creates an organization's first owner."
                    )
                  : t(
                      'admin.organizationUsersSection.thisOrganizationHasNoOwner',
                      'This organization has no owner yet. Create its first owner; they add everyone else.'
                    )}
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
        {canBootstrap && !invitation && (
          <CreateFirstOwnerDialog
            tenantId={tenantId}
            onCreated={() => {
              refresh()
              onChanged?.()
            }}
          />
        )}
      </div>
      {invitation && (
        <OwnerInvitationPanel
          tenantId={tenantId}
          invitation={invitation}
          canManage={canManage}
          onChanged={changed}
          emailDelivery={emailDelivery}
          changeInvitee={
            canBootstrap ? (
              <CreateFirstOwnerDialog
                tenantId={tenantId}
                changeInvitee
                emailDelivery={emailDelivery}
                onCreated={changed}
              />
            ) : undefined
          }
        />
      )}
      {noEmail && users.some(needsHandOverLink) && (
        <p className="text-sm text-muted-foreground">
          {t(
            'admin.org.users.pendingOwnerNoEmail',
            'The owner has not set a password yet. This server cannot send email: if the one-time link shown when the owner was created is lost or expired, make a new one with New setup link and give it to them yourself.'
          )}
        </p>
      )}
      {linkFor && (
        <AdminConfirmDialog
          open
          onOpenChange={(next) => !next && setLinkFor(null)}
          title={t('admin.org.users.setupLink', 'New setup link')}
          description={
            <p>
              {t(
                'admin.org.users.setupLinkWhat',
                'This server cannot send email. Creates a new one-time link where {email} sets their password and shows it to you once, for you to hand over over a channel you trust. It works once and expires in 24 hours; any earlier link stops working.',
                { email: linkFor.email }
              )}
            </p>
          }
          confirmLabel={t('admin.org.users.setupLinkConfirm', 'Create link')}
          onConfirm={async ({ reason }) => {
            // A bearer secret: straight into the one-time dialog, nowhere else.
            const res = await issueOwnerSetupLink(linkFor.user_id, tenantId, reason)
            const link = res.setup_url
            if (!link) {
              toast.error(
                t(
                  'admin.org.users.setupLinkNoAddress',
                  'The link could not be built: set the public address (APP_URL) on the API.'
                )
              )
              return
            }
            setHandOver({ link, expiresAt: res.setup_expires_at, email: linkFor.email })
            setLinkFor(null)
          }}
        />
      )}
      <OneTimeLinkDialog
        open={!!handOver}
        onOpenChange={(next) => {
          if (!next) setHandOver(null)
        }}
        title={t('admin.org.users.setupLink', 'New setup link')}
        description={t(
          'admin.org.users.setupLinkFor',
          'Set-password link for {email}. It works once.',
          { email: handOver?.email ?? '' }
        )}
        link={handOver?.link ?? ''}
        expiresAt={handOver?.expiresAt}
      />
      {error ? (
        <ErrorState
          title={t('admin.organizationUsersSection.users2', 'users')}
          error={error}
          onRetry={refresh}
        />
      ) : redacted ? (
        <RedactedMemberCounts byRole={data?.by_role ?? {}} total={data?.total ?? 0} />
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
          emptyMessage={t('admin.organizationUsersSection.noUsersYet', 'No users yet')}
        />
      )}
    </section>
  )
}

/**
 * What a read-only administrator sees of an organization's members: how many
 * there are by role, never who (names and emails are personal data).
 */
function RedactedMemberCounts({
  byRole,
  total,
}: {
  byRole: Record<string, number>
  total: number
}) {
  const { t } = useTranslation()
  const roles = Object.entries(byRole).sort(([a], [b]) => a.localeCompare(b))
  return (
    <div className="rounded-md border p-4 text-sm">
      <p className="text-muted-foreground">
        {t(
          'admin.org.users.redacted',
          'Your console role sees how many members there are, not who they are. {count, plural, one {# member} other {# members}} in total.',
          { count: total }
        )}
      </p>
      {roles.length > 0 && (
        <ul className="mt-2 flex flex-wrap gap-3">
          {roles.map(([role, n]) => (
            <li key={role}>
              <span className="font-medium">{n}</span>{' '}
              <span className="text-muted-foreground">{role}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
