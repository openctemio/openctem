'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { ShieldAlert, X } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { DataTable, ErrorState, PageHeader, PageStack, StackedCell } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import {
  assignPlatformRole,
  revokePlatformRole,
  usePlatformRoleAssignments,
  usePlatformRoles,
} from '@console/features/admin-console/api/use-platform-roles'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { AdminConfirmDialog } from '@console/features/admin-console/components/admin-confirm-dialog'
import {
  adminHas,
  type PlatformRoleAssignment,
  type PlatformRoleInfo,
} from '@console/features/admin-console/types'

type Change =
  | { kind: 'assign'; target: PlatformRoleAssignment }
  | { kind: 'revoke'; target: PlatformRoleAssignment; role: string }

/**
 * Security > Roles (RFC-134): the platform roles, what each allows, and who
 * holds them. An owner gives or takes the additional roles here (step-up and a
 * reason, audited, announced); the owner, admin and read-only roles follow the
 * administrator's role on the Administrators page.
 */
export default function AdminRolesPage() {
  const me = useAdmin()
  const { t } = useTranslation()
  const canSeeHolders = adminHas(me, 'platform.admins.read')
  const canAssign = adminHas(me, 'platform.roles.assign')
  const catalog = usePlatformRoles()
  const assignments = usePlatformRoleAssignments(canSeeHolders)
  const [change, setChange] = useState<Change | null>(null)
  const [newRole, setNewRole] = useState('')

  const roleName = (key: string) =>
    t(`admin.platformRole.${key}`, catalog.data?.roles.find((r) => r.key === key)?.name ?? key)
  const additional = (catalog.data?.roles ?? []).filter((r) => !r.base)

  const roleColumns = useMemo<ColumnDef<PlatformRoleInfo>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('admin.roles.col.role', 'Role'),
        cell: ({ row }) => (
          <StackedCell
            primary={t(`admin.platformRole.${row.original.key}`, row.original.name)}
            secondary={t(`admin.platformRoleDesc.${row.original.key}`, row.original.description)}
          />
        ),
      },
      {
        id: 'kind',
        header: t('admin.roles.col.kind', 'Kind'),
        cell: ({ row }) => (
          <Badge variant="outline">
            {row.original.base
              ? t('admin.roles.kind.base', 'Base')
              : t('admin.roles.kind.additional', 'Additional')}
          </Badge>
        ),
      },
      {
        id: 'permissions',
        header: t('admin.roles.col.permissions', 'Permissions'),
        cell: ({ row }) => (
          <span className="text-muted-foreground text-sm">
            {t('admin.roles.permissionCount', '{n} permissions', {
              n: row.original.permissions.length,
            })}
          </span>
        ),
      },
      {
        accessorKey: 'holders',
        header: t('admin.roles.col.holders', 'Holders'),
      },
    ],
    [t]
  )

  const holderColumns = useMemo<ColumnDef<PlatformRoleAssignment>[]>(
    () => [
      {
        accessorKey: 'email',
        header: t('admin.roles.col.admin', 'Administrator'),
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            <StackedCell
              primary={row.original.name || row.original.email}
              secondary={row.original.email}
            />
            {row.original.break_glass && (
              <Badge variant="secondary">{t('admin.roles.breakGlass', 'Break-glass')}</Badge>
            )}
            {!row.original.active && (
              <Badge variant="secondary">{t('admin.roles.inactive', 'Inactive')}</Badge>
            )}
          </div>
        ),
      },
      {
        id: 'roles',
        header: t('admin.roles.col.roles', 'Roles'),
        cell: ({ row }) => (
          <div className="flex flex-wrap items-center gap-1">
            {row.original.roles.map((key) => {
              const removable =
                canAssign &&
                row.original.admin_id !== me.id &&
                additional.some((r) => r.key === key)
              return (
                <Badge key={key} variant="outline" className="gap-1">
                  {roleName(key)}
                  {removable && (
                    <button
                      type="button"
                      className="hover:text-destructive"
                      aria-label={t('admin.roles.removeRole', 'Take {role}', {
                        role: roleName(key),
                      })}
                      onClick={() => setChange({ kind: 'revoke', target: row.original, role: key })}
                    >
                      <X className="size-3" />
                    </button>
                  )}
                </Badge>
              )
            })}
          </div>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) =>
          canAssign && row.original.admin_id !== me.id && row.original.active ? (
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setNewRole('')
                setChange({ kind: 'assign', target: row.original })
              }}
            >
              {t('admin.roles.giveRole', 'Give a role')}
            </Button>
          ) : null,
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t, canAssign, me.id, catalog.data]
  )

  const assignable =
    change?.kind === 'assign' ? additional.filter((r) => !change.target.roles.includes(r.key)) : []

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.nav.roles', 'Roles')}
          description={t(
            'admin.roles.description',
            'Platform roles decide what each administrator may do in the console. They never apply inside an organization.'
          )}
        />
        {catalog.data?.owners_warning && (
          <Alert>
            <ShieldAlert className="size-4" />
            <AlertTitle>
              {t('admin.roles.ownersWarningTitle', 'Fewer than two platform owners')}
            </AlertTitle>
            <AlertDescription>
              {t(
                'admin.roles.ownersWarning',
                'Keep at least two named platform owners (besides the break-glass account): with one, four-eyes approvals have no second approver and a lost account locks the platform out.'
              )}
            </AlertDescription>
          </Alert>
        )}
        {catalog.error ? (
          <ErrorState
            title={t('admin.roles.title', 'roles')}
            error={catalog.error}
            onRetry={() => void catalog.mutate()}
          />
        ) : (
          <DataTable
            columns={roleColumns}
            data={catalog.data?.roles ?? []}
            getRowId={(r) => r.key}
            isLoading={catalog.isLoading}
            showSearch={false}
            showColumnToggle={false}
            showSelectionCount={false}
            mobileCards
            emptyMessage={t('admin.roles.empty', 'No roles')}
          />
        )}
        {canSeeHolders &&
          (assignments.error ? (
            <ErrorState
              title={t('admin.roles.holdersTitle', 'role holders')}
              error={assignments.error}
              onRetry={() => void assignments.mutate()}
            />
          ) : (
            <DataTable
              columns={holderColumns}
              data={assignments.data?.data ?? []}
              getRowId={(a) => a.admin_id}
              isLoading={assignments.isLoading}
              showSearch={false}
              showColumnToggle={false}
              showSelectionCount={false}
              mobileCards
              emptyMessage={t('admin.roles.noHolders', 'No administrators')}
            />
          ))}
        {change && (
          <AdminConfirmDialog
            open
            onOpenChange={(open) => !open && setChange(null)}
            title={
              change.kind === 'assign'
                ? t('admin.roles.giveTitle', 'Give a platform role')
                : t('admin.roles.takeTitle', 'Take a platform role')
            }
            description={
              <p>
                {change.kind === 'assign'
                  ? t(
                      'admin.roles.giveWhat',
                      '{email} gets the role at once. The other administrators are told, and the change is in the audit log.',
                      { email: change.target.email }
                    )
                  : t(
                      'admin.roles.takeWhat',
                      '{email} loses {role} at once, including an elevation as that role. The other administrators are told.',
                      { email: change.target.email, role: roleName(change.role) }
                    )}
              </p>
            }
            confirmLabel={
              change.kind === 'assign'
                ? t('admin.roles.giveConfirm', 'Give role')
                : t('admin.roles.takeConfirm', 'Take role')
            }
            destructive={change.kind === 'revoke'}
            canSubmit={change.kind === 'revoke' || newRole !== ''}
            onConfirm={async ({ reason }) => {
              if (change.kind === 'assign') {
                await assignPlatformRole(change.target.admin_id, newRole, reason)
                toast.success(t('admin.roles.given', 'Role given.'))
              } else {
                await revokePlatformRole(change.target.admin_id, change.role, reason)
                toast.success(t('admin.roles.taken', 'Role taken.'))
              }
              void assignments.mutate()
              void catalog.mutate()
            }}
          >
            {change.kind === 'assign' && (
              <div className="space-y-1.5">
                <Label>{t('admin.roles.col.role', 'Role')}</Label>
                <Select value={newRole} onValueChange={setNewRole}>
                  <SelectTrigger aria-label={t('admin.roles.col.role', 'Role')}>
                    <SelectValue placeholder={t('admin.roles.pickRole', 'Choose a role')} />
                  </SelectTrigger>
                  <SelectContent>
                    {assignable.map((r) => (
                      <SelectItem key={r.key} value={r.key}>
                        {roleName(r.key)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </AdminConfirmDialog>
        )}
      </PageStack>
    </Main>
  )
}
