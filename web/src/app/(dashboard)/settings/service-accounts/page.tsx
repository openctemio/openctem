'use client'

/**
 * Service accounts (board P4-Settings-ServiceAccounts): an organization-owned
 * identity for an integration (a SIEM export, a ticketing bridge) instead of a
 * person's key. A new account holds no permission; it gets a role in Roles and
 * assets through a team, and acts only through API keys minted here. The API
 * is the authority on every rule (never an owner or administrator, never full
 * data access, never signs in); deleting an account or a key, and minting a
 * key, ask for a recent sign-in when the server says so.
 */

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'
import { KeyRound, Plus, ServerCog, Trash2 } from 'lucide-react'
import {
  EmptyState,
  DataTable,
  DataTableColumnHeader,
  RelativeTime,
  ErrorState,
  SettingsPage,
} from '@/features/shared'
import { DataTableRowActions } from '@/features/shared/components/data-table-row-actions'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { PersonPhoneCard } from '@/features/organization/components/person-phone-card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogForm,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Permission, useCanMutate, usePermissions } from '@/lib/permissions'
import { getErrorMessage } from '@/lib/api/error-handler'
import { toDisplayText } from '@/lib/untrusted-text'
import { useUrlFilter } from '@/hooks/use-url-param'
import {
  GenerateKeyDialog,
  RevealKeyDialog,
} from '@/features/api-keys/components/generate-key-dialog'
import {
  useServiceAccounts,
  useCreateServiceAccount,
  useDeleteServiceAccount,
  useServiceAccountKeys,
  useCreateServiceAccountKey,
  useDeleteServiceAccountKey,
  type ServiceAccount,
} from '@/features/service-accounts/api/use-service-accounts'
import { useTranslation } from '@/context/i18n-provider'
import { safeHref } from '@/lib/safe-href'

const MAX_NAME = 100
const MAX_DESCRIPTION = 500

const accountHref = (id: string) => `/settings/service-accounts?account=${encodeURIComponent(id)}`

function CreateAccountDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
}) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [nameError, setNameError] = useState('')
  const { trigger, isMutating } = useCreateServiceAccount()

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) {
      setNameError(t('settings.keys.nameRequired', 'Name is required'))
      return
    }
    try {
      await trigger({ name: name.trim(), description: description.trim() || undefined })
      toast.success(t('settings.serviceAccounts.created', 'Service account created'))
      onOpenChange(false)
      setName('')
      setDescription('')
    } catch (error) {
      // The dialog stays open with what was typed.
      toast.error(
        getErrorMessage(
          error,
          t('settings.serviceAccounts.createFailed', 'Failed to create the service account')
        )
      )
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('settings.serviceAccounts.new', 'New service account')}</DialogTitle>
          <DialogDescription>
            {t(
              'settings.serviceAccounts.dialogDescription',
              'It starts with no permissions. Give it a role in Roles and add it to a team for the assets it may see. You are recorded as the person accountable for it.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogForm onSubmit={handleSubmit} noValidate>
          <DialogBody className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="sa-name">{t('settings.keys.name', 'Name')}</Label>
              <Input
                id="sa-name"
                value={name}
                maxLength={MAX_NAME}
                aria-invalid={nameError ? true : undefined}
                aria-describedby={nameError ? 'sa-name-error' : undefined}
                onChange={(e) => {
                  setName(e.target.value)
                  if (nameError) setNameError('')
                }}
                placeholder={t('settings.serviceAccounts.namePlaceholder', 'SIEM export')}
              />
              {nameError && (
                <p id="sa-name-error" role="alert" className="text-cap text-destructive">
                  {nameError}
                </p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="sa-desc">
                {t('settings.keys.descriptionOptional', 'Description (optional)')}
              </Label>
              <Textarea
                id="sa-desc"
                value={description}
                maxLength={MAX_DESCRIPTION}
                onChange={(e) => setDescription(e.target.value)}
                placeholder={t(
                  'settings.serviceAccounts.descriptionPlaceholder',
                  'What the integration does and who runs it'
                )}
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={isMutating}>
              {isMutating
                ? t('settings.serviceAccounts.creating', 'Creating…')
                : t('settings.serviceAccounts.create', 'Create')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

function AccountKeysSheet({
  account,
  onOpenChange,
}: {
  account: ServiceAccount
  onOpenChange: (o: boolean) => void
}) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useServiceAccountKeys(account.id)
  const { trigger: createKey, isMutating: creating } = useCreateServiceAccountKey(account.id)
  const { trigger: deleteKey, isMutating: deleting } = useDeleteServiceAccountKey(account.id)
  const canMint = useCanMutate('POST /api/v1/service-accounts/{id}/api-keys')
  const [genOpen, setGenOpen] = useState(false)
  const [newKey, setNewKey] = useState('')
  const [pendingDelete, setPendingDelete] = useState<{ id: string; name: string } | null>(null)
  const keys = data?.data ?? []
  const accountName = toDisplayText(account.name, 120)

  async function handleDelete() {
    if (!pendingDelete) return
    try {
      await deleteKey(pendingDelete.id)
      toast.success(t('settings.apiKeys.deleted', 'Key deleted'))
      setPendingDelete(null)
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('settings.apiKeys.deleteFailed', 'Failed to delete the key'))
      )
    }
  }

  return (
    <>
      <Sheet open onOpenChange={onOpenChange}>
        <SheetContent className="w-full sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>
              {t('settings.serviceAccounts.keysTitle', 'API keys of {name}', {
                name: accountName,
              })}
            </SheetTitle>
            <SheetDescription>
              {t(
                'settings.serviceAccounts.keysDescription',
                "A key acts as this service account: it carries only the scopes you give it that the account also holds, sees only the account's assets, and is read-only."
              )}
            </SheetDescription>
          </SheetHeader>
          <SheetBody className="space-y-3">
            {canMint && (
              <Button onClick={() => setGenOpen(true)}>
                <Plus aria-hidden />
                {t('settings.serviceAccounts.generateKey', 'Generate key')}
              </Button>
            )}
            {isLoading ? (
              <Skeleton className="h-24 rounded-lg" />
            ) : error ? (
              <ErrorState
                title={t('settings.apiKeys.title', 'API keys')}
                error={error}
                onRetry={() => void mutate()}
              />
            ) : keys.length === 0 ? (
              <p className="text-body text-muted-foreground">
                {t('settings.serviceAccounts.noKeys', 'No keys yet.')}
              </p>
            ) : (
              <ul className="divide-y rounded-md border">
                {keys.map((k) => {
                  const keyName = toDisplayText(k.name, 120)
                  return (
                    <li key={k.id} className="flex items-start justify-between gap-3 p-3">
                      <div className="min-w-0 space-y-1">
                        <p className="truncate text-body font-medium">{keyName}</p>
                        <p className="text-cap text-muted-foreground">
                          <code className="font-mono">{`${k.key_prefix}…`}</code>
                          {k.expires_at && (
                            <>
                              {', '}
                              {t('settings.serviceAccounts.expires', 'expires')}{' '}
                              <RelativeTime date={k.expires_at} />
                            </>
                          )}
                        </p>
                        <p className="text-cap font-mono text-muted-foreground [overflow-wrap:anywhere]">
                          {k.scopes.join(' ')}
                        </p>
                      </div>
                      <DataTableRowActions
                        title={keyName}
                        label={t('settings.apiKeys.actionsFor', 'Actions for {name}', {
                          name: keyName,
                        })}
                        actions={[
                          {
                            label: t('confirm.apiKey.deleteButton', 'Delete key'),
                            icon: Trash2,
                            destructive: true,
                            route: 'DELETE /api/v1/service-accounts/{id}/api-keys/{key_id}',
                            onClick: () => setPendingDelete({ id: k.id, name: k.name }),
                          },
                        ]}
                      />
                    </li>
                  )
                })}
              </ul>
            )}
          </SheetBody>
        </SheetContent>
      </Sheet>
      <GenerateKeyDialog
        open={genOpen}
        onOpenChange={setGenOpen}
        onSubmit={(req) => createKey(req)}
        isMutating={creating}
        onCreated={setNewKey}
        title={t('settings.serviceAccounts.generateFor', 'Generate a key for {name}', {
          name: accountName,
        })}
        description={t(
          'settings.serviceAccounts.generateDescription',
          'Only scopes you hold yourself can be given. The secret is shown once.'
        )}
        namePlaceholder={t('settings.serviceAccounts.keyNamePlaceholder', 'Production connector')}
      />
      <RevealKeyDialog value={newKey} onClose={() => setNewKey('')} />
      <ConfirmDialog
        open={!!pendingDelete}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        title={t('confirm.serviceAccount.deleteKeyTitle', 'Delete the key {name}?', {
          name: pendingDelete ? toDisplayText(pendingDelete.name, 120) : '',
        })}
        desc={t(
          'confirm.serviceAccount.deleteKeyDesc',
          'The integration using this key loses access at once. This cannot be undone.'
        )}
        confirmText={deleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')}
        destructive
        isLoading={deleting}
        typeToConfirm={pendingDelete?.name}
        handleConfirm={() => void handleDelete()}
      />
    </>
  )
}

export default function ServiceAccountsPage() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useServiceAccounts()
  const canCreate = useCanMutate('POST /api/v1/service-accounts')
  // Listing an account's keys is for owners and administrators who can read
  // members and API keys (the API's gate on GET .../api-keys).
  const { isAdmin, can } = usePermissions()
  const canSeeKeys = isAdmin() && can(Permission.MembersRead) && can(Permission.ApiKeysRead)
  const canDeleteAccount = useCanMutate('DELETE /api/v1/service-accounts/{id}')
  const [createOpen, setCreateOpen] = useState(false)
  const [toDelete, setToDelete] = useState<ServiceAccount | null>(null)
  const { trigger: del, isMutating: deleting } = useDeleteServiceAccount()
  const [accountParam, setAccountParam] = useUrlFilter('account', '')
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const accounts = useMemo(() => data?.data ?? [], [data])
  const keysFor = canSeeKeys ? (accounts.find((a) => a.id === accountParam) ?? null) : null
  const openKeys = useCallback(
    (a: ServiceAccount | null) => setAccountParam(a?.id ?? ''),
    [setAccountParam]
  )

  const shown = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return accounts
    return accounts.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        !!a.description?.toLowerCase().includes(q) ||
        !!a.owner_name?.toLowerCase().includes(q)
    )
  }, [accounts, searchQuery])

  async function handleDelete() {
    if (!toDelete) return
    try {
      await del(toDelete.id)
      toast.success(t('settings.serviceAccounts.deleted', 'Service account deleted'))
      setToDelete(null)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('settings.serviceAccounts.deleteFailed', 'Failed to delete the service account')
        )
      )
    }
  }

  const accountMenu = useCallback(
    (a: ServiceAccount) => {
      if (!canDeleteAccount) return null
      const name = toDisplayText(a.name, 120)
      return (
        <DataTableRowActions
          title={name}
          label={t('common.rowActions.actionsFor', 'Actions for {name}', { name })}
          actions={[
            ...(canSeeKeys
              ? [
                  {
                    label: t('settings.serviceAccounts.keysTitle', 'API keys of {name}', { name }),
                    icon: KeyRound,
                    onClick: () => openKeys(a),
                  },
                ]
              : []),
            {
              label: t('settings.serviceAccounts.deleteAccount', 'Delete service account'),
              icon: Trash2,
              destructive: true,
              separatorBefore: true,
              route: 'DELETE /api/v1/service-accounts/{id}',
              onClick: () => setToDelete(a),
            },
          ]}
        />
      )
    },
    [t, openKeys, canSeeKeys, canDeleteAccount]
  )

  const nameLabel = t('settings.keys.name', 'Name')
  const accountableLabel = t('settings.serviceAccounts.accountable', 'Accountable person')
  const keysLabel = t('settings.apiKeys.title', 'API keys')

  const columns = useMemo<ColumnDef<ServiceAccount>[]>(
    () => [
      {
        accessorKey: 'name',
        meta: { kind: 'name', pin: 'start', minWidth: 220, label: nameLabel },
        enableHiding: false,
        header: ({ column }) => <DataTableColumnHeader column={column} title={nameLabel} />,
        cell: ({ row }) => {
          const a = row.original
          const name = toDisplayText(a.name, 200)
          return (
            <div className="min-w-0">
              {canSeeKeys ? (
                <RowNameLink
                  href={safeHref(accountHref(a.id)) ?? '/settings/service-accounts'}
                  onOpen={() => openKeys(a)}
                  title={name}
                  className="block"
                >
                  {name}
                </RowNameLink>
              ) : (
                <p className="truncate font-medium">{name}</p>
              )}
              {a.description && (
                <p className="text-cap text-muted-foreground truncate">
                  {toDisplayText(a.description, 300)}
                </p>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'owner_name',
        meta: { kind: 'owner', width: 200, label: accountableLabel },
        header: ({ column }) => <DataTableColumnHeader column={column} title={accountableLabel} />,
        cell: ({ row }) =>
          row.original.owner_name ? (
            <span className="block truncate">{toDisplayText(row.original.owner_name, 120)}</span>
          ) : (
            <span className="text-muted-foreground">
              {t('settings.serviceAccounts.unassigned', 'Unassigned')}
            </span>
          ),
      },
      {
        accessorKey: 'api_keys',
        meta: { kind: 'number', label: keysLabel },
        header: ({ column }) => <DataTableColumnHeader column={column} title={keysLabel} />,
        cell: ({ row }) => <span className="tabular-nums">{row.original.api_keys}</span>,
      },
      {
        id: 'actions',
        meta: { kind: 'actions' },
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => accountMenu(row.original),
      },
    ],
    [t, nameLabel, accountableLabel, keysLabel, canSeeKeys, openKeys, accountMenu]
  )

  const createButton = (
    <Button onClick={() => setCreateOpen(true)}>
      <Plus aria-hidden />
      {t('settings.serviceAccounts.new', 'New service account')}
    </Button>
  )

  return (
    <SettingsPage
      wide
      title={t('settings.serviceAccounts.title', 'Service accounts')}
      description={t(
        'settings.serviceAccounts.description',
        'Identities for integrations, so no integration borrows a person’s key.'
      )}
      readOnly={
        !canCreate
          ? t(
              'settings.serviceAccounts.readOnly',
              'View only. Only owners and administrators can change service accounts.'
            )
          : undefined
      }
      actions={canCreate ? createButton : undefined}
    >
      <p className="max-w-[72ch] text-body text-muted-foreground text-pretty">
        {t(
          'settings.serviceAccounts.cardDescription',
          'A service account never signs in and can never be an owner, an administrator or see every asset. It holds what its roles and teams give it, and its keys carry no more.'
        )}
      </p>

      <DataTable
        columns={columns}
        data={shown}
        getRowId={(a) => a.id}
        error={error}
        onRetry={() => void mutate()}
        errorTitle={t('settings.serviceAccounts.subject', 'service accounts')}
        isLoading={isLoading && !data}
        showSearch={false}
        search={{
          value: searchQuery,
          onChange: setSearchQuery,
          placeholder: t('settings.serviceAccounts.searchPlaceholder', 'Search service accounts…'),
          label: t('settings.serviceAccounts.searchLabel', 'Search service accounts'),
        }}
        showToolbar={accounts.length > 0 || !!error}
        onRowClick={canSeeKeys ? (a) => openKeys(a) : undefined}
        showPagination={shown.length > 25}
        paginationNoun={t('settings.serviceAccounts.noun', 'service accounts')}
        mobileRow={(a) => (
          <PersonPhoneCard
            title={toDisplayText(a.name, 200)}
            address={a.description ? toDisplayText(a.description, 300) : undefined}
            onOpen={canSeeKeys ? () => openKeys(a) : undefined}
            menu={accountMenu(a)}
            facts={
              <span className="text-cap text-muted-foreground">
                {t(
                  'settings.serviceAccounts.card.line',
                  '{keys, plural, one {# key} other {# keys}}, accountable: {person}',
                  {
                    keys: a.api_keys,
                    person: a.owner_name
                      ? toDisplayText(a.owner_name, 120)
                      : t('settings.serviceAccounts.unassigned', 'Unassigned'),
                  }
                )}
              </span>
            }
          />
        )}
        isFiltered={searchQuery.trim() !== ''}
        onClearFilters={() => setSearchQuery('')}
        emptyState={{
          nothingYet: (
            <EmptyState
              icon={ServerCog}
              title={t('settings.serviceAccounts.emptyTitle', 'No service accounts yet')}
              description={
                canCreate
                  ? t(
                      'settings.serviceAccounts.emptyDescCreate',
                      'Create one for each integration, then generate its keys.'
                    )
                  : t(
                      'settings.serviceAccounts.emptyDescAsk',
                      'Ask an owner or administrator to create one for your integration.'
                    )
              }
              card={false}
            />
          ),
          noMatch: {
            title: t('settings.serviceAccounts.noMatch', 'No service accounts match your search'),
            hint: t(
              'settings.serviceAccounts.noMatchHint',
              'Try another name, or clear the search.'
            ),
          },
        }}
      />

      <CreateAccountDialog open={createOpen} onOpenChange={setCreateOpen} />
      {keysFor && <AccountKeysSheet account={keysFor} onOpenChange={(o) => !o && openKeys(null)} />}
      <ConfirmDialog
        open={!!toDelete}
        onOpenChange={(o) => !o && setToDelete(null)}
        title={t('confirm.serviceAccount.deleteTitle', 'Delete the service account {name}?', {
          name: toDelete ? toDisplayText(toDelete.name, 120) : '',
        })}
        desc={
          toDelete
            ? t(
                'confirm.serviceAccount.deleteImpact',
                'Its roles, team memberships and {keys, plural, =0 {API keys} one {# API key} other {# API keys}} are removed at once, and every integration using its keys stops working. This cannot be undone.',
                { keys: toDelete.api_keys }
              )
            : ''
        }
        confirmText={deleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')}
        destructive
        isLoading={deleting}
        typeToConfirm={toDelete?.name}
        handleConfirm={() => void handleDelete()}
      />
    </SettingsPage>
  )
}
