'use client'

/**
 * Service accounts: an organization-owned identity for an integration (a SIEM
 * export, a ticketing bridge) instead of a person's key. A new account holds
 * no permission; it gets a role in Roles and assets through a team, and acts
 * only through API keys minted here. The API is the authority on every rule
 * (never an owner or administrator, never full data access, never signs in).
 */

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'
import { KeyRound, Plus, ServerCog, Trash2 } from 'lucide-react'
import { Main } from '@/components/layout'
import {
  PageHeader,
  EmptyState,
  DataTable,
  DataTableColumnHeader,
  RelativeTime,
  StackedCell,
  ErrorState,
} from '@/features/shared'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { Can, Permission, useCanMutate } from '@/lib/permissions'
import { getErrorMessage } from '@/lib/api/error-handler'
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

const MAX_NAME = 100
const MAX_DESCRIPTION = 500

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
  const { trigger, isMutating } = useCreateServiceAccount()

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return toast.error(t('settings.keys.nameRequired', 'Name is required'))
    try {
      await trigger({ name: name.trim(), description: description.trim() || undefined })
      toast.success(t('settings.serviceAccounts.created', 'Service account created'))
      onOpenChange(false)
      setName('')
      setDescription('')
    } catch (error) {
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
        <DialogForm onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="sa-name">{t('settings.keys.name', 'Name')}</Label>
              <Input
                id="sa-name"
                value={name}
                maxLength={MAX_NAME}
                onChange={(e) => setName(e.target.value)}
                placeholder={t('settings.serviceAccounts.namePlaceholder', 'SIEM export')}
                required
              />
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
                name: account.name,
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
              <Button size="sm" onClick={() => setGenOpen(true)}>
                <Plus className="me-2 h-4 w-4" />
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
              <p className="text-muted-foreground text-sm">
                {t('settings.serviceAccounts.noKeys', 'No keys yet.')}
              </p>
            ) : (
              <ul className="divide-y rounded-md border">
                {keys.map((k) => (
                  <li key={k.id} className="flex items-start justify-between gap-3 p-3">
                    <div className="min-w-0 space-y-1">
                      <p className="truncate text-sm font-medium">{k.name}</p>
                      <p className="text-muted-foreground text-xs">
                        <code>{k.key_prefix}…</code>
                        {k.expires_at && (
                          <>
                            {' '}
                            · {t('settings.serviceAccounts.expires', 'expires')}{' '}
                            <RelativeTime date={k.expires_at} />
                          </>
                        )}
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {k.scopes.map((s) => (
                          <Badge key={s} variant="secondary" className="font-mono text-[10px]">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <Can route="DELETE /api/v1/service-accounts/{id}/api-keys/{key_id}">
                      <Button
                        variant="ghost"
                        size="icon"
                        title={t('confirm.delete', 'Delete')}
                        aria-label={t(
                          'confirm.serviceAccount.deleteKeyLabel',
                          'Delete key {name}',
                          {
                            name: k.name,
                          }
                        )}
                        className="text-destructive hover:text-destructive shrink-0"
                        onClick={() => setPendingDelete({ id: k.id, name: k.name })}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </Can>
                  </li>
                ))}
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
          name: account.name,
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
          name: pendingDelete?.name ?? '',
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

function AccountRowActions({
  account,
  onKeys,
}: {
  account: ServiceAccount
  onKeys: (a: ServiceAccount) => void
}) {
  const { t } = useTranslation()
  const [deleteOpen, setDeleteOpen] = useState(false)
  const { trigger: del, isMutating: deleting } = useDeleteServiceAccount()

  async function handleDelete() {
    try {
      await del(account.id)
      toast.success(t('settings.serviceAccounts.deleted', 'Service account deleted'))
      setDeleteOpen(false)
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('settings.serviceAccounts.deleteFailed', 'Failed to delete the service account')
        )
      )
    }
  }

  return (
    <div className="flex justify-end gap-1">
      <Can permission={[Permission.MembersRead, Permission.ApiKeysRead]} requireAll minRole="admin">
        <Button
          variant="ghost"
          size="sm"
          aria-label={t('settings.serviceAccounts.keysTitle', 'API keys of {name}', {
            name: account.name,
          })}
          onClick={() => onKeys(account)}
        >
          <KeyRound className="me-1 h-4 w-4" />
          {t('settings.serviceAccounts.keys', 'Keys')}
        </Button>
      </Can>
      <Can route="DELETE /api/v1/service-accounts/{id}">
        <Button
          variant="ghost"
          size="icon"
          title={t('confirm.delete', 'Delete')}
          aria-label={t('confirm.serviceAccount.deleteLabel', 'Delete {name}', {
            name: account.name,
          })}
          className="text-destructive hover:text-destructive"
          onClick={() => setDeleteOpen(true)}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </Can>
      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={t('confirm.serviceAccount.deleteTitle', 'Delete the service account {name}?', {
          name: account.name,
        })}
        desc={t(
          'confirm.serviceAccount.deleteDesc',
          'Its roles, team memberships and API keys are removed at once, and every integration using its keys stops working. This cannot be undone.'
        )}
        confirmText={deleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')}
        destructive
        isLoading={deleting}
        typeToConfirm={account.name}
        handleConfirm={() => void handleDelete()}
      />
    </div>
  )
}

export default function ServiceAccountsPage() {
  const { t } = useTranslation()
  const PAGE_TITLE = t('settings.serviceAccounts.title', 'Service accounts')
  const PAGE_DESCRIPTION = t(
    'settings.serviceAccounts.description',
    'Identities for integrations, so no integration borrows a person’s key.'
  )
  const { data, error, isLoading, mutate } = useServiceAccounts()
  const canCreate = useCanMutate('POST /api/v1/service-accounts')
  const [createOpen, setCreateOpen] = useState(false)
  const [keysFor, setKeysFor] = useState<ServiceAccount | null>(null)
  const accounts = useMemo(() => data?.data ?? [], [data])

  const columns = useMemo<ColumnDef<ServiceAccount>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('settings.keys.name', 'Name')} />
        ),
        cell: ({ row }) => (
          <StackedCell primary={row.original.name} secondary={row.original.description} />
        ),
      },
      {
        accessorKey: 'owner_name',
        header: t('settings.serviceAccounts.accountable', 'Accountable person'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.owner_name || (
            <span className="text-muted-foreground text-xs">
              {t('settings.serviceAccounts.none', 'None')}
            </span>
          ),
      },
      {
        accessorKey: 'api_keys',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('settings.apiKeys.title', 'API keys')} />
        ),
      },
      {
        accessorKey: 'created_at',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('settings.keys.created', 'Created')} />
        ),
        cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
      },
      {
        id: 'actions',
        header: () => <div className="text-end">{t('settings.keys.actions', 'Actions')}</div>,
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => <AccountRowActions account={row.original} onKeys={setKeysFor} />,
      },
    ],
    [t]
  )

  const createButton = canCreate ? (
    <Button size="sm" onClick={() => setCreateOpen(true)}>
      <Plus className="me-2 h-4 w-4" />
      {t('settings.serviceAccounts.new', 'New service account')}
    </Button>
  ) : undefined

  if (isLoading)
    return (
      <Main>
        <Skeleton className="mb-6 h-8 w-48" />
        <Skeleton className="h-64 rounded-lg" />
      </Main>
    )
  if (error)
    return (
      <Main>
        <PageHeader title={PAGE_TITLE} description={PAGE_DESCRIPTION} />
        <ErrorState title={PAGE_TITLE} error={error} onRetry={() => void mutate()} />
      </Main>
    )

  return (
    <Main>
      <PageHeader title={PAGE_TITLE} description={PAGE_DESCRIPTION}>
        {createButton}
      </PageHeader>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ServerCog className="h-5 w-5" />
            {PAGE_TITLE}
          </CardTitle>
          <CardDescription>
            {t(
              'settings.serviceAccounts.cardDescription',
              'A service account never signs in and can never be an owner, an administrator or see every asset. It holds what its roles and teams give it, and its keys carry no more.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {accounts.length === 0 ? (
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
              action={createButton}
            />
          ) : (
            <DataTable
              columns={columns}
              data={accounts}
              getRowId={(a) => a.id}
              paginationNoun={t('settings.serviceAccounts.noun', 'service accounts')}
              emptyMessage={t('settings.serviceAccounts.noAccounts', 'No service accounts')}
            />
          )}
        </CardContent>
      </Card>

      <CreateAccountDialog open={createOpen} onOpenChange={setCreateOpen} />
      {keysFor && (
        <AccountKeysSheet account={keysFor} onOpenChange={(o) => !o && setKeysFor(null)} />
      )}
    </Main>
  )
}
