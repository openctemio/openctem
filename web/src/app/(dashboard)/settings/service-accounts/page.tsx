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

const MAX_NAME = 100
const MAX_DESCRIPTION = 500

function CreateAccountDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
}) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const { trigger, isMutating } = useCreateServiceAccount()

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return toast.error('Name is required')
    try {
      await trigger({ name: name.trim(), description: description.trim() || undefined })
      toast.success('Service account created')
      onOpenChange(false)
      setName('')
      setDescription('')
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to create the service account'))
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>New service account</DialogTitle>
          <DialogDescription>
            It starts with no permissions. Give it a role in Roles and add it to a team for the
            assets it may see. You are recorded as the person accountable for it.
          </DialogDescription>
        </DialogHeader>
        <DialogForm onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="sa-name">Name</Label>
              <Input
                id="sa-name"
                value={name}
                maxLength={MAX_NAME}
                onChange={(e) => setName(e.target.value)}
                placeholder="SIEM export"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="sa-desc">Description (optional)</Label>
              <Textarea
                id="sa-desc"
                value={description}
                maxLength={MAX_DESCRIPTION}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="What the integration does and who runs it"
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={isMutating}>
              {isMutating ? 'Creating...' : 'Create'}
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
      toast.success('Key deleted')
      setPendingDelete(null)
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to delete the key'))
    }
  }

  return (
    <>
      <Sheet open onOpenChange={onOpenChange}>
        <SheetContent className="w-full sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>API keys of {account.name}</SheetTitle>
            <SheetDescription>
              A key acts as this service account: it carries only the scopes you give it that the
              account also holds, sees only the account&apos;s assets, and is read-only.
            </SheetDescription>
          </SheetHeader>
          <SheetBody className="space-y-3">
            {canMint && (
              <Button size="sm" onClick={() => setGenOpen(true)}>
                <Plus className="me-2 h-4 w-4" />
                Generate key
              </Button>
            )}
            {isLoading ? (
              <Skeleton className="h-24 rounded-lg" />
            ) : error ? (
              <ErrorState title="API keys" error={error} onRetry={() => void mutate()} />
            ) : keys.length === 0 ? (
              <p className="text-muted-foreground text-sm">No keys yet.</p>
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
                            · expires <RelativeTime date={k.expires_at} />
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
                        title="Delete key"
                        aria-label={`Delete key ${k.name}`}
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
        title={`Generate a key for ${account.name}`}
        description="Only scopes you hold yourself can be given. The secret is shown once."
        namePlaceholder="Production connector"
      />
      <RevealKeyDialog value={newKey} onClose={() => setNewKey('')} />
      <ConfirmDialog
        open={!!pendingDelete}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        title={`Delete ${pendingDelete?.name ?? 'key'}?`}
        desc="The integration using this key loses access immediately. This cannot be undone."
        confirmText={deleting ? 'Deleting...' : 'Delete'}
        destructive
        isLoading={deleting}
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
  const [deleteOpen, setDeleteOpen] = useState(false)
  const { trigger: del, isMutating: deleting } = useDeleteServiceAccount()

  async function handleDelete() {
    try {
      await del(account.id)
      toast.success('Service account deleted')
      setDeleteOpen(false)
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to delete the service account'))
    }
  }

  return (
    <div className="flex justify-end gap-1">
      <Can permission={[Permission.MembersRead, Permission.ApiKeysRead]} requireAll>
        <Button
          variant="ghost"
          size="sm"
          aria-label={`API keys of ${account.name}`}
          onClick={() => onKeys(account)}
        >
          <KeyRound className="me-1 h-4 w-4" />
          Keys
        </Button>
      </Can>
      <Can route="DELETE /api/v1/service-accounts/{id}">
        <Button
          variant="ghost"
          size="icon"
          title="Delete"
          aria-label={`Delete ${account.name}`}
          className="text-destructive hover:text-destructive"
          onClick={() => setDeleteOpen(true)}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </Can>
      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={`Delete ${account.name}?`}
        desc="Its roles, team memberships and API keys are removed at once; every integration using its keys stops working. This cannot be undone."
        confirmText={deleting ? 'Deleting...' : 'Delete'}
        destructive
        isLoading={deleting}
        handleConfirm={() => void handleDelete()}
      />
    </div>
  )
}

const PAGE_TITLE = 'Service accounts'
const PAGE_DESCRIPTION = 'Identities for integrations, so no integration borrows a person’s key.'

export default function ServiceAccountsPage() {
  const { data, error, isLoading, mutate } = useServiceAccounts()
  const canCreate = useCanMutate('POST /api/v1/service-accounts')
  const [createOpen, setCreateOpen] = useState(false)
  const [keysFor, setKeysFor] = useState<ServiceAccount | null>(null)
  const accounts = useMemo(() => data?.data ?? [], [data])

  const columns = useMemo<ColumnDef<ServiceAccount>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
        cell: ({ row }) => (
          <StackedCell primary={row.original.name} secondary={row.original.description} />
        ),
      },
      {
        accessorKey: 'owner_name',
        header: 'Accountable person',
        enableSorting: false,
        cell: ({ row }) =>
          row.original.owner_name || <span className="text-muted-foreground text-xs">None</span>,
      },
      {
        accessorKey: 'api_keys',
        header: ({ column }) => <DataTableColumnHeader column={column} title="API keys" />,
      },
      {
        accessorKey: 'created_at',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Created" />,
        cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
      },
      {
        id: 'actions',
        header: () => <div className="text-end">Actions</div>,
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => <AccountRowActions account={row.original} onKeys={setKeysFor} />,
      },
    ],
    []
  )

  const createButton = canCreate ? (
    <Button size="sm" onClick={() => setCreateOpen(true)}>
      <Plus className="me-2 h-4 w-4" />
      New service account
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
            A service account never signs in and can never be an owner, an administrator or see
            every asset. It holds what its roles and teams give it, and its keys carry no more.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {accounts.length === 0 ? (
            <EmptyState
              icon={ServerCog}
              title="No service accounts yet"
              description={
                canCreate
                  ? 'Create one for each integration, then generate its keys.'
                  : 'Ask an owner or administrator to create one for your integration.'
              }
              card={false}
              action={createButton}
            />
          ) : (
            <DataTable
              columns={columns}
              data={accounts}
              getRowId={(a) => a.id}
              paginationNoun="service accounts"
              emptyMessage="No service accounts"
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
