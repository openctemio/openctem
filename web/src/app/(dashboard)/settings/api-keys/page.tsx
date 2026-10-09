'use client'

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
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
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Can, usePermissions, useCanMutate } from '@/lib/permissions'
import { Input } from '@/components/ui/input'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { useDebounce } from '@/hooks/use-debounce'
import { getErrorMessage } from '@/lib/api/error-handler'
import { KeyRound, Plus, Ban, Trash2 } from 'lucide-react'
import {
  useApiKeys,
  useCreateApiKey,
  useRevokeApiKey,
  useDeleteApiKey,
} from '@/features/api-keys/api/use-api-keys'
import {
  GenerateKeyDialog,
  RevealKeyDialog,
} from '@/features/api-keys/components/generate-key-dialog'
import type { APIKey } from '@/features/api-keys/types/api-key.types'
import { toast } from 'sonner'

function isExpired(k: APIKey): boolean {
  return !!k.expires_at && new Date(k.expires_at).getTime() < Date.now()
}

function isActive(k: APIKey): boolean {
  return k.status !== 'revoked' && !k.revoked_at && !isExpired(k)
}

function StatusBadge({ k }: { k: APIKey }) {
  if (k.status === 'revoked' || k.revoked_at) {
    return <Badge className="border-0 bg-red-500/10 text-red-600 dark:text-red-400">Revoked</Badge>
  }
  if (isExpired(k)) {
    return (
      <Badge className="border-0 bg-orange-500/10 text-orange-600 dark:text-orange-400">
        Expired
      </Badge>
    )
  }
  return (
    <Badge className="border-0 bg-green-500/10 text-green-600 dark:text-green-400">Active</Badge>
  )
}

// ─────────────────────────────────────────────────────────
// Row actions (revoke / delete) — inline prominent buttons
// ─────────────────────────────────────────────────────────

function KeyRowActions({ k, onChanged }: { k: APIKey; onChanged: () => void }) {
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [revokeOpen, setRevokeOpen] = useState(false)
  const { trigger: revoke, isMutating: revoking } = useRevokeApiKey()
  const { trigger: del, isMutating: deleting } = useDeleteApiKey()

  async function handleRevoke() {
    try {
      await revoke(k.id)
      toast.success('Key revoked')
      setRevokeOpen(false)
      onChanged()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to revoke the key'))
    }
  }
  async function handleDelete() {
    try {
      await del(k.id)
      toast.success('Key deleted')
      setDeleteOpen(false)
      onChanged()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to delete the key'))
    }
  }

  return (
    <div className="flex justify-end gap-1">
      {isActive(k) && (
        <Can route="POST /api/v1/api-keys">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setRevokeOpen(true)}
            disabled={revoking}
            title="Revoke"
          >
            <Ban className="h-4 w-4 text-warning" />
          </Button>
        </Can>
      )}
      <Can route="DELETE /api/v1/api-keys/{id}">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setDeleteOpen(true)}
          title="Delete"
          className="text-destructive hover:text-destructive"
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </Can>
      <ConfirmDialog
        open={revokeOpen}
        onOpenChange={setRevokeOpen}
        title={`Revoke ${k.name}?`}
        desc="Any client using this key stops working immediately. A revoked key cannot be re-enabled."
        confirmText={revoking ? 'Revoking...' : 'Revoke'}
        destructive
        isLoading={revoking}
        handleConfirm={() => void handleRevoke()}
      />
      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={`Delete ${k.name}?`}
        desc="Any client using this key will immediately lose access. This cannot be undone."
        confirmText={deleting ? 'Deleting...' : 'Delete'}
        destructive
        isLoading={deleting}
        handleConfirm={() => void handleDelete()}
      />
    </div>
  )
}

// ─────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────

function LoadingSkeleton() {
  return (
    <Main>
      <Skeleton className="mb-6 h-8 w-48" />
      <div className="grid gap-4 md:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24 rounded-lg" />
        ))}
      </div>
      <Skeleton className="mt-6 h-64 rounded-lg" />
    </Main>
  )
}

const API_KEY_PAGE_SIZES = [10, 20, 50, 100]

export default function APIKeysPage() {
  const list = useListParams({ pageSizes: API_KEY_PAGE_SIZES, defaultPageSize: 20 })
  const { pagination, setPagination, setPage } = list
  const resetPage = useCallback(() => setPage(1), [setPage])
  const [searchParam, setSearchParam] = useUrlFilter('q', '')
  const search = useDebounce(searchParam.trim(), 300)
  const { data, error, isLoading, mutate } = useApiKeys({
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
    search: search || undefined,
  })
  // Owners and administrators see every key of the organization; anyone else
  // gets only their own keys from the API, and cannot mint or revoke keys.
  const { isAdmin } = usePermissions()
  const canGenerate = useCanMutate('POST /api/v1/api-keys')
  const ownKeysOnly = !isAdmin()
  const [genOpen, setGenOpen] = useState(false)
  const [newKey, setNewKey] = useState('')
  const { trigger: createKey, isMutating: creating } = useCreateApiKey()

  const keys = useMemo(() => data?.data ?? [], [data])

  const columns = useMemo<ColumnDef<APIKey>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
        cell: ({ row }) => (
          <StackedCell
            primary={row.original.name}
            secondary={<code>{row.original.key_prefix}…</code>}
          />
        ),
      },
      {
        id: 'scopes',
        header: 'Scopes',
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex flex-wrap gap-1">
            {row.original.scopes.slice(0, 3).map((s) => (
              <Badge key={s} variant="secondary" className="font-mono text-[10px]">
                {s}
              </Badge>
            ))}
            {row.original.scopes.length > 3 && (
              <Badge variant="outline" className="text-[10px]">
                +{row.original.scopes.length - 3}
              </Badge>
            )}
          </div>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        enableSorting: false,
        cell: ({ row }) => <StatusBadge k={row.original} />,
      },
      {
        accessorKey: 'last_used_at',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Last used" />,
        cell: ({ row }) =>
          row.original.last_used_at ? (
            <RelativeTime date={row.original.last_used_at} />
          ) : (
            <span className="text-muted-foreground text-xs">Never</span>
          ),
      },
      {
        accessorKey: 'expires_at',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Expires" />,
        cell: ({ row }) =>
          row.original.expires_at ? (
            <RelativeTime date={row.original.expires_at} />
          ) : (
            <span className="text-muted-foreground text-xs">Never</span>
          ),
      },
      {
        id: 'actions',
        header: () => <div className="text-end">Actions</div>,
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => <KeyRowActions k={row.original} onChanged={() => mutate()} />,
      },
    ],
    [mutate]
  )

  const total = data?.total ?? 0

  if (isLoading) return <LoadingSkeleton />
  // A failed read must not render as "No API keys yet" with all-zero stats —
  // an admin could conclude none exist and mint a duplicate key.
  if (error)
    return (
      <Main>
        <PageHeader title="API keys" description="Keys for scripts and tools that call the API." />
        <ErrorState title="API keys" error={error} onRetry={() => void mutate()} />
      </Main>
    )

  return (
    <Main>
      <PageHeader title="API keys" description="Keys for scripts and tools that call the API.">
        {canGenerate && (
          <Button size="sm" onClick={() => setGenOpen(true)}>
            <Plus className="me-2 h-4 w-4" />
            Generate API Key
          </Button>
        )}
      </PageHeader>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" />
            API Key Management
          </CardTitle>
          <CardDescription>
            {ownKeysOnly
              ? 'Your own keys. Owners and administrators see and manage every key in the organization.'
              : 'Each key is scoped to specific permissions and can be set to expire automatically.'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {total === 0 && !search ? (
            <EmptyState
              icon={KeyRound}
              title="No API keys yet"
              description={
                canGenerate
                  ? 'Generate a scoped key for programmatic access to the API.'
                  : 'Ask an owner or administrator if you need a key.'
              }
              card={false}
              action={
                canGenerate ? (
                  <Button size="sm" onClick={() => setGenOpen(true)}>
                    <Plus className="me-2 h-4 w-4" />
                    Generate API Key
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <DataTable
              columns={columns}
              data={keys}
              getRowId={(k) => k.id}
              manualPagination
              rowCount={total}
              pagination={pagination}
              onPaginationChange={setPagination}
              pageSizeOptions={API_KEY_PAGE_SIZES}
              paginationNoun="keys"
              showSearch={false}
              toolbarStart={
                <Input
                  placeholder="Search API keys..."
                  value={searchParam}
                  onChange={(e) => {
                    setSearchParam(e.target.value)
                    resetPage()
                  }}
                  className="h-9 max-w-sm"
                  aria-label="Search API keys"
                />
              }
              emptyMessage="No API keys"
              emptyDescription="No API keys match your search."
            />
          )}
        </CardContent>
      </Card>

      <GenerateKeyDialog
        open={genOpen}
        onOpenChange={setGenOpen}
        onSubmit={(req) => createKey(req)}
        isMutating={creating}
        onCreated={(plaintext) => {
          setNewKey(plaintext)
          mutate()
        }}
      />
      <RevealKeyDialog value={newKey} onClose={() => setNewKey('')} />
    </Main>
  )
}
