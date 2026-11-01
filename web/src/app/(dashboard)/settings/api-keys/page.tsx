'use client'

import { HealthStatus } from '@/components/ui/health-status'
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
  PageStack,
} from '@/features/shared'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { usePermissions, useCanMutate } from '@/lib/permissions'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { DataTableRowActions } from '@/features/shared/components/data-table-row-actions'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { useSearchQuery } from '@/hooks/use-search-query'
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
import { APIKeyPolicyCard } from '@/features/api-keys/components/api-key-policy-card'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'

function isExpired(k: APIKey): boolean {
  return !!k.expires_at && new Date(k.expires_at).getTime() < Date.now()
}

function isActive(k: APIKey): boolean {
  return k.status !== 'revoked' && !k.revoked_at && !isExpired(k)
}

function StatusBadge({ k }: { k: APIKey }) {
  const { t } = useTranslation()
  if (k.status === 'revoked' || k.revoked_at) {
    return <HealthStatus state="off" label={t('settings.keys.status.revoked', 'Revoked')} />
  }
  if (isExpired(k)) {
    return <HealthStatus state="down" label={t('settings.keys.status.expired', 'Expired')} />
  }
  return <HealthStatus state="ok" label={t('settings.keys.status.active', 'Active')} />
}

// ─────────────────────────────────────────────────────────
// Row actions (revoke / delete) — inline prominent buttons
// ─────────────────────────────────────────────────────────

function KeyRowActions({ k, onChanged }: { k: APIKey; onChanged: () => void }) {
  const { t } = useTranslation()
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [revokeOpen, setRevokeOpen] = useState(false)
  const { trigger: revoke, isMutating: revoking } = useRevokeApiKey()
  const { trigger: del, isMutating: deleting } = useDeleteApiKey()

  async function handleRevoke() {
    try {
      await revoke(k.id)
      toast.success(t('settings.apiKeys.revoked', 'Key revoked'))
      setRevokeOpen(false)
      onChanged()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('settings.apiKeys.revokeFailed', 'Failed to revoke the key'))
      )
    }
  }
  async function handleDelete() {
    try {
      await del(k.id)
      toast.success(t('settings.apiKeys.deleted', 'Key deleted'))
      setDeleteOpen(false)
      onChanged()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('settings.apiKeys.deleteFailed', 'Failed to delete the key'))
      )
    }
  }

  return (
    <div className="flex justify-end gap-1">
      <DataTableRowActions
        label={t('settings.apiKeys.actionsFor', 'Actions for {name}', { name: k.name })}
        actions={[
          ...(isActive(k)
            ? [
                {
                  label: t('confirm.revoke', 'Revoke'),
                  icon: Ban,
                  route: 'POST /api/v1/api-keys/{id}/revoke' as const,
                  onClick: () => setRevokeOpen(true),
                },
              ]
            : []),
          {
            label: t('confirm.delete', 'Delete'),
            icon: Trash2,
            destructive: true,
            separatorBefore: isActive(k),
            route: 'DELETE /api/v1/api-keys/{id}' as const,
            onClick: () => setDeleteOpen(true),
          },
        ]}
      />
      <ConfirmDialog
        open={revokeOpen}
        onOpenChange={setRevokeOpen}
        title={t('confirm.apiKey.revokeTitle', 'Revoke the API key {name}?', { name: k.name })}
        desc={t(
          'confirm.apiKey.revokeDesc',
          'Every client using this key stops working at once. A revoked key cannot be re-enabled.'
        )}
        confirmText={revoking ? t('confirm.revoking', 'Revoking…') : t('confirm.revoke', 'Revoke')}
        destructive
        isLoading={revoking}
        typeToConfirm={k.name}
        handleConfirm={() => void handleRevoke()}
      />
      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={t('confirm.apiKey.deleteTitle', 'Delete the API key {name}?', { name: k.name })}
        desc={t(
          'confirm.apiKey.deleteDesc',
          'Every client using this key loses access at once, and the key leaves the list. This cannot be undone.'
        )}
        confirmText={
          deleting
            ? t('confirm.deleting', 'Deleting…')
            : t('confirm.apiKey.deleteButton', 'Delete key')
        }
        destructive
        isLoading={deleting}
        typeToConfirm={k.name}
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
      <PageStack>
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-lg" />
          ))}
        </div>
        <Skeleton className="h-64 rounded-lg" />
      </PageStack>
    </Main>
  )
}

const API_KEY_PAGE_SIZES = [10, 20, 50, 100]

export default function APIKeysPage() {
  const { t } = useTranslation()
  const list = useListParams({ pageSizes: API_KEY_PAGE_SIZES, defaultPageSize: 20 })
  const { pagination, setPagination, setPage } = list
  const resetPage = useCallback(() => setPage(1), [setPage])
  const [searchParam, setSearchParam] = useUrlFilter('q', '')
  const search = useSearchQuery(searchParam).term
  const { data, error, isLoading, mutate } = useApiKeys({
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
    search: search || undefined,
  })
  // Owners and administrators see every key of the organization; anyone else
  // gets only their own keys from the API, and cannot mint or revoke keys.
  const { isAdmin } = usePermissions()
  const canGenerate = useCanMutate('POST /api/v1/api-keys')
  const canSetPolicy = useCanMutate('PUT /api/v1/organization/settings/api-keys')
  const ownKeysOnly = !isAdmin()
  const [genOpen, setGenOpen] = useState(false)
  const [newKey, setNewKey] = useState('')
  const { trigger: createKey, isMutating: creating } = useCreateApiKey()

  const keys = useMemo(() => data?.data ?? [], [data])

  const columns = useMemo<ColumnDef<APIKey>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('settings.keys.name', 'Name')} />
        ),
        cell: ({ row }) => (
          <StackedCell
            primary={row.original.name}
            secondary={<code>{row.original.key_prefix}…</code>}
          />
        ),
      },
      {
        id: 'scopes',
        header: t('settings.keys.scopes', 'Scopes'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex flex-wrap gap-1">
            {row.original.scopes.slice(0, 3).map((s) => (
              <Badge // label-ok: a scope id
                key={s}
                variant="secondary"
                className="font-mono text-xs"
              >
                {s}
              </Badge>
            ))}
            {row.original.scopes.length > 3 && (
              <Badge variant="outline" className="text-xs">
                +{row.original.scopes.length - 3}
              </Badge>
            )}
          </div>
        ),
      },
      {
        id: 'status',
        header: t('settings.keys.status', 'Status'),
        enableSorting: false,
        cell: ({ row }) => <StatusBadge k={row.original} />,
      },
      {
        accessorKey: 'last_used_at',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('settings.keys.lastUsed', 'Last used')} />
        ),
        cell: ({ row }) =>
          row.original.last_used_at ? (
            <RelativeTime date={row.original.last_used_at} />
          ) : (
            <span className="text-muted-foreground text-xs">
              {t('settings.keys.never', 'Never')}
            </span>
          ),
      },
      {
        accessorKey: 'expires_at',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('settings.keys.expires', 'Expires')} />
        ),
        cell: ({ row }) =>
          row.original.expires_at ? (
            <span className="inline-flex items-center gap-2">
              <RelativeTime date={row.original.expires_at} />
              {row.original.exceeds_org_max && (
                <Badge
                  variant="outline"
                  title={t(
                    'settings.keys.exceedsMaxHint',
                    'Created before the organization lowered its maximum lifetime. Replace it sooner.'
                  )}
                >
                  {t('settings.keys.exceedsMax', 'Over the maximum')}
                </Badge>
              )}
            </span>
          ) : (
            <span className="text-muted-foreground text-xs">
              {t('settings.keys.never', 'Never')}
            </span>
          ),
      },
      {
        id: 'actions',
        header: () => <div className="text-end">{t('settings.keys.actions', 'Actions')}</div>,
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => <KeyRowActions k={row.original} onChanged={() => mutate()} />,
      },
    ],
    [mutate, t]
  )

  const total = data?.total ?? 0
  const pageTitle = t('settings.apiKeys.title', 'API keys')
  const pageDesc = t(
    'settings.apiKeys.description',
    'Keys for scripts and tools that call the API.'
  )

  if (isLoading) return <LoadingSkeleton />
  // A failed read must not render as "No API keys yet" with all-zero stats —
  // an admin could conclude none exist and mint a duplicate key.
  if (error)
    return (
      <Main>
        <PageStack>
          <PageHeader title={pageTitle} description={pageDesc} />
          <ErrorState title={pageTitle} error={error} onRetry={() => void mutate()} />
        </PageStack>
      </Main>
    )

  return (
    <Main>
      <PageStack>
        <PageHeader title={pageTitle} description={pageDesc}>
          {canGenerate && (
            <Button size="sm" onClick={() => setGenOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              {t('settings.apiKeys.generate', 'Generate API key')}
            </Button>
          )}
        </PageHeader>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-5 w-5" />
              {t('settings.apiKeys.cardTitle', 'API key management')}
            </CardTitle>
            <CardDescription>
              {ownKeysOnly
                ? t(
                    'settings.apiKeys.cardDescOwn',
                    'Your own keys. Owners and administrators see and manage every key in the organization.'
                  )
                : t(
                    'settings.apiKeys.cardDescAll',
                    'Each key is scoped to specific permissions and can be set to expire automatically.'
                  )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {total === 0 && !search ? (
              <EmptyState
                icon={KeyRound}
                title={t('settings.apiKeys.emptyTitle', 'No API keys yet')}
                description={
                  canGenerate
                    ? t(
                        'settings.apiKeys.emptyDescGenerate',
                        'Generate a scoped key for programmatic access to the API.'
                      )
                    : t(
                        'settings.apiKeys.emptyDescAsk',
                        'Ask an owner or administrator if you need a key.'
                      )
                }
                card={false}
                action={
                  canGenerate ? (
                    <Button size="sm" onClick={() => setGenOpen(true)}>
                      <Plus className="me-2 h-4 w-4" />
                      {t('settings.apiKeys.generate', 'Generate API key')}
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
                paginationNoun={t('settings.apiKeys.noun', 'keys')}
                showSearch={false}
                search={{
                  value: searchParam,
                  onChange: (v) => {
                    setSearchParam(v)
                    resetPage()
                  },
                  placeholder: t('settings.apiKeys.searchPlaceholder', 'Search API keys…'),
                  label: t('settings.apiKeys.searchLabel', 'Search API keys'),
                }}
                emptyMessage={t('settings.apiKeys.noKeys', 'No API keys')}
                emptyDescription={t('settings.apiKeys.noMatch', 'No API keys match your search.')}
              />
            )}
          </CardContent>
        </Card>

        {!ownKeysOnly && <APIKeyPolicyCard canEdit={canSetPolicy} />}

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
      </PageStack>
    </Main>
  )
}
