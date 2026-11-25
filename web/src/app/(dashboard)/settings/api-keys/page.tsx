'use client'

import { HealthStatus } from '@/components/ui/health-status'
import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import {
  EmptyState,
  DataTable,
  DataTableColumnHeader,
  RelativeTime,
  SettingsPage,
} from '@/features/shared'
import { PersonPhoneCard } from '@/features/organization/components/person-phone-card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { usePermissions, useCanMutate } from '@/lib/permissions'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { DataTableRowActions } from '@/features/shared/components/data-table-row-actions'
import { useListParams } from '@/hooks/use-list-params'
import { getErrorMessage } from '@/lib/api/error-handler'
import { toDisplayText } from '@/lib/untrusted-text'
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
import { APIKeyPolicySection } from '@/features/api-keys/components/api-key-policy-card'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissionLabel } from '@/lib/use-permission-label'

/**
 * API keys (board P4-Settings-ApiKeys): the organization's maximum key
 * lifetime (owners and administrators) and the keys list, server paged,
 * searched and sorted. Generate is the page's one main action; the secret is
 * shown once. Anyone who is not an owner or administrator gets only their own
 * keys from the API.
 */

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

function ExpiryCell({ k }: { k: APIKey }) {
  const { t } = useTranslation()
  // A revoked key never expires: it stopped working when it was revoked.
  if (k.status === 'revoked' || k.revoked_at) {
    return (
      <span className="text-muted-foreground" data-testid="key-expiry-revoked">
        {t('settings.keys.status.revoked', 'Revoked')}
      </span>
    )
  }
  if (!k.expires_at) {
    return <span className="text-muted-foreground">{t('settings.keys.noExpiry', 'No expiry')}</span>
  }
  return (
    <span className="inline-flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
      <RelativeTime date={k.expires_at} />
      {k.exceeds_org_max && (
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
  )
}

// ─────────────────────────────────────────────────────────
// Row actions (revoke / delete), each behind a confirmation
// ─────────────────────────────────────────────────────────

function KeyRowActions({ k, onChanged }: { k: APIKey; onChanged: () => void }) {
  const { t } = useTranslation()
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [revokeOpen, setRevokeOpen] = useState(false)
  const { trigger: revoke, isMutating: revoking } = useRevokeApiKey()
  const { trigger: del, isMutating: deleting } = useDeleteApiKey()
  const name = toDisplayText(k.name, 120)

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
    <>
      <DataTableRowActions
        title={name}
        label={t('settings.apiKeys.actionsFor', 'Actions for {name}', { name })}
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
            label: t('confirm.apiKey.deleteButton', 'Delete key'),
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
        title={t('confirm.apiKey.revokeTitle', 'Revoke the API key {name}?', { name })}
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
        title={t('confirm.apiKey.deleteTitle', 'Delete the API key {name}?', { name })}
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
    </>
  )
}

// ─────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────

const API_KEY_PAGE_SIZES = [25, 50, 100]
const API_KEY_SORT_FIELDS = ['name', 'last_used_at', 'expires_at', 'created_at'] as const

/** Table frame widths (px) under which a column folds away; the name, the status and the actions stay. */
const API_KEY_HIDE_BELOW = { scopes: 1100, lastUsed: 980, key: 780, expires: 600 } as const

export default function APIKeysPage() {
  const { t } = useTranslation()
  const permissionLabel = usePermissionLabel()
  const list = useListParams({
    pageSizes: API_KEY_PAGE_SIZES,
    sortFields: API_KEY_SORT_FIELDS,
  })
  const { data, error, isLoading, isValidating, mutate } = useApiKeys({
    page: list.page,
    perPage: list.perPage,
    search: list.searchTerm || undefined,
    sort: list.sort || undefined,
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
  const total = data?.total ?? 0

  const nameLabel = t('settings.keys.name', 'Name')
  const keyLabel = t('settings.keys.key', 'Key')
  const scopesLabel = t('settings.keys.scopes', 'Scopes')
  const statusLabel = t('settings.keys.status', 'Status')
  const lastUsedLabel = t('settings.keys.lastUsed', 'Last used')
  const expiresLabel = t('settings.keys.expires', 'Expires')

  const columns = useMemo<ColumnDef<APIKey>[]>(
    () => [
      {
        accessorKey: 'name',
        meta: { kind: 'name', pin: 'start', minWidth: 200, label: nameLabel },
        enableHiding: false,
        header: ({ column }) => <DataTableColumnHeader column={column} title={nameLabel} />,
        cell: ({ row }) => (
          <div className="min-w-0">
            <p className="truncate font-medium">{toDisplayText(row.original.name, 200)}</p>
            {row.original.description && (
              <p className="text-cap text-muted-foreground truncate">
                {toDisplayText(row.original.description, 300)}
              </p>
            )}
          </div>
        ),
      },
      {
        id: 'key',
        meta: { kind: 'id', width: 140, label: keyLabel, hideBelow: API_KEY_HIDE_BELOW.key },
        enableSorting: false,
        header: keyLabel,
        cell: ({ row }) => (
          <code className="font-mono text-cap">{`${row.original.key_prefix}…`}</code>
        ),
      },
      {
        id: 'scopes',
        meta: { kind: 'tags', label: scopesLabel, hideBelow: API_KEY_HIDE_BELOW.scopes },
        enableSorting: false,
        header: scopesLabel,
        cell: ({ row }) => (
          <span
            className="block truncate text-cap"
            title={row.original.scopes.map(permissionLabel).join(', ')}
          >
            {row.original.scopes.map(permissionLabel).join(', ')}
          </span>
        ),
      },
      {
        id: 'status',
        meta: { kind: 'status', label: statusLabel },
        enableSorting: false,
        header: statusLabel,
        cell: ({ row }) => <StatusBadge k={row.original} />,
      },
      {
        accessorKey: 'last_used_at',
        meta: {
          kind: 'datetime-recent',
          label: lastUsedLabel,
          hideBelow: API_KEY_HIDE_BELOW.lastUsed,
        },
        header: ({ column }) => <DataTableColumnHeader column={column} title={lastUsedLabel} />,
        cell: ({ row }) =>
          row.original.last_used_at ? (
            <RelativeTime date={row.original.last_used_at} />
          ) : (
            <span className="text-muted-foreground">{t('settings.keys.never', 'Never')}</span>
          ),
      },
      {
        accessorKey: 'expires_at',
        meta: {
          kind: 'text',
          minWidth: 120,
          maxWidth: 220,
          label: expiresLabel,
          hideBelow: API_KEY_HIDE_BELOW.expires,
        },
        header: ({ column }) => <DataTableColumnHeader column={column} title={expiresLabel} />,
        cell: ({ row }) => <ExpiryCell k={row.original} />,
      },
      {
        id: 'actions',
        meta: { kind: 'actions' },
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => <KeyRowActions k={row.original} onChanged={() => void mutate()} />,
      },
    ],
    [
      mutate,
      t,
      permissionLabel,
      nameLabel,
      keyLabel,
      scopesLabel,
      statusLabel,
      lastUsedLabel,
      expiresLabel,
    ]
  )

  const generateButton = (
    <Button onClick={() => setGenOpen(true)}>
      <Plus aria-hidden />
      {t('settings.apiKeys.generate', 'Generate API key')}
    </Button>
  )

  return (
    <SettingsPage
      wide
      title={t('settings.apiKeys.title', 'API keys')}
      description={
        ownKeysOnly
          ? t(
              'settings.apiKeys.cardDescOwn',
              'Your own keys. Owners and administrators see and manage every key in the organization.'
            )
          : t('settings.apiKeys.description', 'Keys for scripts and tools that call the API.')
      }
      actions={canGenerate ? generateButton : undefined}
    >
      <DataTable
        columns={columns}
        data={keys}
        getRowId={(k) => k.id}
        // A failed read must not render as "No API keys yet": an
        // administrator could conclude none exist and mint a duplicate key.
        error={error}
        onRetry={() => void mutate()}
        errorTitle={t('settings.apiKeys.subject', 'API keys')}
        isLoading={isLoading && !data}
        isRefreshing={isValidating && !!data}
        manualPagination
        rowCount={total}
        pagination={list.pagination}
        onPaginationChange={list.setPagination}
        pageSizeOptions={API_KEY_PAGE_SIZES}
        paginationNoun={t('settings.apiKeys.noun', 'keys')}
        sorting={list.sorting}
        onSortingChange={list.setSorting}
        // No keys at all (or a refused read): nothing to search or arrange, so
        // no search box or Display button. A search with no match keeps it.
        pinActions
        showToolbar={keys.length > 0 || list.q.trim() !== ''}
        showSearch={false}
        search={{
          value: list.q,
          onChange: list.setSearch,
          placeholder: t('settings.apiKeys.searchPlaceholder', 'Search API keys…'),
          label: t('settings.apiKeys.searchLabel', 'Search API keys'),
        }}
        mobileRow={(k) => (
          <PersonPhoneCard
            title={toDisplayText(k.name, 200)}
            address={<code className="font-mono">{`${k.key_prefix}…`}</code>}
            menu={<KeyRowActions k={k} onChanged={() => void mutate()} />}
            facts={
              <>
                <StatusBadge k={k} />
                {/* A revoked key has no expiry: its status already says Revoked. */}
                {k.status !== 'revoked' && !k.revoked_at && (
                  <span className="text-cap text-muted-foreground">
                    {t('settings.keys.expires', 'Expires')} <ExpiryCell k={k} />
                  </span>
                )}
              </>
            }
          />
        )}
        isFiltered={list.q.trim() !== ''}
        onClearFilters={() => list.setSearch('')}
        emptyState={{
          nothingYet: (
            <EmptyState
              icon={KeyRound}
              title={t('settings.apiKeys.emptyTitle', 'No API keys yet')}
              description={
                canGenerate
                  ? t(
                      'settings.apiKeys.emptyDescGenerate',
                      'Use Generate API key above to create a scoped key for programmatic access to the API.'
                    )
                  : t(
                      'settings.apiKeys.emptyDescAsk',
                      'Ask an owner or administrator if you need a key.'
                    )
              }
              card={false}
            />
          ),
          noMatch: {
            title: t('settings.apiKeys.noMatch', 'No API keys match your search.'),
            hint: t('settings.apiKeys.noMatchHint', 'Try another name, or clear the search.'),
          },
        }}
      />

      {!ownKeysOnly && <APIKeyPolicySection canEdit={canSetPolicy} />}

      <GenerateKeyDialog
        open={genOpen}
        onOpenChange={setGenOpen}
        onSubmit={(req) => createKey(req)}
        isMutating={creating}
        onCreated={(plaintext) => {
          setNewKey(plaintext)
          void mutate()
        }}
      />
      <RevealKeyDialog value={newKey} onClose={() => setNewKey('')} />
    </SettingsPage>
  )
}
