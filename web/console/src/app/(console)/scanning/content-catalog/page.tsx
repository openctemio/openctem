'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Package, Search, Upload } from 'lucide-react'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { DataTable, ErrorState, PageHeader, RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import { TrustBanner } from '@/features/content-catalog/components/trust-banner'
import { CONTENT_TYPES } from '@/features/content-catalog/lib'
import {
  useCatalogPackages,
  useCatalogTrust,
  useCatalogVersions,
  type CatalogListItem,
} from '@console/features/admin-console/api/use-content-catalog'
import {
  ImportBundleDialog,
  PublishPackageDialog,
  RevokeVersionDialog,
} from '@console/features/admin-console/components/content-catalog-dialogs'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { adminCan } from '@console/features/admin-console/types'

const ALL_TYPES = '__all'

/**
 * Scanning > Content catalog (RFC-099): the instance catalog organizations
 * install from: its trust state (the trust roots are set on the server and
 * shown read-only), its packages and their versions, and the guarded
 * actions a super admin takes (import a signed bundle, publish an instance
 * package, revoke a version). Organizations install and remove packages
 * themselves; their installations are not shown here.
 */
export default function ContentCatalogPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const canEdit = adminCan(me.role, 'super_admin')
  const list = useListParams({ defaultPageSize: 25, filters: { type: '' } })
  const q = useDebounce(list.q, 300)
  const trust = useCatalogTrust()
  const pkgs = useCatalogPackages(q, list.filters.type, list.page, list.perPage)
  const [importOpen, setImportOpen] = useState(false)
  const [publishOpen, setPublishOpen] = useState(false)
  const [open, setOpen] = useState<string | null>(null)
  const versions = useCatalogVersions(open)
  const [revoke, setRevoke] = useState<{ packageId: string; version: string } | null>(null)

  const refresh = () => {
    void trust.mutate()
    void pkgs.mutate()
    void versions.mutate()
  }

  const columns = useMemo<ColumnDef<CatalogListItem>[]>(
    () => [
      {
        id: 'package',
        header: t('admin.catalog.col.package', 'Package'),
        cell: ({ row }) => (
          <div className="min-w-0">
            <p className="truncate text-sm font-medium">{row.original.latest.title}</p>
            <p className="truncate font-mono text-xs text-muted-foreground">
              {row.original.latest.package_id}
            </p>
          </div>
        ),
      },
      {
        id: 'type',
        header: t('admin.catalog.col.type', 'Type'),
        cell: ({ row }) => (
          <Badge variant="outline">
            {t(`contentCatalog.type.${row.original.latest.type}`, row.original.latest.type)}
          </Badge>
        ),
      },
      {
        id: 'origin',
        header: t('admin.catalog.col.origin', 'Source'),
        cell: ({ row }) => (
          <span className="text-sm">
            {row.original.latest.origin === 'instance'
              ? t('admin.catalog.origin.instance', 'This installation')
              : t('admin.catalog.origin.catalog', 'Signed catalog')}
          </span>
        ),
      },
      {
        id: 'latest',
        header: t('admin.catalog.col.latest', 'Latest'),
        cell: ({ row }) => (
          <span className="flex items-center gap-1.5 font-mono text-sm">
            {row.original.latest.version}
            {row.original.latest.revoked && (
              <Badge variant="destructive">{t('admin.catalog.revokedBadge', 'Revoked')}</Badge>
            )}
          </span>
        ),
      },
      {
        id: 'versions',
        header: t('admin.catalog.col.versions', 'Versions'),
        cell: ({ row }) => <span className="tabular-nums">{row.original.versions}</span>,
      },
    ],
    [t]
  )

  const tr = trust.data
  return (
    <Main>
      <PageHeader
        title={t('admin.nav.contentCatalog', 'Content catalog')}
        description={t(
          'admin.catalog.description',
          'The signed catalog of rules, templates, sensors and other packages organizations install from.'
        )}
      />
      <div className="mt-5 space-y-4">
        {trust.error ? (
          <ErrorState
            title={t('admin.catalog.trustError', 'the catalog trust state')}
            error={trust.error}
            onRetry={() => void trust.mutate()}
          />
        ) : !tr ? (
          <Skeleton className="h-32 w-full" />
        ) : (
          <>
            <TrustBanner trust={tr} />
            <Card>
              <CardHeader>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <CardTitle className="text-base">
                    {t('admin.catalog.trustTitle', 'Trust')}
                  </CardTitle>
                  {canEdit && (
                    <div className="flex flex-wrap gap-2">
                      <Button variant="outline" size="sm" onClick={() => setPublishOpen(true)}>
                        <Package className="me-1.5 size-4" aria-hidden />
                        {t('admin.catalog.publishButton', 'Publish a package')}
                      </Button>
                      <Button
                        size="sm"
                        onClick={() => setImportOpen(true)}
                        disabled={tr.roots_configured === 0}
                      >
                        <Upload className="me-1.5 size-4" aria-hidden />
                        {t('admin.catalog.importButton', 'Import a bundle')}
                      </Button>
                    </div>
                  )}
                </div>
                <CardDescription>
                  {t(
                    'admin.catalog.rootsReadOnly',
                    'Trust roots: {n}. They are set on the server (CONTENT_TRUST_ROOT_KEY_IDS) and cannot be changed from this console: a stolen console session must not be able to trust new content.',
                    { n: tr.roots_configured }
                  )}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
                  <div>
                    <dt className="text-muted-foreground">
                      {t('admin.catalog.keyset', 'Key set version')}
                    </dt>
                    <dd className="font-mono">{tr.keyset_version || '—'}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">
                      {t('admin.catalog.index', 'Signed index')}
                    </dt>
                    <dd className="font-mono">
                      {tr.index_sequence || '—'}
                      {tr.index_expires_at && (
                        <span className="ms-2 font-sans text-xs text-muted-foreground">
                          {tr.index_expired
                            ? t('admin.catalog.expired', 'expired')
                            : t('admin.catalog.expires', 'expires')}{' '}
                          <RelativeTime date={tr.index_expires_at} />
                        </span>
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">
                      {t('admin.catalog.revocations', 'Revocation list')}
                    </dt>
                    <dd className="font-mono">
                      {tr.revocations_sequence || '—'}
                      {tr.revocations_stale && (
                        <Badge variant="destructive" className="ms-2">
                          {t('admin.catalog.stale', 'Out of date')}
                        </Badge>
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">
                      {t('admin.catalog.importedAt', 'Last import')}
                    </dt>
                    <dd>
                      {tr.imported_at ? (
                        <RelativeTime date={tr.imported_at} />
                      ) : (
                        t('admin.catalog.never', 'Never')
                      )}
                    </dd>
                  </div>
                </dl>
              </CardContent>
            </Card>
          </>
        )}

        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative w-full sm:max-w-xs">
            <Search className="absolute start-2.5 top-2.5 size-4 text-muted-foreground" />
            <Input
              value={list.q}
              onChange={(e) => list.setSearch(e.target.value)}
              placeholder={t('admin.catalog.search', 'Package id or title...')}
              aria-label={t('admin.catalog.searchLabel', 'Search packages')}
              className="ps-8"
            />
          </div>
          <Select
            value={list.filters.type || ALL_TYPES}
            onValueChange={(v) => list.setFilter('type', v === ALL_TYPES ? '' : v)}
          >
            <SelectTrigger
              className="w-full sm:w-48"
              aria-label={t('admin.catalog.typeFilter', 'Package type')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_TYPES}>{t('admin.catalog.allTypes', 'All types')}</SelectItem>
              {CONTENT_TYPES.map((ty) => (
                <SelectItem key={ty} value={ty}>
                  {t(`contentCatalog.type.${ty}`, ty)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {pkgs.error ? (
          <ErrorState
            title={t('admin.catalog.packagesError', 'the catalog packages')}
            error={pkgs.error}
            onRetry={() => void pkgs.mutate()}
          />
        ) : (
          <DataTable
            columns={columns}
            data={pkgs.data?.data ?? []}
            getRowId={(p) => p.latest.package_id}
            isLoading={pkgs.isLoading}
            showSearch={false}
            showColumnToggle={false}
            showSelectionCount={false}
            mobileCards
            onRowClick={(p) => setOpen(p.latest.package_id)}
            emptyMessage={t(
              'admin.catalog.empty',
              'No package in the catalog yet: import a signed bundle.'
            )}
            manualPagination
            pageCount={Math.max(1, Math.ceil((pkgs.data?.total ?? 0) / list.perPage))}
            rowCount={pkgs.data?.total ?? 0}
            pagination={list.pagination}
            onPaginationChange={list.setPagination}
          />
        )}
      </div>

      <Sheet open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        <SheetContent className="w-full sm:max-w-lg">
          <SheetHeader>
            <SheetTitle className="break-all font-mono text-base">{open}</SheetTitle>
            <SheetDescription>
              {t(
                'admin.catalog.versionsDesc',
                'Every version, newest first. Revoking one revokes every installation of it.'
              )}
            </SheetDescription>
          </SheetHeader>
          <div className="space-y-2 overflow-y-auto px-4 pb-4">
            {versions.isLoading && <Skeleton className="h-24 w-full" />}
            {versions.data?.versions.map((v) => (
              <div
                key={v.id}
                className="flex items-center justify-between gap-2 rounded-md border p-3"
              >
                <div className="min-w-0">
                  <p className="font-mono text-sm">{v.version}</p>
                  <p className="text-xs text-muted-foreground">
                    {v.revoked
                      ? t('admin.catalog.revokedReason', 'Revoked: {reason}', {
                          reason: v.revoke_reason || '—',
                        })
                      : v.signatures.join(' + ')}
                  </p>
                </div>
                {canEdit && !v.revoked && open && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setRevoke({ packageId: open, version: v.version })}
                  >
                    {t('admin.catalog.revoke', 'Revoke')}
                  </Button>
                )}
              </div>
            ))}
          </div>
        </SheetContent>
      </Sheet>

      <ImportBundleDialog open={importOpen} onOpenChange={setImportOpen} onDone={refresh} />
      <PublishPackageDialog open={publishOpen} onOpenChange={setPublishOpen} onDone={refresh} />
      <RevokeVersionDialog
        target={revoke}
        onOpenChange={(o) => !o && setRevoke(null)}
        onDone={refresh}
      />
    </Main>
  )
}
