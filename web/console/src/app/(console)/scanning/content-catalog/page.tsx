'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Package, Upload } from 'lucide-react'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DataTable,
  EmptyState,
  ErrorState,
  FilterSelect,
  PageHeader,
  MetaLine,
  PageStack,
  RelativeTime,
} from '@/features/shared'
import { ListCount, ListToolbarTitle } from '@/features/shared/components/list-title-row'
import { useTranslation } from '@/context/i18n-provider'
import { useListParams } from '@/hooks/use-list-params'
import { TrustBanner } from '@/features/content-catalog/components/trust-banner'
import { CONTENT_TYPES, trustBanner } from '@/features/content-catalog/lib'
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
import { adminHas } from '@console/features/admin-console/types'

/**
 * A catalog package on a phone. Fixed slots, never a label/value grid; a tap
 * opens its versions, as a row click does:
 *
 *   Web templates (the whole width, cut to one line)
 *   org.example.web-templates
 *   Templates  Signed catalog
 *   Latest 2.4.1  Revoked   3 versions
 */
function CatalogMobileCard({ item, onOpen }: { item: CatalogListItem; onOpen: () => void }) {
  const { t } = useTranslation()
  const p = item.latest
  return (
    <button
      type="button"
      data-slot="catalog-card"
      onClick={onOpen}
      className="flex w-full min-w-0 flex-col gap-1 px-3 py-3 text-start hover:bg-muted/50"
    >
      <span className="w-full truncate font-medium" title={p.title}>
        {p.title}
      </span>
      <span
        className="w-full truncate font-mono text-code text-muted-foreground"
        title={p.package_id}
      >
        {p.package_id}
      </span>
      <span data-slot="catalog-card-kind" className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <Badge variant="outline">{t(`contentCatalog.type.${p.type}`, p.type)}</Badge>
        <span className="text-meta text-muted-foreground">
          {p.origin === 'instance'
            ? t('admin.catalog.origin.instance', 'This installation')
            : t('admin.catalog.origin.catalog', 'Signed catalog')}
        </span>
      </span>
      <MetaLine
        className="items-center"
        items={[
          <span key="latest" className="inline-flex items-center gap-1.5">
            {t('admin.catalog.card.latest', 'Latest {version}', { version: p.version })}
            {p.revoked && (
              <Badge variant="destructive">{t('admin.catalog.revokedBadge', 'Revoked')}</Badge>
            )}
          </span>,
          <span key="versions" className="tabular-nums">
            {t(
              'admin.catalog.card.versions',
              '{count, plural, one {# version} other {# versions}}',
              { count: item.versions }
            )}
          </span>,
        ]}
      />
    </button>
  )
}

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
  const canEdit = adminHas(me, 'platform.content.manage')
  const list = useListParams({ defaultPageSize: 25, filters: { type: '' } })
  const q = list.searchTerm
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
        // The package is the row's name: its title, then its id, on one line.
        // It stays in view while the table scrolls sideways.
        meta: {
          kind: 'name',
          pin: 'start',
          minWidth: 240,
          label: t('admin.catalog.col.package', 'Package'),
        },
        cell: ({ row }) => (
          <div className="flex min-w-0 items-baseline gap-2">
            <span className="truncate font-medium" title={row.original.latest.title}>
              {row.original.latest.title}
            </span>
            <span
              className="min-w-0 shrink truncate font-mono text-xs text-muted-foreground"
              title={row.original.latest.package_id}
            >
              {row.original.latest.package_id}
            </span>
          </div>
        ),
      },
      {
        id: 'type',
        header: t('admin.catalog.col.type', 'Type'),
        meta: { kind: 'text', width: 160, label: t('admin.catalog.col.type', 'Type') },
        cell: ({ row }) => (
          <Badge variant="outline">
            {t(`contentCatalog.type.${row.original.latest.type}`, row.original.latest.type)}
          </Badge>
        ),
      },
      {
        id: 'origin',
        header: t('admin.catalog.col.origin', 'Source'),
        meta: {
          kind: 'text',
          width: 168,
          hideBelow: 800,
          label: t('admin.catalog.col.origin', 'Source'),
        },
        cell: ({ row }) => (
          <span className="block truncate">
            {row.original.latest.origin === 'instance'
              ? t('admin.catalog.origin.instance', 'This installation')
              : t('admin.catalog.origin.catalog', 'Signed catalog')}
          </span>
        ),
      },
      {
        id: 'latest',
        header: t('admin.catalog.col.latest', 'Latest'),
        meta: { kind: 'text', width: 176, label: t('admin.catalog.col.latest', 'Latest') },
        cell: ({ row }) => (
          <span className="flex min-w-0 items-center gap-1.5">
            <span className="truncate font-mono">{row.original.latest.version}</span>
            {row.original.latest.revoked && (
              <Badge variant="destructive">{t('admin.catalog.revokedBadge', 'Revoked')}</Badge>
            )}
          </span>
        ),
      },
      {
        id: 'versions',
        header: t('admin.catalog.col.versions', 'Versions'),
        meta: { kind: 'number', width: 104, label: t('admin.catalog.col.versions', 'Versions') },
        cell: ({ row }) => <span className="tabular-nums">{row.original.versions}</span>,
      },
    ],
    [t]
  )

  const tr = trust.data
  const stale = trustBanner(tr)?.tone === 'warning'
  const total = pkgs.data?.total ?? 0
  // The "nothing imported yet" notice says the catalog is empty: it is only
  // true when no package is listed (instance packages exist without an import),
  // and it is only drawn once the package list is known, never before.
  const listKnown = !!pkgs.data || !!pkgs.error
  const hasPackages = total > 0 || !!q || !!list.filters.type
  const bannerReason = trustBanner(tr)
  const showBanner = !(
    bannerReason?.tone === 'info' &&
    bannerReason.reason === 'no-import' &&
    hasPackages
  )
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.nav.contentCatalog', 'Content catalog')}
          description={t(
            'admin.catalog.description',
            'The signed catalog of rules, templates, sensors and other packages organizations install from.'
          )}
        >
          {/* Drawn from the first frame: Import waits for the trust state (it
              needs a configured root), so nothing in the header changes on load. */}
          {canEdit && (
            <>
              <Button variant="outline" size="sm" onClick={() => setPublishOpen(true)}>
                <Package className="me-1.5 size-4" aria-hidden />
                {t('admin.catalog.publishButton', 'Publish a package')}
              </Button>
              <Button
                size="sm"
                onClick={() => setImportOpen(true)}
                disabled={!tr || tr.roots_configured === 0}
              >
                <Upload className="me-1.5 size-4" aria-hidden />
                {t('admin.catalog.importButton', 'Import a bundle')}
              </Button>
            </>
          )}
        </PageHeader>
        {/* The list is the page's job: it comes first, from the first frame. The
            trust state follows it; a stale catalog keeps a marker in the title
            row that leads down to it. */}
        <DataTable
          // The list's name and count start the toolbar row (no row of their own).
          toolbarTitle={
            <ListToolbarTitle
              title={
                list.filters.type
                  ? t(`contentCatalog.type.${list.filters.type}`, list.filters.type)
                  : t('admin.catalog.viewAll', 'All packages')
              }
              count={
                <ListCount
                  total={total}
                  loading={!pkgs.data && !pkgs.error}
                  label={t(
                    'admin.catalog.total',
                    '{count, plural, one {# package} other {# packages}}',
                    {
                      count: total,
                    }
                  )}
                />
              }
              start={
                stale ? (
                  <a
                    href="#catalog-trust"
                    className="shrink-0 text-body text-destructive underline-offset-4 hover:underline"
                  >
                    {t('admin.catalog.stale', 'Out of date')}
                  </a>
                ) : null
              }
            />
          }
          columns={columns}
          data={pkgs.data?.data ?? []}
          caption={t('admin.catalog.caption', 'Catalog packages')}
          getRowId={(p) => p.latest.package_id}
          error={pkgs.error}
          onRetry={() => void pkgs.mutate()}
          errorTitle={t('admin.catalog.packagesError', 'the catalog packages')}
          // The first read: skeleton rows under a toolbar that stays mounted.
          isLoading={pkgs.isLoading && !pkgs.data}
          isRefreshing={pkgs.isValidating && !!pkgs.data}
          refreshingLabel={t('admin.catalog.refreshing', 'Refreshing packages')}
          showSearch={false}
          search={{
            value: list.q,
            onChange: list.setSearch,
            placeholder: t('admin.catalog.search', 'Search package id or title…'),
            label: t('admin.catalog.searchLabel', 'Search packages'),
          }}
          toolbarStart={
            <FilterSelect
              label={t('admin.catalog.typeFilter', 'Package type')}
              value={list.filters.type}
              foldLabel
              allLabel={t('admin.catalog.allTypes', 'All types')}
              options={CONTENT_TYPES.map((ty) => ({
                value: ty,
                label: t(`contentCatalog.type.${ty}`, ty),
              }))}
              onChange={(v) => list.setFilter('type', v)}
            />
          }
          showSelectionCount={false}
          // A phone card with fixed slots, not the automatic label/value card.
          mobileRow={(p) => (
            <CatalogMobileCard item={p} onOpen={() => setOpen(p.latest.package_id)} />
          )}
          onRowClick={(p) => setOpen(p.latest.package_id)}
          isFiltered={!!(q || list.filters.type)}
          onClearFilters={list.reset}
          emptyState={{
            nothingYet: (
              <EmptyState
                icon={Package}
                title={t(
                  'admin.catalog.empty',
                  'No package in the catalog yet: import a signed bundle.'
                )}
              />
            ),
            noMatch: {
              title: t('admin.catalog.noMatch', 'No package matches these filters'),
            },
          }}
          manualPagination
          pageCount={Math.max(1, Math.ceil(total / list.perPage))}
          rowCount={total}
          pagination={list.pagination}
          onPaginationChange={list.setPagination}
          paginationNoun={t('admin.catalog.noun', 'packages')}
        />

        {/* Under the list: nothing is drawn (not even an empty block that would
            take a gap) until the trust state and the package list are both
            known, so nothing above it moves when this block arrives. */}
        {(trust.error || (tr && listKnown)) && (
          <section id="catalog-trust" className="flex min-w-0 flex-col gap-4 scroll-mt-4">
            {trust.error ? (
              <ErrorState
                title={t('admin.catalog.trustError', 'the catalog trust state')}
                error={trust.error}
                onRetry={() => void trust.mutate()}
              />
            ) : !tr ? null : (
              <>
                {showBanner && <TrustBanner trust={tr} />}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">
                      {t('admin.catalog.trustTitle', 'Trust')}
                    </CardTitle>
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
          </section>
        )}

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
      </PageStack>
    </Main>
  )
}
