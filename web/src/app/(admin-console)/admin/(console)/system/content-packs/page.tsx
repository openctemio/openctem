'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Copy, Download, Search } from 'lucide-react'
import { toast } from 'sonner'
import type { ContentChannelResponse, PlatformContentPackResponse } from '@/lib/api/generated'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  DataTable,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSheet,
  ErrorState,
  PageHeader,
  RelativeTime,
  StackedCell,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import {
  contentPackDownloadUrl,
  revokeContentPack,
  setContentChannel,
  useContentChannels,
  useContentPacks,
  useContentSigningKey,
} from '@/features/admin-console/api/use-content-packs'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { AdminConfirmDialog } from '@/features/admin-console/components/admin-confirm-dialog'
import {
  AddContentPackDialog,
  KNOWN_KINDS,
} from '@/features/admin-console/components/add-content-pack-dialog'
import { ContentLintReportView } from '@/features/admin-console/components/content-lint-report'
import { adminCan } from '@/features/admin-console/types'
import { safeHref } from '@/lib/safe-href'

const ANY = 'any'
const CHANNELS = ['stable', 'canary'] as const

function shortDigest(d?: string): string {
  return d ? `${d.slice(0, 15)}…` : '-'
}

function formatBytes(n?: number): string {
  if (!n) return '-'
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KiB`
  return `${(n / 1024 / 1024).toFixed(1)} MiB`
}

export default function ContentPacksPage() {
  const admin = useAdmin()
  const { t } = useTranslation()
  const canWrite = adminCan(admin.role, 'super_admin')
  const list = useListParams({ defaultPageSize: 25, filters: { kind: '', status: '' } })
  const name = useDebounce(list.q, 300)
  const status =
    list.filters.status === 'active' || list.filters.status === 'revoked' ? list.filters.status : ''
  const packs = useContentPacks({
    name,
    kind: list.filters.kind,
    status,
    page: list.page,
    perPage: list.perPage,
  })
  const channels = useContentChannels()
  const key = useContentSigningKey()
  const [openId, setOpenId] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<PlatformContentPackResponse | null>(null)
  const [moving, setMoving] = useState<{
    pack: PlatformContentPackResponse
    channel: string
  } | null>(null)
  const opened = packs.data?.data?.find((p) => p.id === openId) ?? null
  const refresh = () => {
    void packs.mutate()
    void channels.mutate()
  }

  const columns = useMemo<ColumnDef<PlatformContentPackResponse>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('admin.cp.col.pack', 'Pack'),
        cell: ({ row }) => (
          <StackedCell primary={row.original.name} secondary={row.original.version} />
        ),
      },
      { accessorKey: 'kind', header: t('admin.cp.kind', 'Kind') },
      {
        accessorKey: 'tier',
        header: t('admin.cp.col.tier', 'Tier'),
        cell: ({ row }) => <Badge variant="outline">{row.original.tier}</Badge>,
      },
      {
        id: 'content',
        header: t('admin.cp.col.content', 'Content'),
        cell: ({ row }) => (
          <span className="text-sm tabular-nums">
            {t('admin.cp.files', '{n} files', { n: row.original.file_count ?? 0 })}
            {(row.original.lint?.excluded ?? 0) > 0 && (
              <span className="ms-1 text-warning">
                {t('admin.cp.leftOut', '({n} left out)', { n: row.original.lint?.excluded ?? 0 })}
              </span>
            )}
          </span>
        ),
      },
      {
        accessorKey: 'status',
        header: t('admin.cp.col.status', 'Status'),
        cell: ({ row }) =>
          row.original.status === 'revoked' ? (
            <Badge variant="destructive">{t('admin.cp.revoked', 'Revoked')}</Badge>
          ) : (
            <Badge variant="secondary">{t('admin.cp.active', 'Active')}</Badge>
          ),
      },
      {
        accessorKey: 'created_at',
        header: t('admin.cp.col.added', 'Added'),
        cell: ({ row }) => <RelativeTime date={row.original.created_at} className="text-sm" />,
      },
    ],
    [t]
  )

  const channelRows: ContentChannelResponse[] = channels.data?.data ?? []

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.contentPacks', 'Content packs')}
        description={t(
          'admin.cp.description',
          'Templates, rules and wordlists the platform ships to sensors: linted, signed, and pinned to a channel.'
        )}
      >
        {canWrite && <AddContentPackDialog onAdded={refresh} />}
      </PageHeader>

      <div className="mt-5 grid gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">{t('admin.cp.channels', 'Channels')}</CardTitle>
          </CardHeader>
          <CardContent>
            {channelRows.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {t(
                  'admin.cp.noChannels',
                  'No channel points at a pack yet. Open a pack and promote it.'
                )}
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-muted-foreground">
                    <tr>
                      <th className="py-2 pe-3 text-start font-medium">
                        {t('admin.cp.col.pack', 'Pack')}
                      </th>
                      <th className="py-2 pe-3 text-start font-medium">
                        {t('admin.cp.channel', 'Channel')}
                      </th>
                      <th className="py-2 pe-3 text-start font-medium">
                        {t('admin.cp.version', 'Version')}
                      </th>
                      <th className="py-2 pe-3 text-start font-medium">
                        {t('admin.cp.digest', 'Digest')}
                      </th>
                      <th className="py-2 text-start font-medium">
                        {t('admin.cp.updated', 'Updated')}
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {channelRows.map((c) => (
                      <tr key={`${c.name}-${c.channel}`}>
                        <td className="py-2 pe-3 font-medium">{c.name}</td>
                        <td className="py-2 pe-3">
                          <Badge variant={c.channel === 'stable' ? 'secondary' : 'outline'}>
                            {c.channel}
                          </Badge>
                        </td>
                        <td className="py-2 pe-3 tabular-nums">{c.version}</td>
                        <td className="py-2 pe-3 font-mono text-xs" title={c.digest}>
                          {shortDigest(c.digest)}
                        </td>
                        <td className="py-2">
                          <RelativeTime date={c.updated_at} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('admin.cp.signingKey', 'Signing key')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {key.data ? (
              <>
                <p className="text-muted-foreground">
                  {key.data.algorithm} · {t('admin.cp.keyId', 'key id')}{' '}
                  <code className="text-xs">{key.data.key_id}</code>
                </p>
                <code className="block rounded bg-muted p-2 text-xs break-all select-all">
                  {key.data.public_key}
                </code>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    navigator.clipboard
                      .writeText(key.data?.public_key ?? '')
                      .then(() => toast.success(t('admin.cp.copied', 'Public key copied.')))
                      .catch(() => undefined)
                  }
                >
                  <Copy className="me-2 size-4" />
                  {t('admin.cp.copyKey', 'Copy public key')}
                </Button>
              </>
            ) : (
              <p className="text-muted-foreground">
                {key.error
                  ? t('admin.cp.noKey', 'No signing key is configured.')
                  : t('common.loading', 'Loading...')}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="mt-5">
        {packs.error ? (
          <ErrorState title="content packs" error={packs.error} onRetry={refresh} />
        ) : (
          <DataTable
            columns={columns}
            data={packs.data?.data ?? []}
            getRowId={(p) => p.id ?? ''}
            isLoading={packs.isLoading}
            showSearch={false}
            showColumnToggle={false}
            showSelectionCount={false}
            mobileCards
            onRowClick={(p) => setOpenId(p.id ?? null)}
            emptyMessage={t('admin.cp.empty', 'No content pack yet')}
            manualPagination
            pageCount={Math.max(1, Math.ceil((packs.data?.total ?? 0) / list.perPage))}
            rowCount={packs.data?.total ?? 0}
            pagination={list.pagination}
            onPaginationChange={list.setPagination}
            toolbarStart={
              <div className="flex w-full flex-col gap-2 sm:flex-row">
                <div className="relative w-full sm:max-w-xs">
                  <Search className="absolute start-2.5 top-2.5 size-4 text-muted-foreground" />
                  <Input
                    value={list.q}
                    onChange={(e) => list.setSearch(e.target.value)}
                    placeholder={t('admin.cp.searchName', 'Pack name')}
                    className="ps-8"
                    aria-label={t('admin.cp.searchName', 'Pack name')}
                  />
                </div>
                <Select
                  value={list.filters.kind || ANY}
                  onValueChange={(v) => list.setFilter('kind', v === ANY ? '' : v)}
                >
                  <SelectTrigger className="sm:w-48" aria-label={t('admin.cp.kind', 'Kind')}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ANY}>{t('admin.cp.anyKind', 'Any kind')}</SelectItem>
                    {KNOWN_KINDS.map((k) => (
                      <SelectItem key={k} value={k}>
                        {k}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select
                  value={status || ANY}
                  onValueChange={(v) => list.setFilter('status', v === ANY ? '' : v)}
                >
                  <SelectTrigger
                    className="sm:w-40"
                    aria-label={t('admin.cp.col.status', 'Status')}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ANY}>{t('admin.cp.anyStatus', 'Any status')}</SelectItem>
                    <SelectItem value="active">{t('admin.cp.active', 'Active')}</SelectItem>
                    <SelectItem value="revoked">{t('admin.cp.revoked', 'Revoked')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            }
          />
        )}
      </div>

      <DetailSheet
        open={opened !== null}
        onOpenChange={(o) => !o && setOpenId(null)}
        width="lg"
        header={
          <DetailHeader
            title={opened ? `${opened.name} ${opened.version}` : ''}
            badges={
              opened &&
              (opened.status === 'revoked' ? (
                <Badge variant="destructive">{t('admin.cp.revoked', 'Revoked')}</Badge>
              ) : (
                <Badge variant="secondary">{t('admin.cp.active', 'Active')}</Badge>
              ))
            }
            meta={opened ? [opened.kind, `tier ${opened.tier}`] : []}
            onClose={() => setOpenId(null)}
          />
        }
      >
        {opened && (
          <div className="space-y-5">
            <div className="flex flex-wrap gap-2">
              <Button asChild size="sm" variant="outline">
                <a href={safeHref(contentPackDownloadUrl(opened.id ?? '')) ?? '#'} download>
                  <Download className="me-2 size-4" />
                  {t('admin.cp.download', 'Download signed archive')}
                </a>
              </Button>
              {canWrite &&
                opened.status === 'active' &&
                CHANNELS.map((ch) => (
                  <Button
                    key={ch}
                    size="sm"
                    variant="outline"
                    onClick={() => setMoving({ pack: opened, channel: ch })}
                  >
                    {t('admin.cp.promote', 'Point {channel} here', { channel: ch })}
                  </Button>
                ))}
              {canWrite && opened.status === 'active' && (
                <Button size="sm" variant="destructive" onClick={() => setRevoking(opened)}>
                  {t('admin.cp.revoke', 'Revoke')}
                </Button>
              )}
            </div>
            <DetailFieldGrid>
              <DetailField label={t('admin.cp.digest', 'Digest')} full>
                <code className="text-xs break-all select-all">{opened.digest}</code>
              </DetailField>
              <DetailField label={t('admin.cp.size', 'Size')}>
                {formatBytes(opened.size_bytes)}
              </DetailField>
              <DetailField label={t('admin.cp.fileCount', 'Files')}>
                <span className="tabular-nums">{opened.file_count}</span>
              </DetailField>
              <DetailField label={t('admin.cp.source', 'Source')} full>
                {opened.source === 'https' ? (
                  <span className="text-xs break-all">
                    {opened.source_ref} <code>{opened.source_digest}</code>
                  </span>
                ) : (
                  t('admin.cp.uploaded', 'Uploaded')
                )}
              </DetailField>
              {opened.status === 'revoked' && (
                <DetailField label={t('admin.cp.revokeReason', 'Revoked because')} full>
                  {opened.revoke_reason}
                </DetailField>
              )}
            </DetailFieldGrid>
            <section className="space-y-2">
              <h3 className="text-sm font-medium">{t('admin.cp.lint', 'Lint report')}</h3>
              <ContentLintReportView report={opened.lint ?? {}} />
            </section>
          </div>
        )}
      </DetailSheet>

      {revoking && (
        <AdminConfirmDialog
          open
          onOpenChange={(o) => !o && setRevoking(null)}
          title={t('admin.cp.revokeTitle', 'Revoke {name} {version}', {
            name: revoking.name ?? '',
            version: revoking.version ?? '',
          })}
          description={
            <p>
              {t(
                'admin.cp.revokeWhat',
                'Sensors stop running this pack, and any channel that points at it is cleared. This cannot be undone.'
              )}
            </p>
          }
          confirmLabel={t('admin.cp.revoke', 'Revoke')}
          destructive
          requireCode
          onConfirm={async (proof) => {
            await revokeContentPack(revoking.id ?? '', proof)
            toast.success(t('admin.cp.revokedDone', 'Pack revoked.'))
            setOpenId(null)
            refresh()
          }}
        />
      )}
      {moving && (
        <AdminConfirmDialog
          open
          onOpenChange={(o) => !o && setMoving(null)}
          title={t('admin.cp.moveTitle', 'Point {channel} at {name} {version}', {
            channel: moving.channel,
            name: moving.pack.name ?? '',
            version: moving.pack.version ?? '',
          })}
          description={
            <p>
              {t(
                'admin.cp.moveWhat',
                'Sensors on the {channel} channel pick this version up on their next content check.',
                { channel: moving.channel }
              )}
            </p>
          }
          confirmLabel={t('admin.cp.moveConfirm', 'Move channel')}
          requireCode
          onConfirm={async (proof) => {
            await setContentChannel(moving.channel, { pack_id: moving.pack.id ?? '', ...proof })
            toast.success(t('admin.cp.moved', 'Channel moved.'))
            refresh()
          }}
        />
      )}
    </Main>
  )
}
