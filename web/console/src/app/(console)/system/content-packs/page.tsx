'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { ChevronRight, Copy, Download, Info } from 'lucide-react'
import { toast } from 'sonner'
import type { ContentChannelResponse, PlatformContentPackResponse } from '@/lib/api/generated'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
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
  MetaLine,
  PageHeader,
  PageStack,
  RelativeTime,
  StackedCell,
} from '@/features/shared'
import { ListCount, ListToolbarTitle } from '@/features/shared/components/list-title-row'
import { useTranslation } from '@/context/i18n-provider'
import { useListParams } from '@/hooks/use-list-params'
import {
  contentPackDownloadUrl,
  revokeContentPack,
  setContentChannel,
  useContentChannels,
  useContentPacks,
  useContentSigningKey,
} from '@console/features/admin-console/api/use-content-packs'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import {
  TypedAdminConfirmDialog,
  nameToType,
} from '@console/features/admin-console/components/type-to-confirm-field'
import { AdminConfirmDialog } from '@console/features/admin-console/components/admin-confirm-dialog'
import {
  AddContentPackDialog,
  KNOWN_KINDS,
} from '@console/features/admin-console/components/add-content-pack-dialog'
import { ContentLintReportView } from '@console/features/admin-console/components/content-lint-report'
import { adminHas } from '@console/features/admin-console/types'
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
  const canWrite = adminHas(admin, 'platform.content.manage')
  const list = useListParams({ defaultPageSize: 25, filters: { kind: '', status: '' } })
  const name = list.searchTerm
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
            <Badge variant="secondary">
              {t('admin.cp.storedNotDelivered', 'Stored, not delivered')}
            </Badge>
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
  // Which pack each channel points at: a short list in the shared table, so
  // it gets the same header, states and phone cards as every list.
  const channelColumns = useMemo<ColumnDef<ContentChannelResponse>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('admin.cp.col.pack', 'Pack'),
        meta: { kind: 'name' },
        cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
      },
      {
        accessorKey: 'channel',
        header: t('admin.cp.channel', 'Channel'),
        meta: { kind: 'status' },
        cell: ({ row }) => (
          <Badge variant={row.original.channel === 'stable' ? 'secondary' : 'outline'}>
            {row.original.channel}
          </Badge>
        ),
      },
      {
        accessorKey: 'version',
        header: t('admin.cp.version', 'Version'),
        meta: { kind: 'text' },
        cell: ({ row }) => <span className="tabular-nums">{row.original.version}</span>,
      },
      {
        accessorKey: 'digest',
        header: t('admin.cp.digest', 'Digest'),
        // The digest is on the pack's sheet too: it gives way first on a tablet.
        meta: { kind: 'id', hideBelow: 720 },
        cell: ({ row }) => (
          <span className="font-mono text-xs" title={row.original.digest}>
            {shortDigest(row.original.digest)}
          </span>
        ),
      },
      {
        accessorKey: 'updated_at',
        header: t('admin.cp.updated', 'Updated'),
        meta: { kind: 'datetime-recent' },
        cell: ({ row }) => <RelativeTime date={row.original.updated_at} />,
      },
    ],
    [t]
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.nav.contentPacks', 'Content packs')}
          description={t(
            'admin.cp.description',
            'Templates, rules and wordlists the platform ships to sensors: linted, signed, and pinned to a channel.'
          )}
        >
          {canWrite && <AddContentPackDialog onAdded={refresh} />}
        </PageHeader>

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
            mobileRow={(p) => <PackPhoneCard pack={p} />}
            onRowClick={(p) => setOpenId(p.id ?? null)}
            emptyMessage={t('admin.cp.empty', 'No content pack yet')}
            manualPagination
            pageCount={Math.max(1, Math.ceil((packs.data?.total ?? 0) / list.perPage))}
            rowCount={packs.data?.total ?? 0}
            pagination={list.pagination}
            onPaginationChange={list.setPagination}
            search={{
              value: list.q,
              onChange: list.setSearch,
              placeholder: t('admin.cp.searchName', 'Search pack name…'),
            }}
            toolbarStart={
              <>
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
              </>
            }
          />
        )}

        {/* research/191 C-1: no sensor downloads packs yet; said under the list
            (every row also reads "Stored, not delivered"), not above it. */}
        <p
          data-testid="content-packs-not-delivered"
          className="flex gap-2 text-sm text-muted-foreground"
        >
          <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>
            {t(
              'admin.cp.notDelivered',
              'Not active yet: sensors do not download content packs. A stored pack is not used by any scan, and revoking one stops nothing. Custom templates still travel inside each scan job.'
            )}
          </span>
        </p>

        {/* Which pack each channel points at: a short list in the shared table,
            its name and count in its toolbar row beside Display. */}
        <DataTable
          columns={channelColumns}
          data={channelRows}
          getRowId={(c) => `${c.name}-${c.channel}`}
          caption={t('admin.cp.channels', 'Channels')}
          toolbarTitle={
            <ListToolbarTitle
              title={t('admin.cp.channels', 'Channels')}
              count={
                <ListCount
                  total={channelRows.length}
                  loading={channels.isLoading && !channels.data}
                  label={t(
                    'admin.cp.channelsTotal',
                    '{count, plural, one {# channel} other {# channels}}',
                    { count: channelRows.length }
                  )}
                />
              }
            />
          }
          isLoading={channels.isLoading}
          showSearch={false}
          showColumnToggle={false}
          showSelectionCount={false}
          showPagination={false}
          mobileRow={(c) => <ChannelPhoneCard channel={c} />}
          emptyMessage={t(
            'admin.cp.noChannels',
            'No channel points at a pack yet. Open a pack and promote it.'
          )}
        />

        <section aria-labelledby="content-signing-key" className="flex flex-col gap-2">
          <h2 id="content-signing-key" className="text-sm font-medium">
            {t('admin.cp.signingKey', 'Signing key')}
          </h2>
          {key.data ? (
            <>
              <p className="text-sm text-muted-foreground">
                {key.data.algorithm}, {t('admin.cp.keyId', 'key id')}{' '}
                <code className="text-xs break-all">{key.data.key_id}</code>
              </p>
              <div className="flex flex-col gap-2 sm:flex-row sm:items-start">
                <code className="block min-w-0 flex-1 rounded bg-muted p-2 text-xs break-all select-all">
                  {key.data.public_key}
                </code>
                <Button
                  variant="outline"
                  className="self-start"
                  onClick={() =>
                    navigator.clipboard
                      .writeText(key.data?.public_key ?? '')
                      .then(() => toast.success(t('admin.cp.copied', 'Public key copied.')))
                      .catch(() => undefined)
                  }
                >
                  <Copy aria-hidden />
                  {t('admin.cp.copyKey', 'Copy public key')}
                </Button>
              </div>
            </>
          ) : (
            <p className="text-sm text-muted-foreground">
              {key.error
                ? t('admin.cp.noKey', 'No signing key is configured.')
                : t('common.loading', 'Loading...')}
            </p>
          )}
        </section>

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
                  <Badge variant="secondary">
                    {t('admin.cp.storedNotDelivered', 'Stored, not delivered')}
                  </Badge>
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
                    <span className="text-xs break-words">
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
          <TypedAdminConfirmDialog
            reasonPlaceholder={t(
              'admin.cp.reasonRevoke',
              'Its templates flood findings, advisory 2231'
            )}
            typeToConfirm={nameToType(revoking.name, revoking.version ?? revoking.id ?? 'revoke')}
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
                  'Sensors stop running this pack and any channel that points at it is cleared. The pack stays listed as revoked and cannot be restored.'
                )}
              </p>
            }
            confirmLabel={t('admin.cp.revokePack', 'Revoke pack')}
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
            reasonPlaceholder={t(
              'admin.cp.reasonMove',
              'A week on the test channel without problems, change 2231'
            )}
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
      </PageStack>
    </Main>
  )
}

/**
 * A content pack on a phone; a tap opens its sheet, which the chevron says:
 *
 *   template-facts-core  2026.11.1                              >
 *   nuclei-templates   core   Stored, not delivered
 */
function PackPhoneCard({ pack }: { pack: PlatformContentPackResponse }) {
  const { t } = useTranslation()
  const revoked = pack.status === 'revoked'
  return (
    <div data-slot="pack-card" className="flex w-full min-w-0 items-center gap-2 px-3 py-3">
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <div className="flex min-w-0 items-baseline gap-2">
          <span className="min-w-0 truncate font-medium" title={pack.name}>
            {pack.name}
          </span>
          <span className="shrink-0 text-cap text-muted-foreground tabular-nums">
            {pack.version}
          </span>
        </div>
        <MetaLine
          className="items-center"
          items={[
            pack.kind ? <span key="kind">{pack.kind}</span> : null,
            pack.tier ? (
              <Badge key="tier" variant="outline">
                {pack.tier}
              </Badge>
            ) : null,
            <Badge key="status" variant={revoked ? 'destructive' : 'secondary'}>
              {revoked
                ? t('admin.cp.revoked', 'Revoked')
                : t('admin.cp.storedNotDelivered', 'Stored, not delivered')}
            </Badge>,
          ]}
        />
      </div>
      <ChevronRight
        data-slot="person-card-chevron"
        aria-hidden
        className="size-4 shrink-0 text-muted-foreground rtl:rotate-180"
      />
    </div>
  )
}

/**
 * A channel on a phone: the pack and the channel it is on, then the version
 * and when the channel last moved.
 *
 *   template-facts-core                                     stable
 *   2026.11.1   2 days ago
 */
function ChannelPhoneCard({ channel }: { channel: ContentChannelResponse }) {
  return (
    <div data-slot="channel-card" className="flex w-full min-w-0 flex-col gap-1 px-3 py-3">
      <div className="flex min-w-0 items-center gap-2">
        <span className="min-w-0 flex-1 truncate font-medium" title={channel.name}>
          {channel.name}
        </span>
        <Badge variant={channel.channel === 'stable' ? 'secondary' : 'outline'}>
          {channel.channel}
        </Badge>
      </div>
      <MetaLine
        items={[
          channel.version ? (
            <span key="version" className="tabular-nums">
              {channel.version}
            </span>
          ) : null,
          channel.updated_at ? <RelativeTime key="updated" date={channel.updated_at} /> : null,
        ]}
      />
    </div>
  )
}
