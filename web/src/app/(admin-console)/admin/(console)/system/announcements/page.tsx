'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DataTable, ErrorState, PageHeader } from '@/features/shared'
import { TonePill, type PillTone } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { cancelAnnouncement, useAdminAnnouncements } from '@/features/admin-console/api/use-system'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { AdminConfirmDialog } from '@/features/admin-console/components/admin-confirm-dialog'
import { PublishAnnouncementDialog } from '@/features/admin-console/components/publish-announcement-dialog'
import { adminCan, type AdminAnnouncement } from '@/features/admin-console/types'

const STATE_TONE: Record<AdminAnnouncement['state'], PillTone> = {
  active: 'success',
  scheduled: 'info',
  ended: 'muted',
}

function when(iso?: string): string {
  return iso ? new Date(iso).toLocaleString() : '-'
}

export default function AdminAnnouncementsPage() {
  const admin = useAdmin()
  const { t } = useTranslation()
  const canWrite = adminCan(admin.role, 'ops_admin')
  const { data, error, isLoading, mutate } = useAdminAnnouncements()
  const [ending, setEnding] = useState<AdminAnnouncement | null>(null)

  const columns = useMemo<ColumnDef<AdminAnnouncement>[]>(
    () => [
      {
        accessorKey: 'message',
        header: t('admin.ann.message', 'Message'),
        cell: ({ row }) => (
          <p className="max-w-xl text-sm break-words whitespace-normal">{row.original.message}</p>
        ),
      },
      {
        accessorKey: 'severity',
        header: t('admin.ann.severity', 'Kind'),
        cell: ({ row }) => (
          <Badge variant={row.original.severity === 'info' ? 'secondary' : 'outline'}>
            {t(`admin.ann.sev.${row.original.severity}`, row.original.severity)}
          </Badge>
        ),
      },
      {
        id: 'window',
        header: t('admin.ann.window', 'Shown'),
        cell: ({ row }) => (
          <span className="text-sm whitespace-nowrap tabular-nums">
            {when(row.original.starts_at)} → {when(row.original.ends_at)}
          </span>
        ),
      },
      {
        accessorKey: 'state',
        header: t('admin.ann.state', 'State'),
        cell: ({ row }) => (
          <TonePill
            tone={STATE_TONE[row.original.state]}
            label={t(`admin.ann.state.${row.original.state}`, row.original.state)}
          />
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) =>
          canWrite && row.original.state !== 'ended' ? (
            <Button size="sm" variant="outline" onClick={() => setEnding(row.original)}>
              {row.original.state === 'scheduled'
                ? t('admin.ann.cancel', 'Cancel')
                : t('admin.ann.end', 'End now')}
            </Button>
          ) : null,
      },
    ],
    [t, canWrite]
  )

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.announcements', 'Announcements')}
        description={t(
          'admin.ann.description',
          'Notices every signed-in user sees as a banner while they are active: planned maintenance, warnings.'
        )}
      >
        {canWrite && <PublishAnnouncementDialog onPublished={() => void mutate()} />}
      </PageHeader>
      <div className="mt-5">
        {error ? (
          <ErrorState title="announcements" error={error} onRetry={() => void mutate()} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data ?? []}
            getRowId={(a) => a.id}
            isLoading={isLoading}
            showSearch={false}
            showColumnToggle={false}
            showSelectionCount={false}
            mobileCards
            emptyMessage={t('admin.ann.empty', 'No announcement yet')}
          />
        )}
      </div>
      {ending && (
        <AdminConfirmDialog
          open
          onOpenChange={(o) => !o && setEnding(null)}
          title={t('admin.ann.endTitle', 'Take this announcement down')}
          description={<p className="break-words">{ending.message}</p>}
          confirmLabel={t('admin.ann.end', 'End now')}
          destructive
          onConfirm={async ({ reason }) => {
            await cancelAnnouncement(ending.id, reason)
            toast.success(t('admin.ann.ended', 'Announcement taken down.'))
            void mutate()
          }}
        />
      )}
    </Main>
  )
}
