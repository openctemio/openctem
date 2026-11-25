'use client'

/**
 * Scoping › Programs (RFC-065): the bug-bounty and disclosure programs the
 * caller works on. Members of a program's group see it; a public program is
 * also visible to owners, admins and full-data roles, a private one only to
 * its members and the owners, locked until the person accepts its terms
 * (RFC-065 §15). Program targets are scanned from the organization's own
 * sensors only.
 */

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import Link from '@/components/link'
import { Lock, Plus, Trophy } from 'lucide-react'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import {
  DataTable,
  EmptyState,
  ErrorState,
  GatedSectionTabs,
  NoAccessState,
  PageHeader,
  PageStack,
} from '@/features/shared'
import { Skeleton } from '@/components/ui/skeleton'
import { SCOPE_SECTION_TABS } from '@/config/section-tabs'
import { PROGRAM_STATUS_LABEL, usePrograms, type Program } from '@/features/programs'
import { Permission, useHasPermission } from '@/lib/permissions'

/**
 * The shared table: a long name ends in an ellipsis inside its column and a
 * phone gets the list's cards, so no header runs past the frame. The
 * platform steps aside on a narrow frame (about 650 at 768).
 */
const PROGRAMS_HIDE_BELOW = { platform: 720 } as const

export default function ProgramsPage() {
  const { t } = useTranslation()
  const router = useRouter()
  const canWrite = useHasPermission(Permission.ProgramsWrite)
  const canRead = useHasPermission(Permission.ProgramsRead)
  const { data, error, isLoading, mutate } = usePrograms()

  const columns = useMemo<ColumnDef<Program>[]>(
    () => [
      {
        id: 'name',
        accessorKey: 'name',
        meta: { kind: 'name', pin: 'start', label: t('programs.col.name', 'Program') },
        header: t('programs.col.name', 'Program'),
        cell: ({ row }) => {
          const p = row.original
          return (
            <span className="flex min-w-0 items-center gap-1.5">
              {p.visibility === 'private' && (
                <Lock
                  className="text-muted-foreground h-3.5 w-3.5 shrink-0"
                  aria-label={t('programs.visibility.private', 'Private')}
                />
              )}
              <Link
                href={`/programs/${p.id}`}
                className="truncate font-medium hover:underline"
                title={p.name}
              >
                {p.name}
              </Link>
              {p.locked && (
                <span className="text-muted-foreground shrink-0 text-xs">
                  {t('programs.locked.badge', 'accept the terms to open')}
                </span>
              )}
            </span>
          )
        },
      },
      {
        id: 'platform',
        accessorKey: 'platform',
        meta: {
          kind: 'text',
          width: 176,
          hideBelow: PROGRAMS_HIDE_BELOW.platform,
          label: t('programs.col.platform', 'Platform'),
        },
        header: t('programs.col.platform', 'Platform'),
        cell: ({ row }) => (
          <span className="text-muted-foreground block truncate" title={row.original.platform}>
            {row.original.platform || '-'}
          </span>
        ),
      },
      {
        id: 'status',
        accessorKey: 'status',
        meta: { kind: 'status', label: t('programs.col.status', 'Status') },
        header: t('programs.col.status', 'Status'),
        cell: ({ row }) => (
          <Badge variant={row.original.status === 'active' ? 'outline' : 'secondary'}>
            {t(`programs.status.${row.original.status}`, PROGRAM_STATUS_LABEL[row.original.status])}
          </Badge>
        ),
      },
      {
        id: 'max_tier',
        accessorKey: 'max_tier',
        // "Mức tối đa" (vi) whole, with the cell padding.
        meta: { kind: 'text', width: 112, label: t('programs.col.tier', 'Max tier') },
        header: t('programs.col.tier', 'Max tier'),
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.locked ? '-' : row.original.max_tier}
          </span>
        ),
      },
    ],
    [t]
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('programs.title', 'Programs')}
          description={t(
            'programs.description',
            'Bug-bounty and disclosure programs you test under their published rules. Their targets are scanned only from your own sensors.'
          )}
        >
          {canWrite && (
            <Button asChild size="sm">
              <Link href="/programs/new">
                <Plus className="me-2 h-4 w-4" />
                {t('programs.import', 'Import program')}
              </Link>
            </Button>
          )}
        </PageHeader>
        <GatedSectionTabs tabs={SCOPE_SECTION_TABS} label={t('scope.sections', 'Scope sections')} />

        {!canRead ? (
          <NoAccessState title={t('programs.title', 'Programs')} />
        ) : isLoading ? (
          <div className="space-y-2 rounded-xl border p-3">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : error ? (
          <ErrorState
            title={t('programs.title', 'Programs')}
            error={error}
            onRetry={() => mutate()}
          />
        ) : (data ?? []).length === 0 ? (
          <EmptyState
            icon={Trophy}
            title={t('programs.empty.title', 'No programs yet')}
            description={t(
              'programs.empty.description',
              'Import a program by pasting its scope; its in-scope targets become scope entries and its out-of-scope items program exclusions.'
            )}
          />
        ) : (
          <DataTable
            columns={columns}
            data={data ?? []}
            getRowId={(p) => p.id}
            // A short list with nothing to search or arrange: no toolbar row.
            showToolbar={false}
            onRowClick={(p) => router.push(`/programs/${p.id}`)}
          />
        )}
      </PageStack>
    </Main>
  )
}
