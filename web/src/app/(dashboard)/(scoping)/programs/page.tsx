'use client'

/**
 * Scoping › Programs (RFC-065): the bug-bounty and disclosure programs the
 * caller works on. Members of a program's group see it; a public program is
 * also visible to owners, admins and full-data roles, a private one only to
 * its members and the owners, locked until the person accepts its terms
 * (RFC-065 §15). Program targets are scanned from the organization's own
 * sensors only.
 */

import Link from '@/components/link'
import { Lock, Plus, Trophy } from 'lucide-react'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState, GatedSectionTabs, PageHeader } from '@/features/shared'
import { SCOPE_SECTION_TABS } from '@/config/section-tabs'
import { PROGRAM_STATUS_LABEL, usePrograms } from '@/features/programs'
import { Permission, useHasPermission } from '@/lib/permissions'

export default function ProgramsPage() {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.ProgramsWrite)
  const { data, error, isLoading, mutate } = usePrograms()

  return (
    <Main>
      <PageHeader
        title={t('programs.title', 'Programs')}
        description={t(
          'programs.description',
          'Bug-bounty and disclosure programs you test under their published rules. Their targets are scanned only from your own sensors.'
        )}
      >
        {canWrite && (
          <Button asChild>
            <Link href="/programs/new">
              <Plus className="mr-2 h-4 w-4" />
              {t('programs.import', 'Import program')}
            </Link>
          </Button>
        )}
      </PageHeader>
      <GatedSectionTabs tabs={SCOPE_SECTION_TABS} label="Scope sections" className="mt-4 mb-0" />

      {error ? (
        <ErrorState
          title={t('programs.title', 'Programs')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : !isLoading && (data ?? []).length === 0 ? (
        <EmptyState
          icon={Trophy}
          title={t('programs.empty.title', 'No programs yet')}
          description={t(
            'programs.empty.description',
            'Import a program by pasting its scope; its in-scope targets become scope entries and its out-of-scope items program exclusions.'
          )}
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('programs.col.name', 'Program')}</TableHead>
              <TableHead>{t('programs.col.platform', 'Platform')}</TableHead>
              <TableHead>{t('programs.col.status', 'Status')}</TableHead>
              <TableHead>{t('programs.col.tier', 'Max tier')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(data ?? []).map((p) => (
              <TableRow key={p.id}>
                <TableCell>
                  <Link
                    href={`/programs/${p.id}`}
                    className="inline-flex items-center gap-1.5 font-medium hover:underline"
                  >
                    {p.visibility === 'private' && (
                      <Lock
                        className="text-muted-foreground h-3.5 w-3.5"
                        aria-label={t('programs.visibility.private', 'Private')}
                      />
                    )}
                    {p.name}
                  </Link>
                  {p.locked && (
                    <span className="text-muted-foreground ml-2 text-xs">
                      {t('programs.locked.badge', 'accept the terms to open')}
                    </span>
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground">{p.platform || '-'}</TableCell>
                <TableCell>
                  <Badge variant={p.status === 'active' ? 'default' : 'secondary'}>
                    {t(`programs.status.${p.status}`, PROGRAM_STATUS_LABEL[p.status])}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">{p.locked ? '-' : p.max_tier}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Main>
  )
}
