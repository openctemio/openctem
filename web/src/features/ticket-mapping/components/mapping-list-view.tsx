'use client'

import { useState } from 'react'
import { ArrowLeftRight, Plus, TriangleAlert, FlaskConical } from 'lucide-react'
import { Main } from '@/components/layout'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, ErrorState, PageHeader, RelativeTime } from '@/features/shared'
import { Can, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import { useMappingProfiles } from '../api/use-ticket-mapping-api'
import { CreateMappingDialog } from './create-mapping-dialog'

/** Settings → Integrations → Ticket field mapping: every destination's
 *  mapping profile, its published version, draft, dry run and drift. */
export function MappingListView() {
  const { t } = useTranslation()
  const [createOpen, setCreateOpen] = useState(false)
  const { data, error, isLoading, mutate } = useMappingProfiles()
  const profiles = data?.data ?? []

  return (
    <Main>
      <PageHeader
        title={t('ticketMapping.list.title', 'Ticket field mapping')}
        description={t(
          'ticketMapping.list.description',
          'Which {product} attribute goes to which Jira field, which Jira field comes back, and how statuses map, per project and issue type.'
        )}
      >
        <Can permission={Permission.IntegrationsManage}>
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="me-2 h-4 w-4" aria-hidden />
            {t('ticketMapping.list.new', 'New mapping')}
          </Button>
        </Can>
      </PageHeader>

      <div className="mt-6">
        {isLoading ? (
          <div className="grid gap-3">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-20 w-full" />
            ))}
          </div>
        ) : error ? (
          <ErrorState
            title={t('ticketMapping.list.title', 'Ticket field mapping')}
            error={error}
            onRetry={() => mutate()}
          />
        ) : profiles.length === 0 ? (
          <EmptyState
            icon={ArrowLeftRight}
            title={t('ticketMapping.list.emptyTitle', 'No field mapping yet')}
            description={t(
              'ticketMapping.list.emptyDescription',
              'Without a mapping, tickets use the built-in fields: summary, description, priority from severity and labels.'
            )}
            action={
              <Can permission={Permission.IntegrationsManage}>
                <Button onClick={() => setCreateOpen(true)}>
                  {t('ticketMapping.list.new', 'New mapping')}
                </Button>
              </Can>
            }
          />
        ) : (
          <div className="grid gap-3">
            {profiles.map((p) => (
              <Card key={p.id} className="py-0">
                <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
                  <div className="min-w-0">
                    <Link
                      href={`/settings/integrations/ticketing/mappings/${p.id}`}
                      className="font-medium hover:underline"
                    >
                      {p.name}
                    </Link>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                      <span>
                        {p.project_key} · {p.issue_type || p.issue_type_id}
                      </span>
                      <Badge variant="secondary">
                        {p.object_kind === 'task'
                          ? t('ticketMapping.kind.taskShort', 'Tasks')
                          : t('ticketMapping.kind.findingShort', 'Findings')}
                      </Badge>
                      <span>
                        {t('ticketMapping.list.updated', 'Updated')}{' '}
                        <RelativeTime date={p.updated_at} />
                      </span>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {p.published_version > 0 ? (
                      <Badge variant="outline">
                        {t('ticketMapping.list.published', 'Published v{v}', {
                          v: p.published_version,
                        })}
                      </Badge>
                    ) : (
                      <Badge variant="outline">
                        {t('ticketMapping.list.notPublished', 'Not published')}
                      </Badge>
                    )}
                    {p.draft_version > 0 && (
                      <Badge variant="secondary">
                        {t('ticketMapping.list.draft', 'Draft v{v}', { v: p.draft_version })}
                      </Badge>
                    )}
                    {p.dry_run && (
                      <Badge variant="secondary">
                        <FlaskConical className="me-1 h-3 w-3" aria-hidden />
                        {t('ticketMapping.list.dryRun', 'Dry run')}
                      </Badge>
                    )}
                    {p.drifted && (
                      <Badge variant="destructive">
                        <TriangleAlert className="me-1 h-3 w-3" aria-hidden />
                        {t('ticketMapping.list.drifted', 'Jira changed')}
                      </Badge>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
      <CreateMappingDialog open={createOpen} onOpenChange={setCreateOpen} />
    </Main>
  )
}
