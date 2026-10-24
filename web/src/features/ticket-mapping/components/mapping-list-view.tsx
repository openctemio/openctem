'use client'

import { useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { ArrowLeftRight, Plus, TriangleAlert, FlaskConical } from 'lucide-react'
import { Main } from '@/components/layout'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, ErrorState, PageHeader, RelativeTime, PageStack } from '@/features/shared'
import { Can, Permission, usePermissions } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import { useMappingProfiles } from '../api/use-ticket-mapping-api'
import { CreateMappingDialog, type MappingPreset } from './create-mapping-dialog'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const PROJECT_KEY = /^[A-Z][A-Z0-9_]{0,31}$/i
const ISSUE_TYPE_ID = /^\d{1,20}$/

/** A destination named in the URL (?new=1&integration=&kind=&project=&type=),
 *  from the integration's issue types; every value is checked. */
export function presetFromParams(p: URLSearchParams | null): MappingPreset | undefined {
  if (!p || p.get('new') !== '1') return undefined
  const integrationId = p.get('integration') ?? ''
  const kind = p.get('kind')
  const projectKey = p.get('project') ?? ''
  const issueTypeId = p.get('type') ?? ''
  if (
    !UUID.test(integrationId) ||
    (kind !== 'finding' && kind !== 'task') ||
    !PROJECT_KEY.test(projectKey) ||
    !ISSUE_TYPE_ID.test(issueTypeId)
  ) {
    return undefined
  }
  return { integrationId, kind, projectKey: projectKey.toUpperCase(), issueTypeId }
}

/** Settings → Integrations → Ticket field mapping: every destination's
 *  mapping profile, its published version, draft, dry run and drift. */
export function MappingListView() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const params = useSearchParams()
  // Only a person who may create mappings gets the dialog from a link.
  const preset = can(Permission.IntegrationsManage) ? presetFromParams(params) : undefined
  const [createOpen, setCreateOpen] = useState(Boolean(preset))
  const { data, error, isLoading, mutate } = useMappingProfiles()
  const profiles = data?.data ?? []

  return (
    <Main>
      <PageStack>
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

        <div>
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
                        <span>{p.project_key}</span>
                        <span>{p.issue_type || p.issue_type_id}</span>
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
        <CreateMappingDialog open={createOpen} onOpenChange={setCreateOpen} initial={preset} />
      </PageStack>
    </Main>
  )
}
