'use client'

import { FileSpreadsheet, Plus } from 'lucide-react'
import { Main } from '@/components/layout'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, ErrorState, PageHeader, RelativeTime } from '@/features/shared'
import { Can, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import { useImportMappings } from '../api/import-mappings-api'

/** Settings → Integrations → Import mappings: the organization's mappings. */
export function ImportMappingListView() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useImportMappings()
  const items = data?.items ?? []

  const newButton = (
    <Can permission={Permission.IntegrationsManage}>
      <Button asChild>
        <Link href="/settings/integrations/import-mappings/new">
          <Plus className="me-2 h-4 w-4" aria-hidden />
          {t('importMappings.list.new', 'New mapping')}
        </Link>
      </Button>
    </Can>
  )

  return (
    <Main>
      <PageHeader
        title={t('importMappings.list.title', 'Import mappings')}
        description={t(
          'importMappings.list.description',
          'Turn any CSV, JSON, JSON Lines or XML export into findings and assets. Choose a mapping as the format when you import results.'
        )}
      >
        {newButton}
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
            title={t('importMappings.list.title', 'Import mappings')}
            error={error}
            onRetry={() => mutate()}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={FileSpreadsheet}
            title={t('importMappings.list.emptyTitle', 'No import mapping yet')}
            description={t(
              'importMappings.list.emptyDescription',
              'Start from a template for a generic CSV, findings JSON or test-results XML, and check it on a sample before saving.'
            )}
            action={newButton}
          />
        ) : (
          <div className="grid gap-3">
            {items.map((m) => (
              <Card key={m.id} className="py-0">
                <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
                  <div className="min-w-0 flex-1 basis-60">
                    <Link
                      href={`/settings/integrations/import-mappings/${encodeURIComponent(m.id)}`}
                      className="break-all font-medium hover:underline"
                    >
                      {m.name}
                    </Link>
                    {m.description && (
                      <p className="mt-0.5 line-clamp-2 text-sm text-muted-foreground">
                        {m.description}
                      </p>
                    )}
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                      <code className="break-all">{`mapping:${m.name}`}</code>
                      <span>
                        {t('importMappings.list.updated', 'Updated')}{' '}
                        <RelativeTime date={m.updated_at} />
                      </span>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline">
                      {t(`importMappings.source.${m.source}`, m.source.toUpperCase())}
                    </Badge>
                    <Badge variant="secondary">
                      {t('importMappings.list.version', 'v{v}', { v: m.latest_version })}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </Main>
  )
}
