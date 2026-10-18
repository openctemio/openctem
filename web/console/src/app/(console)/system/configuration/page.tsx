'use client'

import { useMemo, useState } from 'react'
import { ArrowRight } from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ErrorState, PageHeader, RelativeTime } from '@/features/shared'
import { TonePill } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { useConfiguration } from '@console/features/admin-console/api/use-configuration'
import {
  CONFIG_GROUPS,
  CONFIG_GROUP_LABELS,
  CONFIG_ITEM_LABELS,
  configItemKey,
  filterConfig,
  type ConfigFilter,
} from '@console/features/admin-console/lib/configuration'
import type { ConfigurationItem } from '@console/features/admin-console/types'

/**
 * Settings -> Configuration (RFC-022 revision 22): every operator setting,
 * where it is managed (this console, applied at once; or the server, which
 * needs a restart), where its value comes from, and the page that changes
 * it. Secrets show only whether they are set. Read-only for every role.
 */
export default function ConfigurationPage() {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useConfiguration()
  const [filter, setFilter] = useState<ConfigFilter>('all')
  const items = useMemo(() => filterConfig(data?.data ?? [], filter), [data, filter])

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.configuration', 'Configuration')}
        description={t(
          'admin.config.description',
          'Every setting of this installation: what you change here (applied at once) and what the server configuration sets (needs a restart). Secrets are never shown, only whether they are set.'
        )}
      />
      <div className="mt-5 space-y-4">
        <Tabs value={filter} onValueChange={(v) => setFilter(v as ConfigFilter)}>
          <TabsList className="flex-wrap">
            <TabsTrigger value="all">{t('admin.config.filter.all', 'All')}</TabsTrigger>
            <TabsTrigger value="console">
              {t('admin.config.filter.console', 'In this console')}
            </TabsTrigger>
            <TabsTrigger value="server">
              {t('admin.config.filter.server', 'On the server')}
            </TabsTrigger>
            <TabsTrigger value="restart">
              {t('admin.config.filter.restart', 'Needs a restart')}
            </TabsTrigger>
            <TabsTrigger value="planned">
              {t('admin.config.filter.planned', 'Moving to the console')}
            </TabsTrigger>
          </TabsList>
        </Tabs>
        {error ? (
          <ErrorState
            title={t('admin.config.errorTitle', 'the configuration')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          CONFIG_GROUPS.map((group) => {
            const rows = items.filter((i) => i.group === group)
            if (rows.length === 0) return null
            return (
              <Card key={group}>
                <CardHeader>
                  <CardTitle className="text-base">
                    {t(`admin.config.group.${group}`, CONFIG_GROUP_LABELS[group])}
                  </CardTitle>
                </CardHeader>
                <CardContent className="divide-y p-0">
                  {rows.map((item) => (
                    <ConfigRow key={item.key} item={item} />
                  ))}
                </CardContent>
              </Card>
            )
          })
        )}
      </div>
    </Main>
  )
}

function ConfigRow({ item }: { item: ConfigurationItem }) {
  const { t } = useTranslation()
  const name = t(configItemKey(item.key), CONFIG_ITEM_LABELS[item.key] ?? item.key)
  const source =
    item.source === 'console'
      ? t('admin.config.source.console', 'Set in this console')
      : item.source === 'environment'
        ? t('admin.config.source.environment', 'Set on the server')
        : t('admin.config.source.default', 'Default')

  let value: string | null = null
  if (item.secret) {
    value = item.is_set
      ? t('admin.config.secret.set', 'Set')
      : t('admin.config.secret.notSet', 'Not set')
  } else if (item.managed === 'server') {
    value = item.value ? item.value : t('admin.config.empty', '(empty)')
  }

  return (
    <div className="flex flex-col gap-2 px-6 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0 space-y-1">
        <p className="text-sm font-medium">{name}</p>
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
          {item.env_var && <code className="break-all">{item.env_var}</code>}
          {item.ceiling && (
            <span>
              {t(
                'admin.config.ceiling',
                'the server value is an upper bound this console can only tighten'
              )}
            </span>
          )}
          {item.changed_at && (
            <span>
              {item.changed_by
                ? t('admin.config.changedBy', 'changed by {who}', { who: item.changed_by })
                : t('admin.config.changed', 'changed')}{' '}
              <RelativeTime date={item.changed_at} />
            </span>
          )}
        </p>
        {value !== null && <p className="break-all font-mono text-xs">{value}</p>}
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-2">
        <TonePill
          tone={
            item.source === 'default' ? 'muted' : item.source === 'console' ? 'success' : 'info'
          }
          label={source}
        />
        {item.restart_required && (
          <TonePill tone="warning" label={t('admin.config.restart', 'Restart to change')} />
        )}
        {item.planned && (
          <TonePill tone="muted" label={t('admin.config.planned', 'Moving to the console')} />
        )}
        {item.page && (
          <Link
            href={item.page}
            className="inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline"
          >
            {t('admin.config.open', 'Change')}
            <ArrowRight className="size-3.5" aria-hidden />
          </Link>
        )}
      </div>
    </div>
  )
}
