'use client'

/**
 * Settings → Scanning → Tool defaults: per tool, the values every one of
 * the organization's own sensors runs the tool with (api
 * docs/architecture/sensors.md, "Tool settings"). A sensor overrides any
 * option in its own Tool settings; a scan only lowers rate, concurrency and
 * retries. The options come from each tool's own settings schema.
 */

import { useMemo } from 'react'
import { Info, SlidersHorizontal } from 'lucide-react'

import Link from '@/components/link'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, SettingsPage } from '@/features/shared'
import {
  resetToolDefaults,
  saveToolDefaults,
  useToolDefaults,
  type ToolDefaults,
} from '@/lib/api/sensor-tool-settings-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import { problemKey } from '../lib/tool-settings'
import { ToolSettingsList, type T, type ToolSettingsEntry } from './tool-settings-list'

export function defaultsEntry(item: ToolDefaults, t: T): ToolSettingsEntry {
  const notices: ToolSettingsEntry['notices'] = []
  if (item.problems.length > 0) {
    notices.push({
      title: t('sensors.toolDefaults.problemsTitle'),
      items: item.problems.flatMap((p) =>
        p.problems.map((x) =>
          t('sensors.toolDefaults.problemItem', undefined, {
            sensor: p.sensor_name || p.sensor_id,
            key: problemKey(x.path) || item.tool,
            message: x.message,
          })
        )
      ),
    })
  }
  if (!item.schema) {
    notices.push({ title: t('sensors.toolDefaults.noSchema'), items: [] })
  }
  return {
    tool: item.tool,
    schema: item.schema,
    schemaDigest: item.schema_digest,
    values: item.values,
    stored: item.stored,
    updatedAt: item.updated_at,
    problems: [],
    notices: notices.length > 0 ? notices : undefined,
    meta: t(
      item.sensors === 1
        ? 'sensors.toolDefaults.sensorsCount.one'
        : 'sensors.toolDefaults.sensorsCount.other',
      undefined,
      { count: item.sensors }
    ),
  }
}

export function ToolDefaultsSettings() {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.SensorsWrite)
  const { data, error, isLoading, mutate } = useToolDefaults()
  const entries = useMemo(() => (data?.items ?? []).map((i) => defaultsEntry(i, t)), [data, t])

  const title = t('sensors.toolDefaults.title')
  const description = t('sensors.toolDefaults.description')
  if (error || isLoading || !data) {
    return (
      <SettingsPage
        title={title}
        description={description}
        state={error ? 'error' : 'loading'}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  return (
    <SettingsPage
      title={title}
      description={description}
      readOnly={!canWrite && t('sensors.toolDefaults.readOnly')}
      banners={
        <Alert className="max-w-settings">
          <Info className="size-4" aria-hidden />
          <AlertDescription>{t('sensors.toolDefaults.layersNote')}</AlertDescription>
        </Alert>
      }
    >
      {entries.length === 0 ? (
        <EmptyState
          icon={SlidersHorizontal}
          title={t('sensors.toolDefaults.emptyTitle')}
          description={t('sensors.toolDefaults.empty')}
          action={
            <Button variant="outline" size="sm" asChild>
              <Link href="/sensors">{t('sensors.toolDefaults.openSensors', 'Open sensors')}</Link>
            </Button>
          }
        />
      ) : (
        <ToolSettingsList
          mode="organization"
          storageKey="openctem.settings.toolDefaults.open"
          items={entries}
          canEdit={canWrite}
          save={async (tool, values) => {
            await saveToolDefaults(tool, values)
          }}
          reset={resetToolDefaults}
          onChanged={() => void mutate()}
        />
      )}
    </SettingsPage>
  )
}
