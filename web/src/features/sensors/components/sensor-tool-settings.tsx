'use client'

/**
 * A sensor's Tool settings tab: its overrides of the organization's tool
 * defaults (api docs/architecture/sensors.md, "Tool settings"). Every
 * option shows its effective value and where it comes from; the effective
 * table shows the full chain of layers.
 */

import { useMemo, useState } from 'react'
import { SlidersHorizontal } from 'lucide-react'

import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useSensorManifests } from '@/lib/api/sensor-hooks'
import {
  resetSensorToolSettings,
  saveSensorToolSettings,
  useSensorEffectiveToolSettings,
  useSensorToolSettings,
  type SensorToolSettings,
} from '@/lib/api/sensor-tool-settings-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import { problemKey } from '../lib/tool-settings'
import { sourceLabel, ToolSettingsList, type T, type ToolSettingsEntry } from './tool-settings-list'

export const TOOL_DEFAULTS_URL = '/settings/scanning/tool-defaults'

function valueText(v: unknown, t: T): string {
  if (v === null || v === undefined) return t('sensors.toolSettings.unset')
  return Array.isArray(v) ? v.map(String).join(', ') : String(v)
}

function EffectiveTable({ sensorId, tool, t }: { sensorId: string; tool: string; t: T }) {
  const { data, error, isLoading } = useSensorEffectiveToolSettings(sensorId, tool)
  if (isLoading) return <Skeleton className="h-16 w-full" />
  if (error || !data) {
    return (
      <p className="text-sm text-destructive">
        {getErrorMessage(error, t('sensors.toolSettings.effectiveError'))}
      </p>
    )
  }
  return (
    <div
      className="overflow-x-auto rounded-md border"
      data-testid={`tool-settings-effective-${tool}`}
    >
      <table className="w-full text-xs">
        <thead className="bg-muted/40 text-left text-muted-foreground">
          <tr>
            <th className="px-2 py-1 font-medium">{t('sensors.toolSettings.effective.key')}</th>
            <th className="px-2 py-1 font-medium">{t('sensors.toolSettings.effective.value')}</th>
            <th className="px-2 py-1 font-medium">{t('sensors.toolSettings.effective.source')}</th>
            <th className="px-2 py-1 font-medium">{t('sensors.toolSettings.effective.flag')}</th>
          </tr>
        </thead>
        <tbody>
          {data.items.map((e) => (
            <tr key={e.key} className="border-t align-top">
              <td className="px-2 py-1 font-mono">{e.key}</td>
              <td className="px-2 py-1 font-mono">{valueText(e.value, t)}</td>
              <td className="px-2 py-1">
                {sourceLabel(e.source, t)}
                {(e.chain?.length ?? 0) > 1 && (
                  <span
                    className="block text-muted-foreground"
                    data-testid={`tool-settings-chain-${e.key}`}
                  >
                    {t('sensors.toolSettings.chainOver', undefined, {
                      list: (e.chain ?? [])
                        .slice(0, -1)
                        .map((c) =>
                          t('sensors.toolSettings.chainStep', undefined, {
                            value: valueText(c.value, t),
                            source: sourceLabel(c.source, t),
                          })
                        )
                        .join(', '),
                    })}
                  </span>
                )}
              </td>
              <td className="px-2 py-1 font-mono">{e.flag ?? ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function EffectiveToggle({ sensorId, tool }: { sensorId: string; tool: string }) {
  const { t } = useTranslation()
  const [show, setShow] = useState(false)
  return (
    <div className="space-y-2">
      <Button
        type="button"
        size="sm"
        variant="ghost"
        onClick={() => setShow((s) => !s)}
        aria-expanded={show}
      >
        {show ? t('sensors.toolSettings.hideEffective') : t('sensors.toolSettings.showEffective')}
      </Button>
      {show && <EffectiveTable sensorId={sensorId} tool={tool} t={t} />}
    </div>
  )
}

export function sensorEntry(item: SensorToolSettings, t: T): ToolSettingsEntry {
  const orgProblems = item.organization_problems ?? []
  return {
    tool: item.tool,
    schema: item.schema,
    schemaDigest: item.schema_digest,
    values: item.values,
    stored: item.stored,
    updatedAt: item.updated_at,
    problems: item.problems,
    inherited: item.organization_values ?? {},
    notices:
      orgProblems.length > 0
        ? [
            {
              title: t('sensors.toolSettings.orgProblems'),
              items: orgProblems.map((p) => `${problemKey(p.path) || item.tool}: ${p.message}`),
            },
          ]
        : undefined,
  }
}

/**
 * The sensor's tool settings, for owners and administrators (sensors:write):
 * a collapsible row per tool of the current manifest that declares settings,
 * in override mode over the organization's defaults.
 */
export function SensorToolSettingsSection({ sensorId }: { sensorId: string }) {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.SensorsWrite)
  const { data, error, isLoading, mutate } = useSensorToolSettings(sensorId, canWrite)
  const { data: manifests } = useSensorManifests(sensorId, canWrite)
  const versions = useMemo(() => {
    const current = manifests?.items.find((v) => v.current)
    return new Map(
      (current?.manifest.tools ?? [])
        .filter((tool) => tool.version)
        .map((tool) => [tool.name, tool.version as string])
    )
  }, [manifests])
  const entries = useMemo(() => (data?.items ?? []).map((i) => sensorEntry(i, t)), [data, t])
  if (!canWrite) return null
  return (
    <DetailSection title={t('sensors.toolSettings.title')} icon={SlidersHorizontal}>
      <p className="text-sm text-muted-foreground">
        {t('sensors.toolSettings.intro')}{' '}
        <Link href={TOOL_DEFAULTS_URL} className="text-primary underline-offset-4 hover:underline">
          {t('sensors.toolSettings.manageDefaults')}
        </Link>
      </p>
      {isLoading && <Skeleton className="h-24 w-full" />}
      {error && !isLoading && (
        <p className="text-sm text-destructive">
          {getErrorMessage(error, t('sensors.toolSettings.loadError'))}
        </p>
      )}
      {!isLoading && !error && entries.length === 0 && (
        <p className="text-sm text-muted-foreground">{t('sensors.toolSettings.empty')}</p>
      )}
      {entries.length > 0 && (
        <ToolSettingsList
          mode="sensor"
          storageKey={`openctem.sensors.toolSettings.open.${sensorId}`}
          items={entries}
          versions={versions}
          save={async (tool, values) => {
            await saveSensorToolSettings(sensorId, tool, values)
          }}
          reset={(tool) => resetSensorToolSettings(sensorId, tool)}
          onChanged={() => void mutate()}
          renderExtra={(tool) => <EffectiveToggle sensorId={sensorId} tool={tool} />}
        />
      )}
    </DetailSection>
  )
}
