'use client'

import { useId, useState } from 'react'
import { Check, Info } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { DetailField, DetailFieldGrid } from '@/features/shared'
import type { Sensor } from '@/lib/api/sensor-types'
import { cn } from '@/lib/utils'

import { SensorTag } from './sensor-cells'
import { hasReportedTools } from '../lib/capabilities'
import { reportedToolNames } from '../lib/sensor-edit'
import { normalizeSensorVersion, sensorSdkVersion } from '../lib/sensor-version'

/**
 * The platform cannot know which tools a sensor has (a third-party sensor
 * can carry anything), so the install flow does not ask: the sensor reports
 * its inventory on its first heartbeat and the platform uses every installed
 * tool it reports. The sensor grant narrows them (api RFC-052).
 */

/**
 * Step 3 of the install flow: the sensor's self-report (host, version, SDK,
 * protocol, capacity, tools).
 */
export function SensorFirstReport({
  sensor,
  onDone,
  onOpen,
  children,
}: {
  sensor: Sensor
  /** After Done (and the save, when there was one). */
  onDone?: () => void
  onOpen?: (sensor: Sensor) => void
  /** More settings shown above the buttons (the zone picker). */
  children?: React.ReactNode
}) {
  const { t } = useTranslation()
  const listId = useId()
  const [done, setDone] = useState(false)

  const reported = hasReportedTools(sensor)
  const tools = [...(sensor.reported?.tools ?? [])].sort(
    (a, b) => Number(b.installed) - Number(a.installed) || a.name.localeCompare(b.name)
  )
  const installed = reportedToolNames(sensor) ?? []

  const version = normalizeSensorVersion(sensor.version)
  const sdk = sensorSdkVersion(sensor)
  const platform = [sensor.reported?.os, sensor.reported?.arch].filter(Boolean).join('/')
  const slots = sensor.reported?.max_concurrent_jobs ?? null
  const protocol = sensor.protocol

  const handleDone = () => {
    setDone(true)
    onDone?.()
  }

  return (
    <div className="space-y-4">
      <div
        className="flex items-start gap-3 rounded-lg border border-success/40 bg-success/10 p-3 text-sm"
        role="status"
      >
        <Check className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
        <div className="min-w-0">
          <p className="font-medium">{t('sensors.review.connected', 'Connected')}</p>
          <p className="text-muted-foreground">
            {t('sensors.review.firstHeartbeat', '{name} sent its first heartbeat.', {
              name: sensor.name,
            })}
          </p>
        </div>
      </div>

      <section
        className="space-y-3"
        aria-label={t('sensors.review.reportedTitle', 'What it reported')}
      >
        <h3 className="text-sm font-semibold">
          {t('sensors.review.reportedTitle', 'What it reported')}
        </h3>
        {/* Two columns from phone width up: the four values are short. */}
        <DetailFieldGrid className="grid-cols-2 gap-x-4 rounded-lg border bg-background p-3">
          <DetailField label={t('sensors.review.host', 'Host')}>
            <span className="flex flex-col gap-0.5">
              <span className="break-all">
                {sensor.hostname || t('sensors.review.notReported', 'Not reported')}
              </span>
              {platform && <span className="text-xs text-muted-foreground">{platform}</span>}
            </span>
          </DetailField>
          <DetailField label={t('sensors.review.version', 'Version')}>
            <span className="flex flex-col gap-0.5 tabular-nums">
              <span>{version ?? t('sensors.review.notReported', 'Not reported')}</span>
              {sdk && (
                <span className="text-xs text-muted-foreground">
                  {t('sensors.review.sdk', 'SDK {version}', { version: sdk })}
                </span>
              )}
            </span>
          </DetailField>
          <DetailField label={t('sensors.review.protocol', 'Protocol')}>
            {protocol ? (
              <span className="inline-flex items-center gap-1.5 tabular-nums">
                v{protocol.version}
                {(protocol.deprecated || protocol.version < 2) && (
                  <SensorTag tone="warning">
                    {t('sensors.review.deprecated', 'deprecated')}
                  </SensorTag>
                )}
              </span>
            ) : (
              t('sensors.review.notReported', 'Not reported')
            )}
          </DetailField>
          <DetailField label={t('sensors.review.capacity', 'Capacity')}>
            <span className="tabular-nums">
              {slots != null && slots > 0
                ? t('sensors.review.slots', '{count} jobs at once', { count: slots })
                : t('sensors.review.notReported', 'Not reported')}
            </span>
          </DetailField>
        </DetailFieldGrid>
      </section>

      {!reported ? (
        <ToolsNote
          title={t('sensors.review.toolsUnknown', 'It has not reported its tools.')}
          text={t(
            'sensors.review.toolsUnknownHint',
            'Older sensors do not send a tool list. This updates by itself if one arrives.'
          )}
        />
      ) : tools.length === 0 || installed.length === 0 ? (
        <ToolsNote
          title={t('sensors.review.noTools', 'It reported no scanning tools.')}
          text={t(
            'sensors.review.noToolsHint',
            'That is normal for a collector or a custom sensor. There is nothing to choose.'
          )}
        />
      ) : (
        <section className="space-y-2" aria-describedby={`${listId}-hint`}>
          <h3 className="text-sm font-semibold">{t('sensors.review.toolsTitle', 'Its tools')}</h3>
          <p id={`${listId}-hint`} className="text-xs text-muted-foreground">
            {t(
              'sensors.review.toolsHint',
              'Jobs can use every installed tool. To narrow them, edit the sensor grant.'
            )}
          </p>
          <ul
            className="divide-y rounded-lg border bg-background"
            aria-label={t('sensors.review.reportedTools', 'Reported tools')}
          >
            {tools.map((tool) => (
              <li
                key={tool.name}
                data-tool={tool.name}
                className="flex min-h-10 items-center gap-3 px-3 py-2 text-sm"
              >
                <span
                  className={cn(
                    'flex min-w-0 flex-1 items-center gap-2',
                    !tool.installed && 'text-muted-foreground'
                  )}
                >
                  <span className="truncate font-medium">{tool.name}</span>
                  {tool.version && (
                    <span className="text-xs text-muted-foreground tabular-nums">
                      {tool.version}
                    </span>
                  )}
                  {tool.capabilities && tool.capabilities.length > 0 && (
                    <span
                      className="truncate text-xs text-muted-foreground"
                      title={t('sensors.review.serves', 'Serves {caps}', {
                        caps: tool.capabilities.join(', '),
                      })}
                    >
                      {tool.capabilities.join(' · ')}
                    </span>
                  )}
                </span>
                {!tool.installed && (
                  <SensorTag>{t('sensors.review.notInstalled', 'not installed')}</SensorTag>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {children}

      <div className="flex flex-wrap justify-end gap-2">
        {onOpen && (
          <Button variant="outline" onClick={() => onOpen(sensor)}>
            {t('sensors.review.open', 'Open sensor')}
          </Button>
        )}
        <Button onClick={handleDone} disabled={done}>
          {t('sensors.review.done', 'Done')}
        </Button>
      </div>
    </div>
  )
}

function ToolsNote({ title, text }: { title: string; text: string }) {
  return (
    <div className="flex items-start gap-2.5 rounded-lg border border-dashed bg-background p-3 text-sm">
      <Info className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
      <div className="min-w-0">
        <p className="font-medium">{title}</p>
        <p className="text-muted-foreground">{text}</p>
      </div>
    </div>
  )
}
