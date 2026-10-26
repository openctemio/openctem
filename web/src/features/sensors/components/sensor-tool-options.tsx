'use client'

import { useMemo } from 'react'

import { useTranslation } from '@/context/i18n-provider'
import { MetaItem, MetaLine } from '@/features/shared'

import { SensorTag } from './sensor-cells'
import { boundsText, toolOptions, type OptionSafety, type ToolOption } from '../lib/tool-options'

const SAFETY_TONE: Record<OptionSafety, 'muted' | 'warning' | 'destructive'> = {
  safe: 'muted',
  impact: 'warning',
  dangerous: 'destructive',
}

function OptionRow({ tool, o }: { tool: string; o: ToolOption }) {
  const { t } = useTranslation()
  const title = o.common
    ? t(`sensors.toolOptions.common.${o.common}`, o.title ?? o.key)
    : t(`sensors.toolOptions.tool.${tool}.${o.key}`, o.title ?? o.key)
  const bounds = boundsText(o)
  return (
    <li className="space-y-1 px-2 py-1.5" data-option={o.key}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="font-medium">{title}</span>
        <span className="font-mono text-muted-foreground">{o.key}</span>
        {o.common && (
          <SensorTag tone="info">{t('sensors.toolOptions.commonTag', 'Common')}</SensorTag>
        )}
        {o.safety !== 'safe' && (
          <SensorTag tone={SAFETY_TONE[o.safety]}>
            {t(`sensors.toolOptions.safety.${o.safety}`, o.safety)}
          </SensorTag>
        )}
      </div>
      {o.description && <p className="text-muted-foreground">{o.description}</p>}
      <MetaLine
        items={[
          o.defaultValue !== undefined && (
            <MetaItem key="default" label={t('sensors.toolOptions.default', 'Default')}>
              <span className="font-mono">{o.defaultValue}</span>
            </MetaItem>
          ),
          bounds && (
            <MetaItem key="bounds" label={t('sensors.toolOptions.bounds', 'Range')}>
              <span className="tabular-nums">{bounds}</span>
            </MetaItem>
          ),
          o.values && (
            <MetaItem key="values" label={t('sensors.toolOptions.values', 'Values')}>
              {o.values.join(', ')}
            </MetaItem>
          ),
          <MetaItem key="scope" label={t('sensors.toolOptions.setBy', 'Set by')}>
            {o.scope === 'scan'
              ? t('sensors.toolOptions.scope.scan', 'Sensor configuration or a scan')
              : t('sensors.toolOptions.scope.sensor', 'Sensor configuration only')}
          </MetaItem>,
          o.flag && (
            <MetaItem key="flag" label={t('sensors.toolOptions.flag', 'Native flag')}>
              <span className="font-mono">{o.flag}</span>
            </MetaItem>
          ),
        ]}
      />
    </li>
  )
}

/**
 * The options a tool declares in its manifest, read-only: common options
 * first, then the tool's own, with default, range, who may set each and the
 * native flag it maps to. Nothing when the tool declares none.
 */
export function SensorToolOptions({ tool, descriptor }: { tool: string; descriptor: unknown }) {
  const { t } = useTranslation()
  const options = useMemo(() => toolOptions(descriptor), [descriptor])
  if (options.length === 0) return null
  return (
    <details className="rounded-md bg-muted/40 text-xs" data-tool-options={tool}>
      <summary className="cursor-pointer px-2 py-1.5 font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
        {t('sensors.toolOptions.summary', 'Options ({count})', { count: options.length })}
      </summary>
      <ul
        className="divide-y border-t"
        aria-label={t('sensors.toolOptions.listLabel', '{tool} options', { tool })}
      >
        {options.map((o) => (
          <OptionRow key={o.key} tool={tool} o={o} />
        ))}
      </ul>
    </details>
  )
}
