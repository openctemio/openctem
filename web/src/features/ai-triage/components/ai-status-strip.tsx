'use client'

import { useTranslation } from '@/context/i18n-provider'
import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'

import type { AISettings } from '../api/use-ai-settings'
import type { AIMaskingPolicy } from '../api/use-ai-masking'
import type { AIConfig } from '../types/ai-triage.types'

export type AISettingsTab = 'provider' | 'features' | 'knowledge' | 'limits' | 'activity'

interface AIStatusStripProps {
  settings?: AISettings
  config?: AIConfig
  masking?: AIMaskingPolicy | null
  loading?: boolean
  tab: AISettingsTab
  onTab: (tab: AISettingsTab) => void
}

/**
 * Settings > AI at a glance (api: docs/architecture/ai-triage.md): whether
 * AI triage is on, where the AI comes from, this month's use against the
 * limit, automatic triage and masking. Each tile opens the tab that changes
 * it, so the strip follows the page anatomy rule (every tile acts).
 */
export function AIStatusStrip({
  settings,
  config,
  masking,
  loading,
  tab,
  onTab,
}: AIStatusStripProps) {
  const { t } = useTranslation()
  const on = settings?.enabled === true && settings?.source !== 'off'
  const missing = config?.reason === 'platform_not_configured'
  const limit = config?.monthlyTokenLimit ?? 0
  const used = config?.tokensUsedThisMonth ?? 0
  const masked = masking?.classes.filter((c) => c.masked).length ?? 0
  const classes = masking?.classes.length ?? 0

  const source =
    settings?.source === 'own'
      ? t('settings.ai.status.sourceOwn', 'Own provider')
      : settings?.source === 'off'
        ? t('settings.ai.status.sourceOff', 'Off')
        : missing
          ? t('settings.ai.status.sourceMissing', 'Not set up')
          : t('settings.ai.status.sourcePlatform', 'Platform AI')

  const items: MetricStripItem[] = [
    {
      key: 'triage',
      label: t('settings.ai.status.triage', 'AI triage'),
      value: on ? t('settings.ai.status.on', 'On') : t('settings.ai.status.off', 'Off'),
      onClick: () => onTab('provider'),
      active: tab === 'provider',
    },
    {
      key: 'source',
      label: t('settings.ai.status.source', 'Source'),
      value: source,
      hint: config?.model || undefined,
      onClick: () => onTab('provider'),
      active: tab === 'provider',
    },
    {
      key: 'month',
      label: t('settings.ai.status.month', 'This month'),
      value:
        limit > 0 ? `${Math.min(100, Math.round((used / limit) * 100))}%` : used.toLocaleString(),
      hint:
        limit > 0
          ? t('settings.ai.status.monthOfLimit', 'of {limit} tokens', {
              limit: limit.toLocaleString(),
            })
          : t('settings.ai.status.monthNoLimit', 'tokens, no limit'),
      tone: limit > 0 && used >= limit ? 'warning' : 'default',
      onClick: () => onTab('limits'),
      active: tab === 'limits',
    },
    {
      key: 'auto',
      label: t('settings.ai.status.auto', 'Automatic triage'),
      value: config?.autoTriageEnabled
        ? t('settings.ai.status.on', 'On')
        : t('settings.ai.status.off', 'Off'),
      onClick: () => onTab('features'),
      active: tab === 'features',
    },
    {
      key: 'masking',
      label: t('settings.ai.status.masking', 'Masked data kinds'),
      value: classes > 0 ? `${masked}/${classes}` : '—',
      onClick: () => onTab('limits'),
      active: tab === 'limits',
    },
  ]

  return <MetricStrip items={items} loading={loading} />
}
