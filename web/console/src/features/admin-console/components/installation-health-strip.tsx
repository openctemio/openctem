'use client'

import { MetricStrip, type MetricStripItem } from '@/features/shared'
import { TonePill } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import type { HealthTile } from '../lib/installation-health'

/**
 * The Overview's answer to "is the platform healthy?": one strip of five
 * states (services, storage, backups, platform sensors, database schema).
 * Each state is words plus an icon (TonePill), never colour alone, and each
 * tile opens the page that explains it.
 */
export function InstallationHealthStrip({
  tiles,
  loading,
}: {
  tiles: HealthTile[]
  loading?: boolean
}) {
  const { t } = useTranslation()
  const items: MetricStripItem[] = tiles.map((tile) => ({
    key: tile.key,
    label: t(tile.labelKey, tile.label),
    value: (
      <TonePill
        tone={tile.tone}
        label={t(tile.stateKey, tile.state, tile.vars)}
        state={tile.tone}
      />
    ),
    detail: tile.detailKey ? (
      <span className="block truncate text-xs text-muted-foreground">
        {t(tile.detailKey, tile.detail, tile.vars)}
      </span>
    ) : undefined,
    href: tile.href,
  }))
  return <MetricStrip items={items} loading={loading} />
}
