'use client'

import { MetricStrip, type MetricStripItem } from '@/features/shared'
import { TonePill } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import type { HealthTile } from '../lib/installation-health'
import { resolveNamedVars } from '../lib/named-vars'

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
  const items: MetricStripItem[] = tiles.map((tile) => {
    const vars = resolveNamedVars(t, tile.vars, tile.named)
    return {
      key: tile.key,
      label: t(tile.labelKey, tile.label),
      value: (
        <TonePill tone={tile.tone} label={t(tile.stateKey, tile.state, vars)} state={tile.tone} />
      ),
      detail: tile.detailKey ? (
        <span className="block text-cap text-muted-foreground [overflow-wrap:anywhere]">
          {t(tile.detailKey, tile.detail, vars)}
        </span>
      ) : undefined,
      href: tile.href,
    }
  })
  return <MetricStrip items={items} loading={loading} />
}
