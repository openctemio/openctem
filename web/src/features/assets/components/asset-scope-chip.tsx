'use client'

/**
 * The asset header's scan-scope chip (research 129 §3.1): may scans reach
 * this asset now. It shows the same gate answer as the inventory's scope
 * badge: from the list row's triage when the list asked for it, else from
 * the asset's attribution (`GET /assets/{id}/attribution`, cached and shared
 * with the Details tab). The API is the authority; this only reads it.
 */

import type { Asset, AssetTriage } from '../types/asset.types'
import type { AssetAttribution } from '../lib/attribution'
import { useAssetAttribution } from '../hooks/use-asset-attribution'
import { ScopeTriageBadge } from './inventory/scope-triage-badge'

/** The triage shape the scope badge reads, from an attribution answer. */
export function triageFromAttribution(a: AssetAttribution): AssetTriage {
  return {
    attributionState: a.state,
    confidence: a.confidence,
    humanDecided: a.human_decided,
    scanAllowed: a.active_checks_allowed,
    scanBlockedBy: a.active_checks_blocked_by,
    scanRefusalCode: a.blocked_code || (a.active_checks_allowed ? undefined : 'no_entry'),
  }
}

export function AssetScopeChip({ asset }: { asset: Pick<Asset, 'id' | 'triage'> }) {
  // Fetch only when the row did not bring its triage.
  const { attribution } = useAssetAttribution(asset.triage ? null : asset.id)
  const triage = asset.triage ?? (attribution ? triageFromAttribution(attribution) : undefined)
  if (!triage) return null
  return <ScopeTriageBadge triage={triage} />
}
