'use client'

/**
 * A list row's scope standing (research/124, RFC-054 §15) from the row's
 * triage: the active-scan gate's own answer for the asset, so the badge
 * never disagrees with a scan. A discovered asset that no entry covers reads
 * "Not in scope · passive only".
 */

import { useTranslation } from '@/context/i18n-provider'
import { TonePill } from '@/features/shared'
import { refusalTone } from '@/features/scope/components/scope-check-badge'
import { scopeRefusalLabel, scopeRefusalMessage } from '@/features/scope/lib/scope-codes'
import type { AssetTriage } from '../../types/asset.types'

export function ScopeTriageBadge({ triage }: { triage: AssetTriage | undefined }) {
  const { t } = useTranslation()
  if (!triage) return <span className="text-muted-foreground">-</span>
  const discovered = triage.attributionState === 'discovered'
  if (triage.scanAllowed) {
    return (
      <TonePill
        tone="success"
        label={t('assets.triage.badge.inScope', 'In scope')}
        title={t('assets.triage.badge.inScopeHint', 'A scope entry covers it; scans can reach it.')}
        state="allowed"
      />
    )
  }
  if (triage.scanRefusalCode === 'no_entry') {
    return (
      <TonePill
        tone="warning"
        label={
          discovered
            ? t('assets.triage.badge.passiveOnly', 'Not in scope · passive only')
            : t('assets.triage.badge.notInScope', 'Not in scope')
        }
        title={
          discovered
            ? t(
                'assets.triage.badge.passiveOnlyHint',
                'Discovery found this asset and no scope entry covers it, so it gets passive checks only. Add it to scope to scan it, or mark it out of scope.'
              )
            : scopeRefusalMessage(t, 'no_entry')
        }
        state="no_entry"
      />
    )
  }
  return (
    <TonePill
      tone={refusalTone(triage.scanRefusalCode)}
      label={scopeRefusalLabel(t, triage.scanRefusalCode)}
      title={scopeRefusalMessage(t, triage.scanRefusalCode)}
      state={triage.scanRefusalCode}
    />
  )
}
