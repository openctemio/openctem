'use client'

/**
 * A list row's scope standing (research/124, RFC-054 §15) from the row's
 * triage: the active-scan gate's own answer for the asset, so the badge
 * never disagrees with a scan. A short word in the attention tones
 * (research/266), with an icon per kind of answer and the full reason in the
 * tooltip; a discovered asset that no entry covers reads "Not in scope", and
 * the tooltip says it gets passive checks only.
 */

import { Ban, CircleCheck, CircleDashed, Lock, MinusCircle, type LucideIcon } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { ToneChip, type Tone } from '@/components/ui/tone-chip'
import { scopeRefusalLabel, scopeRefusalMessage } from '@/features/scope/lib/scope-codes'
import type { AssetTriage } from '../../types/asset.types'

/** Tone and icon of a refusal code: blocked outright, set aside by a person, or held. */
export function triageRefusalLook(code: string | undefined): { tone: Tone; icon: LucideIcon } {
  if (code === 'deny_list' || code === 'invalid_target') return { tone: 'danger', icon: Ban }
  if (code === 'rejected' || code === 'excluded') return { tone: 'neutral', icon: MinusCircle }
  if (code === 'no_entry') return { tone: 'caution', icon: CircleDashed }
  return { tone: 'caution', icon: Lock }
}

export function ScopeTriageBadge({ triage }: { triage: AssetTriage | undefined }) {
  const { t } = useTranslation()
  if (!triage) return <span className="text-muted-foreground">-</span>
  const discovered = triage.attributionState === 'discovered'
  if (triage.scanAllowed) {
    return (
      <ToneChip
        tone="ok"
        icon={CircleCheck}
        value="allowed"
        label={t('assets.triage.badge.inScope', 'In scope')}
        title={t('assets.triage.badge.inScopeHint', 'A scope entry covers it; scans can reach it.')}
      />
    )
  }
  const code = triage.scanRefusalCode
  const { tone, icon } = triageRefusalLook(code)
  if (code === 'no_entry') {
    return (
      <ToneChip
        tone={tone}
        icon={icon}
        value="no_entry"
        label={t('assets.triage.badge.notInScope', 'Not in scope')}
        title={
          discovered
            ? t(
                'assets.triage.badge.passiveOnlyHint',
                'Discovery found this asset and no scope entry covers it, so it gets passive checks only. Add it to scope to scan it, or mark it out of scope.'
              )
            : scopeRefusalMessage(t, 'no_entry')
        }
      />
    )
  }
  // The guardrail's full name is long; the column shows the short word.
  const label =
    code === 'guardrailed'
      ? t('assets.triage.badge.guardrailed', 'Guardrail hold')
      : scopeRefusalLabel(t, code)
  return (
    <ToneChip
      tone={tone}
      icon={icon}
      value={code}
      label={label}
      title={`${scopeRefusalLabel(t, code)}: ${scopeRefusalMessage(t, code)}`}
    />
  )
}
