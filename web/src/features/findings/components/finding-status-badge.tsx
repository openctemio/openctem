'use client'

import { Copy, Eye, ShieldAlert } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { StatusLozenge } from '@/components/ui/status-lozenge'
import {
  CheckCircleGlyph,
  DashedCircleGlyph,
  HalfCircleGlyph,
  RingDotGlyph,
  SlashedCircleGlyph,
  ThreeQuarterCircleGlyph,
  type StatusGlyph,
} from '@/components/ui/status-glyphs'
import type { FindingStatus, StatusConfig, StatusIconKey } from '../types'
import { FINDING_STATUS_CONFIG } from '../types'

// Neutral fallback for a status this UI build doesn't recognize (backend /
// source drift, e.g. a legacy or newer status value). Renders the raw status
// instead of crashing on `config.icon`.
const UNKNOWN_STATUS_CONFIG: StatusConfig = {
  label: 'Unknown',
  labelKey: '',
  tone: 'closed',
  icon: 'dashed',
  category: 'open',
}

/** Each status declares a progression icon in FINDING_STATUS_CONFIG; this renders it. */
export const STATUS_GLYPHS: Record<StatusIconKey, StatusGlyph> = {
  dashed: DashedCircleGlyph,
  'ring-dot': RingDotGlyph,
  half: HalfCircleGlyph,
  'three-quarter': ThreeQuarterCircleGlyph,
  check: CheckCircleGlyph,
  slashed: SlashedCircleGlyph,
  eye: Eye,
  copy: Copy,
  'shield-alert': ShieldAlert,
}

interface FindingStatusBadgeProps {
  status: FindingStatus
  className?: string
}

/**
 * A finding status as a lozenge tinted by workflow category (untouched, open,
 * in progress, resolved, accepted, closed) with a progression icon. Nothing
 * animates. The one rendering of a finding status.
 */
export function FindingStatusBadge({ status, className }: FindingStatusBadgeProps) {
  const { t } = useTranslation()
  const config = (FINDING_STATUS_CONFIG as Record<string, StatusConfig | undefined>)[status] ?? {
    ...UNKNOWN_STATUS_CONFIG,
    label: String(status) || UNKNOWN_STATUS_CONFIG.label,
  }
  const label = config.labelKey
    ? t(config.labelKey, config.label)
    : String(status)
      ? config.label
      : t('findings.statusBadge.unknown', 'Unknown')
  return (
    <StatusLozenge
      tone={config.tone}
      icon={STATUS_GLYPHS[config.icon]}
      label={label}
      value={String(status)}
      className={className}
    />
  )
}
