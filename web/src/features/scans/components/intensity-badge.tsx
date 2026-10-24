'use client'

/**
 * The scan intensity (RFC-071), wherever a scan or a run is shown, so it is
 * clear how much it may touch the targets. Label system (research/247):
 * passive and active are a plain Tag (a classification, neutral ink, the icon
 * tells them apart); intrusive is a SignalChip, a neutral chip that raises
 * attention because it changes what a scan may touch. No hue: amber and
 * orange belong to severity and to "needs a person".
 *
 * Both never grow past their container: the text is cut with the full label
 * in the tooltip, so a narrow cell can never be overrun.
 */

import { Eye, Radar, Zap } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { SignalChip } from '@/components/ui/signal-chip'
import { Tag } from '@/components/ui/tag'
import { cn } from '@/lib/utils'
import type { ScanIntensity } from '@/lib/api/scan-types'

const ICON = { passive: Eye, active: Radar, intrusive: Zap } as const

export function IntensityBadge({
  intensity,
  className,
}: {
  intensity?: ScanIntensity | null
  className?: string
}) {
  const { t } = useTranslation()
  if (!intensity || !ICON[intensity]) return null
  const label = t(`scans.intensity.${intensity}`)
  const title = t('scans.intensity.badgeTitle', undefined, { level: label })
  if (intensity === 'intrusive') {
    return (
      <SignalChip
        icon={ICON.intrusive}
        title={title}
        className={cn('min-w-0 max-w-full overflow-hidden', className)}
      >
        <span className="min-w-0 truncate">{label}</span>
      </SignalChip>
    )
  }
  return (
    <Tag
      variant="plain"
      icon={ICON[intensity]}
      label={label}
      title={title}
      className={cn('min-w-0 max-w-full', className)}
    />
  )
}

/** The "Intensity" field label, for pages that render labels outside i18n hooks. */
export function IntensityLabel() {
  const { t } = useTranslation()
  return <>{t('scans.intensity.label')}</>
}
