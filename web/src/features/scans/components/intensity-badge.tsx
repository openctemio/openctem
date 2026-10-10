'use client'

/**
 * The scan intensity (RFC-071) as a small badge: wherever a scan or a run is
 * shown, so it is clear how much it may touch the targets.
 */

import { Eye, Radar, Zap } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { ScanIntensity } from '@/lib/api/scan-types'

const STYLE: Record<ScanIntensity, { icon: React.ReactNode; className: string }> = {
  passive: { icon: <Eye className="h-3 w-3" aria-hidden />, className: 'text-success' },
  active: { icon: <Radar className="h-3 w-3" aria-hidden />, className: 'text-info' },
  intrusive: { icon: <Zap className="h-3 w-3" aria-hidden />, className: 'text-warning' },
}

export function IntensityBadge({
  intensity,
  className,
}: {
  intensity?: ScanIntensity | null
  className?: string
}) {
  const { t } = useTranslation()
  if (!intensity || !STYLE[intensity]) return null
  const label = t(`scans.intensity.${intensity}`)
  return (
    <Badge
      variant="outline"
      className={cn('gap-1 text-[11px] font-normal', STYLE[intensity].className, className)}
      title={t('scans.intensity.badgeTitle', undefined, { level: label })}
    >
      {STYLE[intensity].icon}
      {label}
    </Badge>
  )
}

/** The "Intensity" field label, for pages that render labels outside i18n hooks. */
export function IntensityLabel() {
  const { t } = useTranslation()
  return <>{t('scans.intensity.label')}</>
}
