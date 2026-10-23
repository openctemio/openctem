'use client'

import { Gem, Lock } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export const MARKER_KINDS = [
  'beta',
  'preview',
  'new',
  'soon',
  'enterprise',
  'adminOnly',
  'system',
] as const
export type MarkerKind = (typeof MARKER_KINDS)[number]

const ICON: Partial<Record<MarkerKind, LucideIcon>> = {
  enterprise: Gem,
  adminOnly: Lock,
  system: Lock,
}

const DEFAULT_LABEL: Record<MarkerKind, string> = {
  beta: 'Beta',
  preview: 'Preview',
  new: 'New',
  soon: 'Soon',
  enterprise: 'Enterprise',
  adminOnly: 'Admin only',
  system: 'System',
}

/**
 * About the feature, not the data: Beta, Preview, New, Soon, Enterprise,
 * Admin only, System. An outline box with no hue, so it never competes with a
 * status. The text is always present.
 */
export function Marker({ kind, className }: { kind: MarkerKind; className?: string }) {
  const { t } = useTranslation()
  const Icon = ICON[kind]
  return (
    <span
      data-slot="marker"
      data-kind={kind}
      className={cn(
        'inline-flex h-[18px] w-fit shrink-0 items-center gap-1 whitespace-nowrap rounded-sm border border-border-strong px-1.5 text-xs font-medium leading-none text-muted-foreground',
        className
      )}
    >
      {Icon && <Icon className="size-3 shrink-0" aria-hidden />}
      {t(`labels.marker.${kind}`, DEFAULT_LABEL[kind])}
    </span>
  )
}
