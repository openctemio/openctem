'use client'

/**
 * "Possible path, not proven" (api docs/architecture/attack-paths.md, Proof):
 * exposure chains and attack paths are built from the asset graph and the
 * open findings. No check has shown that an attacker can follow one, so
 * every place that presents them as paths says so, until a verdict exists.
 * One component for every such place.
 */

import { CircleHelp } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export function PossiblePathLabel({ className }: { className?: string }) {
  const { t } = useTranslation()
  const hint = t(
    'components.possiblePath.hint',
    'Built from your asset relationships and open findings. No check has shown that an attacker can follow it.'
  )
  return (
    <Badge
      variant="outline"
      className={cn('gap-1 text-xs font-normal text-muted-foreground', className)}
      title={hint}
      data-slot="possible-path"
    >
      <CircleHelp className="h-3 w-3" aria-hidden />
      <span>{t('components.possiblePath.label', 'Possible path, not proven')}</span>
      <span className="sr-only">: {hint}</span>
    </Badge>
  )
}
