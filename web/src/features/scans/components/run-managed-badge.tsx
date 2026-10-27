'use client'

import { Cog } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { runManagedLabel } from '../lib/run-display'

/**
 * Marks a run of a scan the platform manages (continuous coverage,
 * enrichment): the run is read-only for people. Nothing for a person's scan.
 */
export function RunManagedBadge({ managedBy }: { managedBy?: string | null }) {
  const { t } = useTranslation()
  const label = runManagedLabel(managedBy, t)
  if (!label) return null
  return (
    <Badge variant="secondary" className="gap-1 font-normal" data-testid="run-managed-badge">
      <Cog className="h-3 w-3" aria-hidden="true" />
      {label}
    </Badge>
  )
}
