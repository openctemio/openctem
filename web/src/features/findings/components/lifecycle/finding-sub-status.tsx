'use client'

import { useSubStatusCatalog } from '../../api/use-finding-lifecycles'
import { SubStatusPill } from './sub-status-pill'

interface FindingSubStatusProps {
  /** The finding's sub_status_id; absent: nothing is shown (the status itself). */
  subStatusId?: string | null
  showStatus?: boolean
  className?: string
}

/**
 * A finding's sub-status next to its status badge. Renders nothing for a
 * finding without one, or while the catalog loads.
 */
export function FindingSubStatus({ subStatusId, showStatus, className }: FindingSubStatusProps) {
  const catalog = useSubStatusCatalog(!!subStatusId)
  const sub = subStatusId ? catalog.get(subStatusId) : undefined
  if (!sub) return null
  return <SubStatusPill subStatus={sub} showStatus={showStatus} className={className} />
}
