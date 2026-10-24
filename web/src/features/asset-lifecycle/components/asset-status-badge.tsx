'use client'

import { HealthStatus } from '@/components/ui/health-status'
import type { HealthState } from '@/lib/health-colors'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

type AssetStatus = 'active' | 'stale' | 'inactive' | 'archived' | string

interface AssetStatusBadgeProps {
  status: AssetStatus
  /**
   * Days since the asset was last observed. When provided alongside
   * a stale/inactive status, the badge renders as "Stale 12d" so
   * operators can tell how old the signal is at a glance.
   */
  daysSinceLastSeen?: number
  /**
   * Snooze expiry timestamp. When set, the tooltip mentions the
   * active snooze so operators know the worker is paused on this
   * asset.
   */
  snoozedUntil?: string | null
  className?: string
}

/** Lifecycle status -> health state (research/247): active is healthy, stale needs a look, the rest are off. */
export const ASSET_LIFECYCLE_HEALTH: Record<string, HealthState> = {
  active: 'ok',
  stale: 'warn',
  inactive: 'off',
  archived: 'off',
}

const STATUS_CONFIG: Record<string, { label: string; description: string }> = {
  active: {
    label: 'Active',
    description: 'Asset was recently observed by a scanner or integration.',
  },
  stale: {
    label: 'Stale',
    description: 'No source has re-observed this asset within the configured threshold.',
  },
  inactive: {
    label: 'Inactive',
    description: 'The asset has been stale long enough to be marked inactive.',
  },
  archived: {
    label: 'Archived',
    description: 'Archived — requires manual restore to return to active rotation.',
  },
}

const UNKNOWN_CONFIG = {
  label: 'Unknown',
  description: 'Unrecognised status value.',
}

export function AssetStatusBadge({
  status,
  daysSinceLastSeen,
  snoozedUntil,
  className,
}: AssetStatusBadgeProps) {
  const config = STATUS_CONFIG[status] ?? UNKNOWN_CONFIG
  const state = ASSET_LIFECYCLE_HEALTH[status] ?? 'unknown'

  const showDays =
    typeof daysSinceLastSeen === 'number' &&
    daysSinceLastSeen > 0 &&
    (status === 'stale' || status === 'inactive')

  const snoozeActive = snoozedUntil && new Date(snoozedUntil) > new Date()

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex">
          <HealthStatus
            state={state}
            value={status}
            label={config.label}
            detail={[showDays ? `${daysSinceLastSeen}d` : '', snoozeActive ? 'snoozed' : ''].filter(
              Boolean
            )}
            className={className}
          />
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-xs">
        <p>{config.description}</p>
        {showDays && (
          <p className="mt-1 text-muted-foreground">Last observed {daysSinceLastSeen} days ago.</p>
        )}
        {snoozeActive && (
          <p className="mt-1 text-muted-foreground">
            Lifecycle worker paused until {new Date(snoozedUntil).toLocaleDateString()}.
          </p>
        )}
      </TooltipContent>
    </Tooltip>
  )
}
