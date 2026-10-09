'use client'

import Link from '@/components/link'
import { Snowflake } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Permission, usePermissions } from '@/lib/permissions'

import { useFreezeWindows } from '../api/use-freeze-windows'
import { activeWindows, formatInZone } from '../lib/schedule'
import type { FreezeWindow } from '../types'

interface FreezeBannerProps {
  /** Only this zone's windows and the organization-wide ones. */
  zoneId?: string
  /** Zone names by id, to say which zone a window freezes. */
  zoneNames?: Map<string, string>
  className?: string
}

function scopeOf(w: FreezeWindow, zoneNames?: Map<string, string>): string {
  if (!w.scan_zone_id) return 'the whole organization'
  const name = zoneNames?.get(w.scan_zone_id)
  return name ? `zone "${name}"` : 'one scan zone'
}

/**
 * Shown while a scan freeze window is active: active scans of the
 * organization (or of a zone) are not dispatched until it ends. Hidden
 * otherwise, and for members who cannot read scans.
 */
export function FreezeBanner({ zoneId, zoneNames, className }: FreezeBannerProps) {
  const { can } = usePermissions()
  const canRead = can(Permission.ScansRead)
  const { data } = useFreezeWindows({}, canRead)
  const active = activeWindows(data?.data).filter(
    (w) => !zoneId || !w.scan_zone_id || w.scan_zone_id === zoneId
  )
  if (active.length === 0) return null
  return (
    <Alert className={className} data-testid="freeze-banner">
      <Snowflake className="h-4 w-4" aria-hidden />
      <AlertTitle>
        {active.length === 1 ? 'A scan freeze window is active' : 'Scan freeze windows are active'}
      </AlertTitle>
      <AlertDescription>
        <ul className="list-disc space-y-0.5 pl-5">
          {active.map((w) => (
            <li key={w.id}>
              <span className="font-medium">{w.name}</span> freezes {scopeOf(w, zoneNames)}
              {w.active_until
                ? ` until ${formatInZone(w.active_until, w.timezone)} (${w.timezone})`
                : ''}
              .
            </li>
          ))}
        </ul>
        <p className="mt-1">
          Active scans are not dispatched until then; scheduled runs start when the window ends.
          Passive discovery and imports continue.{' '}
          <Link href="/settings/scanning/freeze-windows" className="underline underline-offset-2">
            Freeze windows
          </Link>
        </p>
      </AlertDescription>
    </Alert>
  )
}
