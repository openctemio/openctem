'use client'

/**
 * Shown on the Scans and Runs pages while a blackout that governs every
 * target is active, or while an override lifts scan windows. Hidden
 * otherwise, and for members who cannot read scans. Narrower policies are
 * shown where they apply (New Scan preview, run tasks, asset page).
 */

import Link from '@/components/link'
import { CalendarX, ShieldAlert } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, usePermissions } from '@/lib/permissions'

import { useScanWindowOverrides, useScanWindowPolicies } from '../api/use-scan-windows'
import { formatInZone } from '../lib/schedule'
import { isEmptySelector } from '../lib/selector'
import type { ScanWindowOverride, ScanWindowPolicy } from '../types'

/** Enabled blackouts with no selector that block now. */
export function orgWideBlackouts(policies: ScanWindowPolicy[] | undefined): ScanWindowPolicy[] {
  return (policies ?? []).filter(
    (p) => p.enabled && p.kind === 'blackout' && !p.open_now && isEmptySelector(p.selector)
  )
}

export function activeOverrides(overrides: ScanWindowOverride[] | undefined): ScanWindowOverride[] {
  return (overrides ?? []).filter((o) => o.active)
}

export function ScanWindowsBanner({ className }: { className?: string }) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.ScansRead)
  const { data: policies } = useScanWindowPolicies(canRead)
  const { data: overrides } = useScanWindowOverrides(canRead)
  const blackouts = orgWideBlackouts(policies?.data)
  const lifted = activeOverrides(overrides?.data)
  if (blackouts.length === 0 && lifted.length === 0) return null
  const link = (
    <Link href="/settings/scanning/scan-windows" className="underline underline-offset-2">
      {t('scanWindows.banner.link', 'Scan windows')}
    </Link>
  )
  return (
    <div className={className}>
      <div className="space-y-3">
        {blackouts.length > 0 && (
          <Alert data-testid="scan-windows-banner-blackout">
            <CalendarX className="h-4 w-4" aria-hidden />
            <AlertTitle>
              {t('scanWindows.banner.blackoutTitle', 'A blackout is active for every target')}
            </AlertTitle>
            <AlertDescription>
              <ul className="list-disc space-y-0.5 ps-5">
                {blackouts.map((p) => (
                  <li key={p.id}>
                    <span className="font-medium">{p.name}</span>
                    {p.next_change_at
                      ? ` ${t('scanWindows.banner.until', 'until {at}', { at: formatInZone(p.next_change_at) })}`
                      : ''}
                  </li>
                ))}
              </ul>
              <p className="mt-1">
                {t(
                  'scanWindows.banner.blackoutHint',
                  'Governed scans wait until it ends; runs started now hold their tasks.'
                )}{' '}
                {link}
              </p>
            </AlertDescription>
          </Alert>
        )}
        {lifted.length > 0 && (
          <Alert data-testid="scan-windows-banner-override">
            <ShieldAlert className="h-4 w-4" aria-hidden />
            <AlertTitle>
              {t('scanWindows.banner.overrideTitle', 'Scan windows are overridden')}
            </AlertTitle>
            <AlertDescription>
              <ul className="list-disc space-y-0.5 ps-5">
                {lifted.map((o) => (
                  <li key={o.id}>
                    <span className="font-medium">
                      {o.policy_name || t('scanWindows.override.all', 'Every policy')}
                    </span>{' '}
                    {t('scanWindows.banner.until', 'until {at}', { at: formatInZone(o.ends_at) })}
                  </li>
                ))}
              </ul>
              <p className="mt-1">
                {t('scanWindows.banner.overrideHint', 'Bug-bounty program windows still apply.')}{' '}
                {link}
              </p>
            </AlertDescription>
          </Alert>
        )}
      </div>
    </div>
  )
}
