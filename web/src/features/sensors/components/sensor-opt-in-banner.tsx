'use client'

import Link from 'next/link'
import { ShieldOff } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { affectedScans, useSensorOptInImpact } from '@/lib/api/sensor-opt-in-hooks'

/** How many affected scans the banner names before "and N more". */
const LISTED = 5

/**
 * The scans the organization's sensor opt-ins affect (api research/25 D3):
 * out-of-band callbacks (interactsh) and custom templates are off unless an
 * owner enabled them, so a scan that asks for interactsh runs without it and
 * a scan with custom templates is refused at trigger. Shown wherever scans
 * or the switches are managed; hidden when nothing is affected.
 */
export function SensorOptInBanner({ showSettingsLink = true }: { showSettingsLink?: boolean }) {
  const { data } = useSensorOptInImpact()
  const scans = affectedScans(data)
  if (!data || scans.length === 0) return null
  const listed = scans.slice(0, LISTED)
  const more = scans.length - listed.length + (data.truncated ? 1 : 0)
  return (
    <Alert data-testid="sensor-opt-in-banner">
      <ShieldOff className="h-4 w-4" aria-hidden />
      <AlertTitle>Some scans ask for sensor features your organization has turned off</AlertTitle>
      <AlertDescription>
        <p>
          Out-of-band callbacks (interactsh) and custom templates are off by default. Scans that ask
          for interactsh run without it; scans with custom templates are refused when they start.
        </p>
        <ul className="mt-2 list-disc space-y-0.5 pl-5">
          {listed.map((s) => (
            <li key={s.id}>
              <Link href={`/scans/${s.id}`} className="underline underline-offset-2">
                {s.name}
              </Link>
              <span className="text-muted-foreground">
                {' '}
                (
                {[
                  s.uses_interactsh && !data.opt_ins.allow_interactsh ? 'interactsh' : null,
                  s.uses_custom_templates && !data.opt_ins.allow_custom_templates
                    ? 'custom templates'
                    : null,
                ]
                  .filter(Boolean)
                  .join(', ')}
                )
              </span>
            </li>
          ))}
        </ul>
        {more > 0 && (
          <p className="mt-1 text-muted-foreground">
            {data.truncated ? 'and more' : `and ${more} more`}
          </p>
        )}
        {showSettingsLink && (
          <p className="mt-2">
            An owner can turn them on in{' '}
            <Link href="/settings/authentication" className="underline underline-offset-2">
              Settings, Authentication and security
            </Link>
            . Turning one on is audited and alerted, and a sensor still refuses what its own local
            policy does not allow.
          </p>
        )}
      </AlertDescription>
    </Alert>
  )
}
