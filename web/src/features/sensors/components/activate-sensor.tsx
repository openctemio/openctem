'use client'

/**
 * /activate: the page a sensor's printed link opens (api
 * docs/architecture/sensor-pairing.md, "One install path"; research/356).
 *
 * The sensor prints `<console>/activate?code=K7QM-4ZTD`. The page reads the
 * code once, removes it from the address bar, looks it up (sensors:pair) and
 * shows the review the Add sensor dialog shows: the organization the sensor
 * joins, the host, its address next to yours, the fingerprint to pick and the
 * approval with step-up. It never approves on load. Without a code it asks
 * for the one the sensor printed.
 */

import { useEffect, useRef, useState } from 'react'
import Link from '@/components/link'
import { useRouter } from 'next/navigation'
import { CheckCircle2, Loader2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { useSensor } from '@/lib/api/sensor-hooks'
import type { SensorPairingView } from '@/lib/api/sensor-pairing-hooks'
import type { Sensor } from '@/lib/api/sensor-types'
import { Permission, useHasPermission } from '@/lib/permissions'

import { formatPairingCode, normalizePairingCode } from '../lib/pairing'
import { FIRST_HEARTBEAT_POLL_MS } from './sensor-install-flow'
import { EnterCodePanel } from './sensor-pairing-steps'

/**
 * The code a link carried, normalised, and the address without it. The
 * code is an index, never a credential, but it has no reason to stay in the
 * history or on a shared screen.
 */
export function takeCodeFromLocation(search: string): { code: string; rest: string } {
  const params = new URLSearchParams(search)
  const raw = params.get('code')
  params.delete('code')
  const norm = raw ? normalizePairingCode(raw) : null
  const rest = params.toString()
  return { code: norm ? formatPairingCode(norm) : '', rest: rest ? `?${rest}` : '' }
}

export function ActivateSensor() {
  const { t } = useTranslation()
  const router = useRouter()
  const canPair = useHasPermission(Permission.SensorsPair)
  // undefined until the address was read (client only).
  const [code, setCode] = useState<string | undefined>(undefined)
  const [approved, setApproved] = useState<SensorPairingView | null>(null)

  // Read once per mounted page: a second effect run (React's development
  // double run, or a re-render) must not read the address it already cleaned.
  const taken = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (taken.current === undefined) {
      const { code: c, rest } = takeCodeFromLocation(window.location.search)
      taken.current = c
      if (window.location.search) {
        window.history.replaceState(window.history.state, '', window.location.pathname + rest)
      }
    }
    setCode(taken.current)
  }, [])

  return (
    <PageStack>
      <PageHeader
        title={t('sensors.activate.title')}
        description={t('sensors.activate.description')}
      />
      <Card className="w-full max-w-2xl gap-0 py-0" data-testid="activate-sensor">
        <CardContent className="p-4 sm:p-6">
          {!canPair ? (
            <p className="text-sm text-muted-foreground">{t('sensors.activate.needsPermission')}</p>
          ) : approved ? (
            <ActivateDone view={approved} />
          ) : code === undefined ? (
            <Skeleton className="h-40 w-full" />
          ) : (
            <EnterCodePanel
              initialCode={code || undefined}
              onApproved={setApproved}
              onClose={() => router.push('/sensors')}
            />
          )}
        </CardContent>
      </Card>
    </PageStack>
  )
}

/** Poll the new sensor until its first heartbeat (module scope: see the SWR note in the panel). */
function seenInterval(s?: Sensor): number {
  return s?.last_seen_at ? 0 : FIRST_HEARTBEAT_POLL_MS
}

function ActivateDone({ view }: { view: SensorPairingView }) {
  const { t } = useTranslation()
  const { data: sensor } = useSensor(view.sensor_id ?? null, { refreshInterval: seenInterval })
  const online = !!sensor?.last_seen_at
  return (
    <div className="space-y-4" aria-live="polite" data-testid="activate-done">
      <div className="flex items-start gap-3">
        {online ? (
          <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-success" aria-hidden />
        ) : (
          <Loader2
            className="mt-0.5 h-5 w-5 shrink-0 animate-spin text-primary motion-reduce:animate-none"
            aria-hidden
          />
        )}
        <div className="min-w-0 space-y-1">
          <p className="font-medium">
            {online
              ? t('sensors.onboard.online', undefined, { name: sensor?.name ?? '' })
              : t('sensors.activate.approved')}
          </p>
          <p className="text-sm text-muted-foreground">
            {online ? t('sensors.activate.onlineNext') : t('sensors.activate.approvedNext')}
          </p>
        </div>
      </div>
      <div className="flex justify-end">
        <Button asChild>
          <Link href="/sensors">{t('sensors.activate.toSensors')}</Link>
        </Button>
      </div>
    </div>
  )
}
