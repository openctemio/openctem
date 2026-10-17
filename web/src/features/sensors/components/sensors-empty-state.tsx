'use client'

/**
 * The Sensors page before the organization has a sensor: what a sensor is,
 * how to add one, and that scanning repositories from CI needs none.
 *
 * Pairing comes first: the sensor makes its own key and the administrator
 * never handles a secret (api docs/rfcs/RFC-052). Installing with an API key
 * is offered only where the organization still allows bearer keys.
 */

import Link from '@/components/link'
import { ArrowRight, Download, Link2, RadioTower, ScanSearch, Waypoints } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export interface SensorsEmptyStateProps {
  /** sensors:pair: show "Pair a sensor". */
  canPair: boolean
  /** sensors:write and bearer keys allowed: show "Install with an API key". */
  canInstallWithKey: boolean
  /** ci:read and the scans module: show the CI/CD hint. */
  canReadCI: boolean
  onPair: () => void
  onInstall: () => void
  className?: string
}

export function SensorsEmptyState({
  canPair,
  canInstallWithKey,
  canReadCI,
  onPair,
  onInstall,
  className,
}: SensorsEmptyStateProps) {
  const { t } = useTranslation()
  const roles = [
    {
      key: 'scanner',
      icon: ScanSearch,
      title: t('sensors.empty.role.scanner.title'),
      text: t('sensors.empty.role.scanner.text'),
    },
    {
      key: 'collector',
      icon: Waypoints,
      title: t('sensors.empty.role.collector.title'),
      text: t('sensors.empty.role.collector.text'),
    },
  ]
  return (
    <Card className={cn('gap-0 py-0', className)}>
      <CardContent className="p-0">
        <div className="space-y-6 p-6 sm:p-8">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
            <span
              aria-hidden
              className="flex size-11 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary"
            >
              <RadioTower className="size-5" />
            </span>
            <div className="min-w-0 space-y-1.5">
              <h2 className="text-lg font-semibold">{t('sensors.empty.title')}</h2>
              <p className="max-w-2xl text-sm text-muted-foreground">{t('sensors.empty.what')}</p>
            </div>
          </div>

          <ul className="grid gap-3 sm:grid-cols-2">
            {roles.map((r) => (
              <li key={r.key} className="flex gap-3 rounded-lg border bg-muted/30 p-3">
                <r.icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
                <span className="min-w-0 text-sm">
                  <span className="block font-medium">{r.title}</span>
                  <span className="block text-muted-foreground">{r.text}</span>
                </span>
              </li>
            ))}
          </ul>

          {canPair || canInstallWithKey ? (
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              {canPair && (
                <Button onClick={onPair}>
                  <Link2 className="h-4 w-4" />
                  {t('sensors.pair.title')}
                </Button>
              )}
              {canInstallWithKey && (
                <Button variant={canPair ? 'outline' : 'default'} onClick={onInstall}>
                  <Download className="h-4 w-4" />
                  {t('sensors.empty.installWithKey')}
                </Button>
              )}
              {canPair && (
                <p className="text-xs text-muted-foreground sm:ms-1">
                  {t('sensors.empty.pairHint')}
                </p>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t('sensors.empty.askAdmin')}</p>
          )}
        </div>

        {canReadCI && (
          <div className="flex flex-col gap-1 border-t bg-muted/30 px-6 py-3 text-sm sm:flex-row sm:items-center sm:gap-2 sm:px-8">
            <span className="text-muted-foreground">{t('sensors.empty.ciNoSensor')}</span>
            <Link
              href="/ci-cd"
              className="inline-flex items-center gap-1 rounded-sm font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {t('sensors.empty.ciLink')}
              <ArrowRight className="h-3.5 w-3.5" aria-hidden />
            </Link>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
