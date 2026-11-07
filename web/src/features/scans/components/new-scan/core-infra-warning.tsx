'use client'

/**
 * A warning, never a block: the scan's address or range targets cover the
 * core infrastructure the organization's sensors depend on (their DNS
 * resolvers, gateways, their own addresses, the platform's addresses), as
 * the sensors reported it. An intrusive scan of a sensor's resolver or
 * gateway can cut that sensor off the platform. "Exclude these" adds the
 * addresses to the organization's scope exclusions (do not scan) for those
 * who may change the scope. Sensor names and addresses are rendered as text.
 */

import { useMemo, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, usePermissions } from '@/lib/permissions'
import { useSensorCoreAddresses } from '@/lib/api/sensor-hooks'
import { createExclusions } from '@/features/assets/api/triage-api'
import { coreInfraHits, type CoreInfraHit } from '../../lib/core-infra'

/** How many addresses are named one by one. */
const LISTED = 5

function useRoleLabel() {
  const { t } = useTranslation()
  return (role: string) => {
    switch (role) {
      case 'resolver':
        return t('scans.coreInfra.role.resolver')
      case 'tool_resolver':
        return t('scans.coreInfra.role.tool_resolver')
      case 'gateway':
        return t('scans.coreInfra.role.gateway')
      case 'host':
        return t('scans.coreInfra.role.host')
      case 'platform':
        return t('scans.coreInfra.role.platform')
      default:
        return t('scans.coreInfra.role.other')
    }
  }
}

export function CoreInfraWarning({ targets }: { targets: readonly string[] }) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.SensorsRead)
  const canExclude = can(Permission.ScopeWrite)
  const { data } = useSensorCoreAddresses(canRead && targets.length > 0)
  const [excluded, setExcluded] = useState<ReadonlySet<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const roleLabel = useRoleLabel()

  const hits = useMemo(
    () => coreInfraHits(targets, data).filter((h) => !excluded.has(h.address)),
    [targets, data, excluded]
  )
  if (hits.length === 0) return null

  const describe = (h: CoreInfraHit) =>
    h.uses
      .map((u) =>
        t('scans.coreInfra.use', undefined, { role: roleLabel(u.role), sensor: u.sensorName })
      )
      .join('; ')

  const exclude = async () => {
    setBusy(true)
    try {
      const res = await createExclusions(
        hits.map((h) => ({ exclusion_type: 'ip_address' as const, pattern: h.address })),
        { kind: 'do_not_scan', reason: t('scans.coreInfra.reason') }
      )
      const done = res.results.filter((r) => r.result !== 'refused').map((r) => r.pattern)
      setExcluded((prev) => new Set([...prev, ...done]))
      if (res.refused > 0) {
        toast.error(t('scans.coreInfra.refused', undefined, { count: res.refused }))
      } else {
        toast.success(t('scans.coreInfra.excluded', undefined, { count: done.length }))
      }
    } catch {
      toast.error(t('scans.coreInfra.failed'))
    } finally {
      setBusy(false)
    }
  }

  const listed = hits.slice(0, LISTED)
  const more = hits.length - listed.length
  return (
    <Alert className="border-warning/30 bg-warning/5" data-testid="core-infra-warning">
      <AlertTriangle className="h-4 w-4 text-warning" aria-hidden />
      <AlertTitle className="text-warning">
        {hits.length === 1
          ? t('scans.coreInfra.titleOne')
          : t('scans.coreInfra.titleMany', undefined, { count: hits.length })}
      </AlertTitle>
      <AlertDescription className="space-y-2">
        <p>{t('scans.coreInfra.why')}</p>
        <ul className="space-y-1">
          {listed.map((h) => (
            <li key={h.address} className="min-w-0 break-words">
              <span className="font-mono">{h.address}</span>
              {': '}
              {describe(h)}
            </li>
          ))}
        </ul>
        {more > 0 && <p>{t('scans.coreInfra.more', undefined, { count: more })}</p>}
        {canExclude ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => void exclude()}
          >
            {t('scans.coreInfra.exclude')}
          </Button>
        ) : (
          <p className="text-xs text-muted-foreground">{t('scans.coreInfra.askAdmin')}</p>
        )}
      </AlertDescription>
    </Alert>
  )
}
