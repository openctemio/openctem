'use client'

import { AlertTriangle } from 'lucide-react'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { DetailCallout } from '@/features/shared'
import { toDisplayText } from '@/lib/untrusted-text'

import { impactsOf, type SensorImpact } from '../lib/impact'

interface ImpactListProps {
  impacts: SensorImpact[]
  /** True before the default pool is saved on: the sensors "would" stop. */
  pending: boolean
}

/**
 * The sensors the organization default pool holds back, grouped by why:
 * no scan jobs (no proxy support reported) and no validation jobs (the
 * sensor's validation probes do not go through a proxy). Each sensor links
 * to its page, where its network path can be set to Direct or upgraded.
 * Nothing renders when no sensor is affected.
 */
export function ImpactList({ impacts, pending }: ImpactListProps) {
  const { t } = useTranslation()
  if (impacts.length === 0) return null
  const groups = [
    {
      key: 'unsupported' as const,
      title: t('proxyPools.impact.unsupportedTitle', 'No scan jobs: no proxy support reported'),
      fix: t(
        'proxyPools.impact.unsupportedFix',
        'Upgrade the sensor and run it with network confinement, or set its network path to Direct on its page.'
      ),
    },
    {
      key: 'validate-waits' as const,
      title: t('proxyPools.impact.validateTitle', 'No validation jobs: probes would leave direct'),
      fix: t(
        'proxyPools.impact.validateFix',
        'Scans run through the proxies. Validation jobs wait until the sensor sends its probes through them too.'
      ),
    },
  ]
  return (
    <DetailCallout
      tone="warning"
      icon={AlertTriangle}
      label={t('proxyPools.impact.label', 'Sensors affected by the proxies')}
      title={t(
        `proxyPools.impact.${pending ? 'titlePending' : 'title'}.${impacts.length === 1 ? 'one' : 'other'}`,
        pending
          ? impacts.length === 1
            ? 'Turning proxies on holds back {count} sensor'
            : 'Turning proxies on holds back {count} sensors'
          : impacts.length === 1
            ? '{count} sensor cannot fully use the proxies'
            : '{count} sensors cannot fully use the proxies',
        { count: impacts.length }
      )}
    >
      <div className="space-y-3" data-testid="proxy-impact-list">
        {groups.map((g) => {
          const list = impactsOf(impacts, g.key)
          if (list.length === 0) return null
          return (
            <div key={g.key} data-testid={`proxy-impact-${g.key}`} className="space-y-1">
              <p className="font-medium text-foreground">{g.title}</p>
              <ul className="flex flex-wrap gap-x-4 gap-y-1">
                {list.map((i) => (
                  <li key={i.id}>
                    <Link
                      href="/sensors"
                      className="text-primary underline-offset-2 hover:underline"
                    >
                      {toDisplayText(i.name)}
                    </Link>
                  </li>
                ))}
              </ul>
              <p>{g.fix}</p>
            </div>
          )
        })}
      </div>
    </DetailCallout>
  )
}
