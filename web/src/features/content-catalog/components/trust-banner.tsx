'use client'

import { AlertTriangle, Info } from 'lucide-react'
import type { ContentTrust } from '@/lib/api/generated'
import { DetailCallout } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { trustBanner } from '../lib'

/** Whether the catalog this organization browses is current and trusted. */
export function TrustBanner({ trust }: { trust: ContentTrust | undefined }) {
  const { t } = useTranslation()
  const banner = trustBanner(trust)
  if (!banner) return null
  if (banner.tone === 'info') {
    return (
      <DetailCallout
        tone="info"
        icon={Info}
        title={
          banner.reason === 'no-roots'
            ? t('contentCatalog.trust.noRootsTitle', 'The catalog is not set up')
            : t('contentCatalog.trust.noImportTitle', 'No catalog has been imported yet')
        }
      >
        {banner.reason === 'no-roots'
          ? t(
              'contentCatalog.trust.noRoots',
              'This instance has no catalog trust root, so it cannot import packages. Ask the platform administrator.'
            )
          : t(
              'contentCatalog.trust.noImport',
              'The platform administrator imports a signed catalog bundle; its packages then appear here.'
            )}
      </DetailCallout>
    )
  }
  return (
    <DetailCallout
      tone="warning"
      icon={AlertTriangle}
      title={t('contentCatalog.trust.staleTitle', 'The catalog is out of date')}
    >
      <ul className="list-disc space-y-0.5 ps-4">
        {banner.reasons.includes('index-expired') && (
          <li>
            {t(
              'contentCatalog.trust.indexExpired',
              'The signed index has expired: new versions stop arriving until the next import.'
            )}
          </li>
        )}
        {banner.reasons.includes('revocations-stale') && (
          <li>
            {t(
              'contentCatalog.trust.revocationsStale',
              'The revocation list is past its expiry: sensors and tool adapters cannot be installed until the next import.'
            )}
          </li>
        )}
      </ul>
    </DetailCallout>
  )
}
