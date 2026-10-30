'use client'

import { useAsset } from './use-assets'
import { useRelatedAssets } from './use-related-assets'
import { recordedCertificate } from '../lib/service-facts'
import type { Asset } from '../types/asset.types'

/**
 * The certificate asset a service serves (its `serves_certificate` edge), for
 * the drawer's TLS facts. The probe records the certificate as its own asset
 * and links it; the service holds only the fingerprint. Nothing is fetched for
 * an asset that already carries its certificate or is not a service.
 * Both reads are the caller's own (relationships module, assets:read), so a
 * certificate outside the caller's data scope never arrives.
 */
export function useServedCertificate(asset: Asset | null, enabled: boolean): Asset | null {
  const wanted = enabled && !!asset && !recordedCertificate(asset)
  const related = useRelatedAssets(wanted ? asset!.id : null, {
    type: 'serves_certificate',
    direction: 'outgoing',
    limit: 1,
  })
  const ref = related.groups[0]?.items[0]?.asset
  const certId = wanted && ref?.type === 'certificate' ? ref.id : null
  return useAsset(certId).asset
}
