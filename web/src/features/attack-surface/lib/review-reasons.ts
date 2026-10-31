/** A translator as `useTranslation()` returns it. */
type T = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** The rules that put a name in the review queue, in words (reason filter). */
export function reviewReasonLabel(t: T, reason: string): string {
  switch (reason) {
    case 'fqdn_under_verified_root':
      return t('easmReview.reason.verifiedRoot', 'Under a verified domain')
    case 'fqdn_under_asserted_root':
      return t('easmReview.reason.assertedRoot', 'Under a domain you listed, not verified')
    case 'tenant_scanned':
      return t('easmReview.reason.scanned', 'A target your organization scanned')
    case 'tenant_scan_discovered':
      return t('easmReview.reason.scanDiscovered', 'Found by one of your scans')
    case 'certificate_san':
      return t('easmReview.reason.certificateSan', 'Named in a TLS certificate')
    case 'matches_scope_target':
      return t('easmReview.reason.matchesScope', 'Covered by a scope entry')
    default:
      return reason.replace(/_/g, ' ')
  }
}
