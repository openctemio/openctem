/** The rules that put a name in the review queue, in words (reason filter). */
export const REVIEW_REASON_LABEL: Record<string, string> = {
  fqdn_under_verified_root: 'Under a verified domain',
  fqdn_under_asserted_root: 'Under a domain you listed, not verified',
  tenant_scanned: 'A target your organization scanned',
  tenant_scan_discovered: 'Found by one of your scans',
  matches_scope_target: 'Covered by a scope entry',
}

export function reviewReasonLabel(reason: string): string {
  return REVIEW_REASON_LABEL[reason] ?? reason.replace(/_/g, ' ')
}
