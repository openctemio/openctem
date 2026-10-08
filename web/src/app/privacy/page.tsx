import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { LegalDocument } from '@/features/legal/components/legal-document'
import { privacySections } from '@/features/legal/templates'
import { legalConfig } from '@/lib/legal'

export const dynamic = 'force-dynamic'

export const metadata: Metadata = { title: 'Privacy Policy' }

/** The built-in privacy template (LEGAL_PAGES_ENABLED=true); 404 otherwise. */
export default function PrivacyPage() {
  const cfg = legalConfig()
  if (!cfg.templatesEnabled) notFound()
  return (
    <LegalDocument
      title="Privacy Policy"
      effectiveDate={cfg.values.effectiveDate}
      sections={privacySections(cfg.values)}
    />
  )
}
