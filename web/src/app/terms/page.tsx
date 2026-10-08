import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { LegalDocument } from '@/features/legal/components/legal-document'
import { termsSections } from '@/features/legal/templates'
import { legalConfig } from '@/lib/legal'

export const dynamic = 'force-dynamic'

export const metadata: Metadata = { title: 'Terms of Service' }

/** The built-in terms template (LEGAL_PAGES_ENABLED=true); 404 otherwise. */
export default function TermsPage() {
  const cfg = legalConfig()
  if (!cfg.templatesEnabled) notFound()
  return (
    <LegalDocument
      title="Terms of Service"
      effectiveDate={cfg.values.effectiveDate}
      sections={termsSections(cfg.values)}
    />
  )
}
