import { notFound } from 'next/navigation'
import { LEGAL_DOCS, legalConfig, type LegalDoc } from '@/lib/legal'
import { LegalDocument } from './components/legal-document'
import { legalSections } from './templates'

/** One built-in legal page; 404 unless LEGAL_PAGES_ENABLED=true. */
export function LegalPage({ doc }: { doc: LegalDoc }) {
  const cfg = legalConfig()
  if (!cfg.templatesEnabled) notFound()
  const meta = LEGAL_DOCS.find((d) => d.doc === doc)
  if (!meta) notFound()
  return (
    <LegalDocument
      title={meta.title}
      effectiveDate={cfg.values.effectiveDate}
      sections={legalSections(doc, cfg.values)}
      contact={cfg.values.contactEmail}
      docsUrl={cfg.values.docsUrl}
    />
  )
}

export function legalTitle(doc: LegalDoc): string {
  return LEGAL_DOCS.find((d) => d.doc === doc)?.title ?? ''
}
