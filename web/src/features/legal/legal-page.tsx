import { notFound } from 'next/navigation'
import { LEGAL_DOCS, legalConfig, type LegalDoc } from '@/lib/legal'
import { legalSettings } from '@/lib/legal-settings'
import { LegalDocument } from './components/legal-document'
import { legalSections } from './templates'

/** One built-in legal page; 404 unless the admin console turned the legal pages on. */
export async function LegalPage({ doc }: { doc: LegalDoc }) {
  const cfg = legalConfig(await legalSettings())
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
