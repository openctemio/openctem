import { notFound } from 'next/navigation'
import { LEGAL_DOCS, legalConfig, type LegalDoc } from '@/lib/legal'
import { legalSettings } from '@/lib/legal-settings'
import { LegalDocument } from './components/legal-document'
import { legalFrameLabels, legalLanguageNote, legalTranslator, type LegalT } from './legal-labels'
import { legalSections } from './templates'

/** One built-in legal page; 404 unless the admin console turned the legal pages on. */
export async function LegalPage({ doc }: { doc: LegalDoc }) {
  const cfg = legalConfig(await legalSettings())
  if (!cfg.templatesEnabled) notFound()
  const meta = LEGAL_DOCS.find((d) => d.doc === doc)
  if (!meta) notFound()
  const t = await legalTranslator()
  return (
    <LegalDocument
      title={legalDocTitle(t, doc)}
      documents={LEGAL_DOCS.map((d) => ({ label: legalDocTitle(t, d.doc), href: d.path }))}
      effective={t('legal.frame.effective', 'Effective {date}', {
        date: cfg.values.effectiveDate,
      })}
      sections={legalSections(doc, cfg.values)}
      languageNote={await legalLanguageNote(t)}
      labels={legalFrameLabels(t)}
    />
  )
}

/**
 * The name of a document in the reader's language (the page title, its tab).
 * The text itself, and the links to the other documents inside it, stay in
 * the language it is published in (English).
 */
function legalDocTitle(t: LegalT, doc: LegalDoc): string {
  return t(`legal.doc.${doc}`, LEGAL_DOCS.find((d) => d.doc === doc)?.title ?? '')
}

/** The browser tab title of a legal page, in the reader's language. */
export async function legalTitle(doc: LegalDoc): Promise<string> {
  return legalDocTitle(await legalTranslator(), doc)
}
