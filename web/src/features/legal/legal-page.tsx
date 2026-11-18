import { notFound } from 'next/navigation'
import { LEGAL_DOCS, legalConfig, type LegalDoc } from '@/lib/legal'
import { legalSettings } from '@/lib/legal-settings'
import { LegalDocument } from './components/legal-document'
import { LegalMail, LegalWeb, withNodes } from './components/legal-links'
import { legalFrameLabels, legalLanguageNote, legalTranslator } from './legal-labels'
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
      title={meta.title}
      effective={t('legal.frame.effective', 'Effective {date}', {
        date: cfg.values.effectiveDate,
      })}
      sections={legalSections(doc, cfg.values)}
      contactLine={withNodes(
        // Each mark is asked as itself, then replaced by its link.
        t('legal.frame.contact', 'Contact: {contact}. Documentation: {docs}.', {
          contact: '{contact}',
          docs: '{docs}',
        }),
        {
          contact: <LegalMail to={cfg.values.contactEmail} />,
          docs: <LegalWeb url={cfg.values.docsUrl} />,
        }
      )}
      languageNote={await legalLanguageNote(t)}
      labels={legalFrameLabels(t)}
    />
  )
}

export function legalTitle(doc: LegalDoc): string {
  return LEGAL_DOCS.find((d) => d.doc === doc)?.title ?? ''
}
