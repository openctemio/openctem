import type { ReactNode } from 'react'

import {
  StaticArticle,
  StaticPage,
  StaticSection,
  staticToc,
  type StaticPageLabels,
} from '@/components/static-page'
import type { SectionTab } from '@/features/shared/components/section-tabs'
import { LEGAL_DOCS } from '@/lib/legal'

export interface LegalSection {
  heading: string
  body: ReactNode
}

/**
 * A legal page (the built-in templates) in the static reading frame: the five
 * documents as route tabs, the table of contents of this one, its sections.
 * The document text is rendered on the server. The frame (title, tabs, labels)
 * is in the reader's language; the text is published in English, so its
 * sections are marked as English and are not translated.
 */
export function LegalDocument({
  title,
  documents = LEGAL_DOCS.map((d) => ({ label: d.title, href: d.path })),
  effective,
  sections,
  languageNote,
  labels,
}: {
  /** The document's name, translated. */
  title: string
  /** The five documents as route tabs, their names translated. */
  documents?: SectionTab[]
  /** "Effective <date>", translated. */
  effective: string
  /** Each document names its own contacts in its text, so the frame adds no contact footer. */
  sections: LegalSection[]
  /** Shown under the date when the reader's language is not the text's (English). */
  languageNote?: string
  labels: StaticPageLabels
}) {
  const toc = staticToc(
    sections.map((s) => s.heading),
    'legal'
  )
  return (
    <StaticPage labels={labels} documents={documents} toc={toc} textLang="en">
      <StaticArticle
        title={title}
        meta={effective}
        note={languageNote}
        contents={{ toc, label: labels.onThisPage, print: labels.print }}
        textLang="en"
      >
        {sections.map((s, i) => (
          <StaticSection key={s.heading} id={toc[i].id} heading={s.heading}>
            {s.body}
          </StaticSection>
        ))}
      </StaticArticle>
    </StaticPage>
  )
}
