import type { ReactNode } from 'react'

import {
  StaticArticle,
  StaticPage,
  StaticSection,
  staticToc,
  type StaticPageLabels,
} from '@/components/static-page'
import { LEGAL_DOCS } from '@/lib/legal'

export interface LegalSection {
  heading: string
  body: ReactNode
}

/**
 * A legal page (the built-in templates) in the static reading frame: the five
 * documents as route tabs, the table of contents of this one, its sections.
 * The document text is rendered on the server.
 */
export function LegalDocument({
  title,
  effective,
  sections,
  contactLine,
  labels,
}: {
  title: string
  /** "Effective <date>", translated. */
  effective: string
  sections: LegalSection[]
  /** "Contact: ... Documentation: ...", translated. */
  contactLine: string
  labels: StaticPageLabels
}) {
  const toc = staticToc(
    sections.map((s) => s.heading),
    'legal'
  )
  return (
    <StaticPage
      labels={labels}
      documents={LEGAL_DOCS.map((d) => ({ label: d.title, href: d.path }))}
      toc={toc}
    >
      <StaticArticle title={title} meta={effective} footer={<p>{contactLine}</p>}>
        {sections.map((s, i) => (
          <StaticSection key={s.heading} id={toc[i].id} heading={s.heading}>
            {s.body}
          </StaticSection>
        ))}
      </StaticArticle>
    </StaticPage>
  )
}
