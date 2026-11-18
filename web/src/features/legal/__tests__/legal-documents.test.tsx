import { describe, it, expect } from 'vitest'
import { render, screen, within } from '@testing-library/react'

import { LEGAL_DOCS, legalConfig } from '@/lib/legal'
import { LegalDocument } from '../components/legal-document'
import { legalSections } from '../templates'

const labels = {
  signIn: 'Sign in',
  documents: 'Legal documents',
  onThisPage: 'On this page',
  print: 'Print or save as PDF',
  skip: 'Skip to the document',
}

function renderDoc(doc: (typeof LEGAL_DOCS)[number], languageNote?: string) {
  const cfg = legalConfig({})
  return render(
    <LegalDocument
      title={doc.title}
      effective="Effective 1 January 2026"
      sections={legalSections(doc.doc, cfg.values)}
      contactLine="Contact: privacy@example.com."
      languageNote={languageNote}
      labels={labels}
    />
  )
}

describe('legal documents', () => {
  it.each(LEGAL_DOCS.map((d) => [d.doc, d] as const))(
    '%s names its cross-references by the document title, as links',
    (_, doc) => {
      const { container } = renderDoc(doc)
      const main = container.querySelector('main') as HTMLElement
      // Never a raw path in parentheses such as "(/dpa)".
      expect(main.textContent).not.toMatch(/\(\/[a-z.-]+/)
      for (const other of LEGAL_DOCS) {
        for (const link of within(main).queryAllByRole('link', { name: other.title })) {
          expect(link).toHaveAttribute('href', other.path)
        }
      }
    }
  )

  it('links the Privacy Policy to the addendum and the subprocessors', () => {
    const privacy = LEGAL_DOCS.find((d) => d.doc === 'privacy')!
    const { container } = renderDoc(privacy)
    const main = container.querySelector('main') as HTMLElement
    expect(within(main).getByRole('link', { name: 'Data Processing Addendum' })).toHaveAttribute(
      'href',
      '/dpa'
    )
    expect(within(main).getByRole('link', { name: 'Subprocessors' })).toHaveAttribute(
      'href',
      '/subprocessors'
    )
  })

  it('puts the phone contents under the title, folded, with 44 px rows', () => {
    const terms = LEGAL_DOCS.find((d) => d.doc === 'terms')!
    const { container } = renderDoc(terms)
    const article = container.querySelector('[data-slot="static-article"]') as HTMLElement
    const phone = article.querySelector('[data-slot="static-toc-phone"]') as HTMLElement
    expect(phone.tagName).toBe('DETAILS')
    expect(phone.hasAttribute('open')).toBe(false)
    expect(phone.className).toContain('md:hidden')
    // After the title's header, before the first section.
    const header = article.querySelector('header') as HTMLElement
    expect(header.compareDocumentPosition(phone) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    const firstSection = article.querySelector('section') as HTMLElement
    expect(phone.compareDocumentPosition(firstSection) & Node.DOCUMENT_POSITION_FOLLOWING).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING
    )
    for (const row of phone.querySelectorAll('ol a')) expect(row.className).toContain('min-h-11')
    // The side list is for 768 px and up only.
    const side = container.querySelector('[data-slot="static-toc"]') as HTMLElement
    expect(side.className).toMatch(/(^| )hidden( |$)/)
    expect(side.className).toContain('md:flex')
  })

  it('says the text is in English when a language note is given', () => {
    const terms = LEGAL_DOCS.find((d) => d.doc === 'terms')!
    renderDoc(terms, 'Văn bản này được công bố bằng tiếng Anh.')
    expect(screen.getByText('Văn bản này được công bố bằng tiếng Anh.')).toBeInTheDocument()
  })
})
