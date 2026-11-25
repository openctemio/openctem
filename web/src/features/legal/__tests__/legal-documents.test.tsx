import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { render, screen, within } from '@testing-library/react'

import { LEGAL_DOCS, legalConfig } from '@/lib/legal'
import { LegalDocument } from '../components/legal-document'
import { LegalMail, LegalWeb, withNodes } from '../components/legal-links'
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
        // A section of the same name in the contents is an in-page anchor, not a reference.
        for (const link of within(main).queryAllByRole('link', { name: other.title })) {
          if (link.getAttribute('href')?.startsWith('#')) continue
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

  it.each(LEGAL_DOCS.map((d) => [d.doc, d] as const))(
    '%s prints no site path as text and links every e-mail address',
    (_, doc) => {
      const { container } = renderDoc(doc)
      const main = container.querySelector('main') as HTMLElement
      for (const node of main.querySelectorAll('section p, section td, section li')) {
        // Text outside links: no "/subprocessors" style path.
        const own = Array.from(node.childNodes)
          .filter((n) => n.nodeType === Node.TEXT_NODE)
          .map((n) => n.textContent)
          .join('')
        expect(own).not.toMatch(/(^|\s)\/[a-z-]+/)
        expect(own).not.toMatch(/[^\s@]+@[^\s@]+\.[a-z]{2,}/i)
      }
      for (const link of main.querySelectorAll('a[href^="mailto:"]')) {
        expect(link.getAttribute('href')).toBe(`mailto:${link.textContent}`)
      }
    }
  )

  it('links the contact and security addresses as mailto', () => {
    const terms = LEGAL_DOCS.find((d) => d.doc === 'terms')!
    const { container } = renderDoc(terms)
    const values = legalConfig({}).values
    const main = container.querySelector('main') as HTMLElement
    expect(within(main).getAllByRole('link', { name: values.securityEmail })[0]).toHaveAttribute(
      'href',
      `mailto:${values.securityEmail}`
    )
    expect(within(main).getAllByRole('link', { name: values.docsUrl })[0]).toHaveAttribute(
      'href',
      new URL(values.docsUrl).href
    )
  })

  it('lists no contents for a page of one section', () => {
    const subprocessors = LEGAL_DOCS.find((d) => d.doc === 'subprocessors')!
    const cfg = legalConfig({})
    expect(legalSections('subprocessors', cfg.values)).toHaveLength(1)
    const { container } = renderDoc(subprocessors)
    expect(container.querySelector('[data-slot="static-toc"]')).toBeNull()
    expect(container.querySelector('[data-slot="static-toc-phone"]')).toBeNull()
    // A page of several sections keeps both lists.
    const terms = LEGAL_DOCS.find((d) => d.doc === 'terms')!
    const other = renderDoc(terms).container
    expect(other.querySelector('[data-slot="static-toc"]')).not.toBeNull()
    expect(other.querySelector('[data-slot="static-toc-phone"]')).not.toBeNull()
  })

  it('puts links into a translated line in the translator order', () => {
    const line = withNodes('Liên hệ: {contact}. Tài liệu: {docs}.', {
      contact: <LegalMail to="privacy@example.com" />,
      docs: <LegalWeb url="https://docs.example.com" />,
    })
    render(<p data-testid="line">{line}</p>)
    const p = screen.getByTestId('line')
    expect(p.textContent).toBe('Liên hệ: privacy@example.com. Tài liệu: https://docs.example.com.')
    expect(within(p).getByRole('link', { name: 'privacy@example.com' })).toHaveAttribute(
      'href',
      'mailto:privacy@example.com'
    )
    expect(within(p).getByRole('link', { name: 'https://docs.example.com' })).toHaveAttribute(
      'href',
      'https://docs.example.com/'
    )
  })

  it('keeps an address that is not a safe link as text', () => {
    render(
      <p data-testid="bad">
        <LegalWeb url="javascript:alert(1)" />
      </p>
    )
    expect(within(screen.getByTestId('bad')).queryByRole('link')).toBeNull()
  })

  it('says the text is in English when a language note is given', () => {
    const terms = LEGAL_DOCS.find((d) => d.doc === 'terms')!
    renderDoc(terms, 'Văn bản này được công bố bằng tiếng Anh.')
    expect(screen.getByText('Văn bản này được công bố bằng tiếng Anh.')).toBeInTheDocument()
  })
})

describe('legal pages render on the server', () => {
  // A value imported from a 'use client' module reaches a server component as
  // a client reference, so a link drawn there would lose its classes.
  it.each(['templates.tsx', 'components/legal-links.tsx'])(
    '%s takes the link classes from the plain module',
    (file) => {
      const src = readFileSync(path.resolve(__dirname, '..', file), 'utf8')
      expect(src).not.toMatch(/TEXT_LINK_CLASS[^\n]*from '@\/components\/ui\/text-link'/)
      if (src.includes('TEXT_LINK_CLASS'))
        expect(src).toContain("from '@/components/ui/text-link-class'")
    }
  )
})
