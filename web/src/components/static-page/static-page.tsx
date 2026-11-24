import type { ReactNode } from 'react'
import { ChevronDown } from 'lucide-react'

import { BrandLogoFull } from '@/components/brand-logo'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { SectionTabs, type SectionTab } from '@/features/shared/components/section-tabs'
import { safeInternalHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'

import { PrintButton } from './print-button'

/**
 * The frame of a static reading page (legal documents, licences): one reading
 * column, the title as the page's h1, sections as h2, and the table of
 * contents of those sections beside the text.
 *
 * - `StaticPage` is the whole page for a route outside the app shell: brand
 *   and sign-in on top, the sibling documents as route tabs, then the reading
 *   layout. Controls take the entry scale.
 * - `StaticArticle`, `StaticSection` and `StaticLead` are the reading parts on
 *   their own, for a static page inside the app shell.
 *
 * From 768 px the contents sit beside the text. On a phone the title comes
 * first: the article draws the contents under its header as a folded list
 * with 44 px rows (`StaticArticle` `contents`), and the side list is hidden.
 * A page of one section has no contents (a one-entry list only repeats the
 * heading under it).
 *
 * Text is passed in by the caller (already translated), so the frame renders
 * on the server and in a client page alike. A text published in one language
 * only (the legal documents, in English) passes `textLang`: its sections and
 * their entries in the contents are marked as that language and are not
 * translated; the frame around them is.
 */

/** Fewest sections for which a page lists its contents. */
const MIN_TOC = 2

export interface StaticPageLabels {
  /** The brand link and the button to the sign-in page. */
  signIn: string
  /** Name of the sibling-document navigation. */
  documents: string
  /** Heading and name of the table of contents. */
  onThisPage: string
  print: string
  /** Name of the skip link. */
  skip: string
}

/** Marks a text kept in the language it is published in. */
function textLangProps(textLang?: string) {
  return textLang ? { lang: textLang, translate: 'no' as const } : {}
}

export interface StaticTocItem {
  id: string
  heading: string
}

const ARTICLE_ID = 'static-content'

export function StaticPage({
  labels,
  documents,
  toc,
  textLang,
  children,
}: {
  labels: StaticPageLabels
  /** The sibling documents, as route tabs. */
  documents?: SectionTab[]
  /** The sections of the article; none when empty. */
  toc?: StaticTocItem[]
  /** The language of the text when it is published in one language only. */
  textLang?: string
  /** A `StaticArticle`. */
  children: ReactNode
}) {
  const hasToc = !!toc && toc.length >= MIN_TOC
  return (
    <div
      data-control-scale="entry"
      data-slot="static-page"
      className="flex min-h-svh flex-col items-center gap-5 bg-background px-4 pt-6 pb-10 text-foreground print:p-0"
    >
      <a
        href={`#${ARTICLE_ID}`}
        className="sr-only rounded-md bg-card px-3 py-2 text-body focus:not-sr-only focus:absolute focus:start-4 focus:top-4 focus:z-10 focus:outline-2 focus:outline-ring"
      >
        {labels.skip}
      </a>
      <header className="flex w-full max-w-270 flex-wrap items-center justify-between gap-2 print:hidden">
        <Link href="/login" aria-label={labels.signIn} className="inline-flex rounded-md">
          <BrandLogoFull className="h-7 w-auto" />
        </Link>
        <Button asChild variant="outline">
          <Link href="/login">{labels.signIn}</Link>
        </Button>
      </header>
      {documents && documents.length > 0 && (
        <div className="w-full max-w-270 print:hidden">
          <SectionTabs tabs={documents} label={labels.documents} />
        </div>
      )}
      <div className="flex w-full max-w-270 flex-wrap items-start gap-x-8 gap-y-5">
        {hasToc && (
          <nav
            aria-label={labels.onThisPage}
            data-slot="static-toc"
            className="hidden min-w-0 flex-[1_1_13.75rem] flex-col gap-1 text-dense md:sticky md:top-6 md:flex md:max-w-65 print:hidden"
          >
            <span className="text-cap text-muted-foreground">{labels.onThisPage}</span>
            <ol className="flex flex-col" {...textLangProps(textLang)}>
              {toc.map((s) => (
                <li key={s.id}>
                  <a
                    href={safeInternalHref(`#${s.id}`)}
                    className="block rounded-sm py-1 text-signal-text underline-offset-3 hover:underline focus-visible:underline"
                  >
                    {s.heading}
                  </a>
                </li>
              ))}
            </ol>
            <PrintButton className="mt-3 self-start">{labels.print}</PrintButton>
          </nav>
        )}
        <main id={ARTICLE_ID} tabIndex={-1} className="min-w-0 flex-[999_1_30rem] outline-none">
          {children}
        </main>
      </div>
    </div>
  )
}

/**
 * The reading column: the header (the title, the lines under it and, on a
 * phone, the folded contents), the sections, a footer.
 */
export function StaticArticle({
  title,
  meta,
  note,
  contents,
  footer,
  textLang,
  className,
  children,
}: {
  title: string
  /** One muted line under the title, e.g. the effective date. */
  meta?: ReactNode
  /** A second muted line under the title (e.g. the language the text is published in). */
  note?: ReactNode
  /** The phone's contents under the title: the same list `StaticPage` shows beside the text. */
  contents?: { toc: StaticTocItem[]; label: string; print: string }
  footer?: ReactNode
  /** The language of the sections when the text is published in one language only. */
  textLang?: string
  className?: string
  children: ReactNode
}) {
  return (
    <article data-slot="static-article" className={cn('flex max-w-180 flex-col gap-5', className)}>
      {/* The page's header: the lines under the title and the phone's contents
          belong to it, the way a page header's description does. */}
      <header data-slot="page-header">
        <h1 className="text-page">{title}</h1>
        {meta && <p className="mt-1 text-dense text-muted-foreground">{meta}</p>}
        {note && <p className="mt-1 text-dense text-muted-foreground">{note}</p>}
        {contents && contents.toc.length >= MIN_TOC && (
          <StaticContents {...contents} textLang={textLang} />
        )}
      </header>
      <div data-slot="static-sections" className="flex flex-col gap-5" {...textLangProps(textLang)}>
        {children}
      </div>
      {footer && (
        <footer className="flex flex-col gap-1.5 border-t pt-3 text-cap text-muted-foreground">
          {footer}
        </footer>
      )}
    </article>
  )
}

/** The contents on a phone: folded under the title, one 44 px row per section. */
function StaticContents({
  toc,
  label,
  print,
  textLang,
}: {
  toc: StaticTocItem[]
  label: string
  print: string
  textLang?: string
}) {
  return (
    <details
      data-slot="static-toc-phone"
      className="group mt-3 rounded-md border md:hidden print:hidden"
    >
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-2 px-3 text-body font-medium [&::-webkit-details-marker]:hidden">
        {label}
        <ChevronDown
          className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180 motion-reduce:transition-none"
          aria-hidden
        />
      </summary>
      <nav aria-label={label} className="border-t">
        <ol className="flex flex-col" {...textLangProps(textLang)}>
          {toc.map((s) => (
            <li key={s.id}>
              <a
                href={safeInternalHref(`#${s.id}`)}
                className="flex min-h-11 items-center px-3 text-body text-signal-text underline-offset-3 hover:underline focus-visible:underline"
              >
                {s.heading}
              </a>
            </li>
          ))}
        </ol>
        <div className="border-t p-3">
          <PrintButton>{print}</PrintButton>
        </div>
      </nav>
    </details>
  )
}

/** One section of the article; `id` is the anchor the table of contents links to. */
export function StaticSection({
  id,
  heading,
  children,
}: {
  id: string
  heading: string
  children: ReactNode
}) {
  return (
    <section id={id} aria-labelledby={`${id}-h`} className="scroll-mt-6">
      <h2 id={`${id}-h`} className="text-section">
        {heading}
      </h2>
      <div data-slot="static-prose" className="mt-2 space-y-2 text-body/6 text-muted-foreground">
        {children}
      </div>
    </section>
  )
}

/** The opening paragraph of a static page inside the app shell. */
export function StaticLead({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <p data-slot="static-lead" className={cn('max-w-180 text-section font-normal', className)}>
      {children}
    </p>
  )
}

/** Anchor ids for a list of section headings: `<prefix>-1`, `<prefix>-2`, ... */
export function staticToc(headings: string[], prefix = 'section'): StaticTocItem[] {
  return headings.map((heading, i) => ({ id: `${prefix}-${i + 1}`, heading }))
}
