import type { ReactNode } from 'react'
import Link from 'next/link'
import { LogoFull } from '@/assets/logo'

export interface LegalSection {
  heading: string
  body: ReactNode
}

/**
 * A plain, readable legal page (the built-in /terms and /privacy templates).
 * Server component: no client JavaScript.
 */
export function LegalDocument({
  title,
  effectiveDate,
  sections,
}: {
  title: string
  effectiveDate: string
  sections: LegalSection[]
}) {
  return (
    <div className="min-h-svh bg-background px-4 py-10 text-foreground">
      <article className="mx-auto max-w-2xl space-y-6">
        <Link href="/login" aria-label="Sign in" className="inline-block">
          <LogoFull className="h-10 w-auto" />
        </Link>
        <header className="space-y-1">
          <h1 className="text-3xl font-semibold tracking-tight">{title}</h1>
          <p className="text-sm text-muted-foreground">Effective {effectiveDate}</p>
        </header>
        {sections.map((s) => (
          <section key={s.heading} className="space-y-2">
            <h2 className="text-lg font-semibold">{s.heading}</h2>
            <div className="space-y-2 text-sm leading-6 text-muted-foreground">{s.body}</div>
          </section>
        ))}
      </article>
    </div>
  )
}
