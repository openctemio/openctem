import type { Metadata } from 'next'
import { headers } from 'next/headers'

import './console.css'
import { Providers } from '@/app/providers'
import { getDirFromLocale, defaultLocale, isSupportedLocale } from '@/lib/i18n'
import { NavProgressBar } from '@/components/layout/nav-progress'
import { brandSettings } from '@/lib/brand-settings'

/** The page title comes from the instance brand, like the tenant app's. */
export async function generateMetadata(): Promise<Metadata> {
  const brand = await brandSettings()
  return { title: brand.name, robots: { index: false, follow: false } }
}

/**
 * Root layout of the platform console app: the shared providers (theme,
 * i18n, brand, SWR) and nothing of the tenant shell.
 */
export default async function ConsoleRootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  const h = await headers()
  const requested = h.get('x-locale')
  const locale = isSupportedLocale(requested) ? requested : defaultLocale
  const dir = getDirFromLocale(locale)
  // Per-request CSP nonce from src/proxy.ts, for the theme's inline script.
  const nonce = h.get('x-nonce') ?? undefined
  const brand = await brandSettings()
  const brandStyle = brand.primaryColor
    ? ({ '--primary': brand.primaryColor } as React.CSSProperties)
    : undefined
  return (
    <html lang={locale} dir={dir} style={brandStyle} suppressHydrationWarning>
      <body className="antialiased" suppressHydrationWarning>
        <Providers dir={dir} locale={locale} nonce={nonce} brand={brand}>
          {children}
        </Providers>
        <NavProgressBar />
      </body>
    </html>
  )
}
