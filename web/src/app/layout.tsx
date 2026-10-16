import type { Metadata } from 'next'
// import { Geist, Geist_Mono } from "next/font/google";
import { headers } from 'next/headers'
import './globals.css'
import { Providers } from './providers'
import { getDirFromLocale, defaultLocale, isSupportedLocale } from '@/lib/i18n'
import { NavProgressBar } from '@/components/layout/nav-progress'
import { brandSettings } from '@/lib/brand-settings'

const appDescription =
  process.env.NEXT_PUBLIC_APP_DESCRIPTION || 'Continuous Threat Exposure Management Platform'

/**
 * The page title comes from the instance brand (src/lib/brand.ts); the icon
 * routes (icon.tsx, apple-icon.tsx) serve the brand's favicon when it has one.
 */
export async function generateMetadata(): Promise<Metadata> {
  const brand = await brandSettings()
  return {
    title: brand.name,
    description: `${brand.name} - ${appDescription}`,
  }
}

// const geistSans = Geist({
//   variable: "--font-geist-sans",
//   subsets: ["latin"],
// });

// const geistMono = Geist_Mono({
//   variable: "--font-geist-mono",
//   subsets: ["latin"],
// });

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  const h = await headers()
  // Set by src/proxy.ts (cookie, then Accept-Language). Checked again here:
  // a request the proxy does not run on keeps whatever header it was sent.
  const requested = h.get('x-locale')
  const locale = isSupportedLocale(requested) ? requested : defaultLocale
  const dir = getDirFromLocale(locale)
  // Per-request CSP nonce from src/proxy.ts, for the inline script next-themes
  // writes (the policy has no 'unsafe-inline').
  const nonce = h.get('x-nonce') ?? undefined
  const brand = await brandSettings()
  // The brand color replaces the theme's primary color (validated #rrggbb).
  const brandStyle = brand.primaryColor
    ? ({ '--primary': brand.primaryColor } as React.CSSProperties)
    : undefined
  return (
    <html lang={locale} dir={dir} style={brandStyle} suppressHydrationWarning>
      <body
        // className={`${geistSans.variable} ${geistMono.variable} antialiased`}
        className="antialiased"
        suppressHydrationWarning
      >
        <Providers dir={dir} locale={locale} nonce={nonce} brand={brand}>
          {children}
        </Providers>
        {/* Page-wide navigation progress bar, shown while a nav link waits for
            its route (NavPendingHint). */}
        <NavProgressBar />
      </body>
    </html>
  )
}
