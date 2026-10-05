'use client'

import { useEffect } from 'react'
import { ThemeProvider } from '@/context/theme-provider'
import { DirectionProvider } from '@/context/direction-provider'
import { I18nProvider } from '@/context/i18n-provider'
import { SWRProvider } from '@/lib/swr-config'
import { Toaster } from 'sonner'
import { migrateSensorBrowserStorage } from '@/lib/sensor-storage-migration'
import { config as zodConfig } from 'zod/v4/core'

// The CSP has no 'unsafe-eval' (src/lib/middleware/csp.ts). Zod probes for
// `new Function` on its first parse to pick its JIT path; the probe is caught,
// but the browser still reports a script-src violation for it. Jitless skips
// the probe (and the JIT, which the policy would block anyway).
//
// `config` from zod's core, not `z.config` from 'zod': the global config is
// shared (globalThis.__zod_globalConfig), and importing `z` here put all of
// zod (~90 KB gzipped) into every page's first-load JS. Pages with forms load
// it in their own chunks.
zodConfig({ jitless: true })

// Browser state written before the sensor rename (RFC-023: cached permissions,
// app keys) is migrated once, when this module first loads in the browser:
// before any component renders, so nothing reads the old spelling. Idempotent
// and exception-safe; see src/lib/sensor-storage-migration.ts.
if (typeof window !== 'undefined') {
  migrateSensorBrowserStorage()
}

export function Providers({
  children,
  dir,
  locale,
  nonce,
}: {
  children: React.ReactNode
  dir: 'ltr' | 'rtl'
  locale: string
  /** CSP nonce for the theme script (see src/proxy.ts). */
  nonce?: string
}) {
  // Initialize Web Vitals reporting (lazy load to avoid bundling optional dependencies)
  useEffect(() => {
    // Only load web-vitals module if Sentry DSN is configured
    if (process.env.NEXT_PUBLIC_SENTRY_DSN) {
      import('@/lib/web-vitals')
        .then((module) => module.initWebVitals())
        .catch(() => {
          // Module not available, skip silently
        })
    }
  }, [])

  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      disableTransitionOnChange
      nonce={nonce}
    >
      <SWRProvider>
        <DirectionProvider dir={dir}>
          <I18nProvider locale={locale}>{children}</I18nProvider>
          <Toaster
            richColors
            position="bottom-right"
            expand={true}
            visibleToasts={3}
            closeButton
            toastOptions={{
              style: {
                // Ensure action buttons are always visible
                minHeight: '48px',
              },
            }}
          />
        </DirectionProvider>
      </SWRProvider>
    </ThemeProvider>
  )
}
