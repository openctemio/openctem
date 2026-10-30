'use client'

import { Suspense, createContext, use, useContext, useMemo, useCallback } from 'react'
import {
  getDictionary,
  loadDictionary,
  loadedDictionary,
  translate,
  defaultLocale,
  type TranslateVars,
} from '@/lib/i18n'
import { useBrand } from '@/context/brand-provider'
import type { Brand } from '@/lib/brand'

type TranslateFn = (key: string, fallback?: string, vars?: TranslateVars) => string

type I18nContextValue = {
  locale: string
  t: TranslateFn
}

const I18nContext = createContext<I18nContextValue | null>(null)

/**
 * The brand variables every string can use: `{product}` (the brand name) and
 * `{productShort}`. A caller's own vars win.
 */
export function brandVars(brand: Brand, vars?: TranslateVars): TranslateVars {
  return { product: brand.name, productShort: brand.shortName, ...vars }
}

// Start downloading the page's catalog as soon as this module runs, before
// React starts hydrating: the server rendered <html lang> with the locale.
if (typeof document !== 'undefined') {
  void loadDictionary(document.documentElement.lang).catch(() => {
    // I18nProvider retries and reports through the error boundary.
  })
}

/**
 * Provides the active locale + a `t()` translator to the client tree. The locale
 * is resolved server-side (from the `x-locale` header, see app/layout.tsx) and
 * threaded down, so the first paint already matches the detected language.
 *
 * Only that locale's catalog is downloaded (src/lib/i18n.ts). Until it has
 * loaded the tree waits: on the first load React keeps the server-rendered
 * HTML on screen and hydrates once the catalog is there.
 */
export function I18nProvider({ locale, children }: { locale: string; children: React.ReactNode }) {
  return (
    <Suspense fallback={null}>
      <LoadedI18nProvider locale={locale}>{children}</LoadedI18nProvider>
    </Suspense>
  )
}

function LoadedI18nProvider({ locale, children }: { locale: string; children: React.ReactNode }) {
  // `use` may be called conditionally; skip it once the catalog is in memory.
  const dict = loadedDictionary(locale) ?? use(loadDictionary(locale))
  const brand = useBrand()
  const t = useCallback<TranslateFn>(
    (key, fallback, vars) => translate(dict, key, fallback, brandVars(brand, vars)),
    [dict, brand]
  )
  const value = useMemo(() => ({ locale, t }), [locale, t])
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

/** Access the `t()` translator and active locale. */
export function useTranslation() {
  const ctx = useContext(I18nContext)
  if (!ctx) {
    // Graceful fallback outside a provider (e.g. isolated component tests):
    // resolve against the default catalog rather than throwing.
    const dict = getDictionary(defaultLocale)
    return {
      locale: defaultLocale,
      t: ((key, fallback, vars) => translate(dict, key, fallback, vars)) as TranslateFn,
    }
  }
  return ctx
}
