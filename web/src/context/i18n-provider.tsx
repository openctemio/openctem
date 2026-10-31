'use client'

import { Suspense, createContext, use, useContext, useMemo, useCallback } from 'react'
import {
  getDictionary,
  loadDictionary,
  loadedDictionary,
  translate,
  type Dictionary,
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
      <CatalogGate locale={locale}>
        {(dict) => (
          <LoadedI18nProvider locale={locale} dict={dict}>
            {children}
          </LoadedI18nProvider>
        )}
      </CatalogGate>
    </Suspense>
  )
}

/**
 * Waits for the catalog and hands it down. It is its own component, with no
 * other hook, on purpose: when the catalog arrives while React is rendering,
 * React replays a component that suspended in `use()`, and a replay of one
 * that also calls hooks (useCallback, useMemo, useContext) after `use` fails
 * with React error 467 ("Update hook called on initial render") on a first
 * render, about one cold page load in a few. A component whose only call is
 * `use` replays safely.
 */
function CatalogGate({
  locale,
  children,
}: {
  locale: string
  children: (dict: Dictionary) => React.ReactNode
}) {
  // `use` may be called conditionally; skip it once the catalog is in memory.
  return children(loadedDictionary(locale) ?? use(loadDictionary(locale)))
}

function LoadedI18nProvider({
  locale,
  dict,
  children,
}: {
  locale: string
  dict: Dictionary
  children: React.ReactNode
}) {
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
