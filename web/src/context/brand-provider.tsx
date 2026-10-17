'use client'

import { createContext, useCallback, useContext } from 'react'
import { DEFAULT_BRAND, type Brand } from '@/lib/brand'
import { DOCS_ORIGIN } from '@/lib/docs-links'

const BrandContext = createContext<Brand>(DEFAULT_BRAND)

/** Hands the instance brand (read on the server, src/lib/brand-settings.ts) to the client tree. */
export function BrandProvider({ brand, children }: { brand: Brand; children: React.ReactNode }) {
  return <BrandContext.Provider value={brand}>{children}</BrandContext.Provider>
}

/** The instance brand; the OpenCTEM defaults outside a provider. */
export function useBrand(): Brand {
  return useContext(BrandContext)
}

/**
 * Moves a link from the docs catalog (src/lib/docs-links.ts, written against
 * the default documentation site) onto the brand's documentation site,
 * keeping the path. Other links are returned unchanged.
 */
export function rebaseDocsLink(link: string, docsUrl: string): string {
  if (!link.startsWith(DOCS_ORIGIN) || docsUrl === DOCS_ORIGIN) return link
  const rest = link.slice(DOCS_ORIGIN.length)
  if (rest && !['/', '#', '?'].includes(rest[0])) return link
  return docsUrl + rest
}

/** `docsHref(DOCS.x.y)`: a docs catalog link on the brand's documentation site. */
export function useDocsHref(): (link: string) => string {
  const { docsUrl } = useBrand()
  return useCallback((link: string) => rebaseDocsLink(link, docsUrl), [docsUrl])
}
