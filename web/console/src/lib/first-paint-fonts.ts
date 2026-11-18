/**
 * The Inter files the console's first paint draws with (src/styles/fonts.css):
 * Latin always; Latin Extended and Vietnamese for a Vietnamese page (its
 * letters with diacritics come from those two subsets). The root layout
 * preloads them so they arrive with the stylesheet instead of after the first
 * layout; the size-adjusted `Inter Fallback` face covers a page that still
 * paints before them.
 */
const LATIN = '/fonts/inter-latin-wght-normal.woff2'

const BY_LOCALE: Record<string, readonly string[]> = {
  en: [LATIN],
  vi: [
    LATIN,
    '/fonts/inter-latin-ext-wght-normal.woff2',
    '/fonts/inter-vietnamese-wght-normal.woff2',
  ],
}

export function firstPaintFonts(locale: string): readonly string[] {
  return BY_LOCALE[locale] ?? BY_LOCALE.en
}
