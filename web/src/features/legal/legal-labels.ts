import { headers } from 'next/headers'

import type { StaticPageLabels } from '@/components/static-page'
import { loadDictionary, translate, type Dictionary, type TranslateVars } from '@/lib/i18n'

export type LegalT = (key: string, fallback: string, vars?: TranslateVars) => string

/**
 * The translator of a legal page, on the server: the request's locale
 * (`x-locale`, set by the proxy), English outside a request.
 */
export async function legalTranslator(): Promise<LegalT> {
  let dict: Dictionary = {}
  try {
    dict = await loadDictionary((await headers()).get('x-locale') ?? undefined)
  } catch {
    // No request (a unit test, a static render): the English fallbacks.
  }
  return (key, fallback, vars) => translate(dict, key, fallback, vars)
}

export function legalFrameLabels(t: LegalT): StaticPageLabels {
  return {
    signIn: t('legal.frame.signIn', 'Sign in'),
    documents: t('legal.frame.documents', 'Legal documents'),
    onThisPage: t('legal.frame.onThisPage', 'On this page'),
    print: t('legal.frame.print', 'Print or save as PDF'),
    skip: t('legal.frame.skip', 'Skip to the document'),
  }
}
