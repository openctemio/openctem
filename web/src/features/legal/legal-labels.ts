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

/**
 * The legal text is published in English only (whether to translate it is
 * an open owner decision): a reader in another language is told so in one line.
 */
export async function legalLanguageNote(t: LegalT): Promise<string | undefined> {
  let locale = 'en'
  try {
    locale = (await headers()).get('x-locale') ?? 'en'
  } catch {
    // No request: English.
  }
  return locale === 'en'
    ? undefined
    : t('legal.frame.publishedInEnglish', 'This document is published in English.')
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
