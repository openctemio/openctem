/**
 * The translator signature the scans lib helpers take. Components pass the
 * active locale's `t` from `useTranslation()`; callers without one (tests,
 * non-React code) get the English catalog.
 */
import { getDictionary, translate, type TranslateVars } from '@/lib/i18n'

export type Translate = (key: string, fallback?: string, vars?: TranslateVars) => string

const en = getDictionary('en')

export const enTranslate: Translate = (key, fallback, vars) => translate(en, key, fallback, vars)
