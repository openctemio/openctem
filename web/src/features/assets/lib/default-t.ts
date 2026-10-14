import { defaultLocale, getDictionary, translate, type TranslateVars } from '@/lib/i18n'

/** The signature of `useTranslation().t`, for pure helpers that take it as a parameter. */
export type TFn = (key: string, fallback?: string, vars?: TranslateVars) => string

/**
 * The default-locale translator, for pure helpers called without a `t` (tests,
 * non-React callers). Components pass the `t` from `useTranslation()`.
 */
export const defaultT: TFn = (key, fallback, vars) =>
  translate(getDictionary(defaultLocale), key, fallback, vars)
