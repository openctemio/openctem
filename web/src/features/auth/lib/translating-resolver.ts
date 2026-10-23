import type { FieldErrors, FieldValues, Resolver } from 'react-hook-form'

import { AUTH_VALIDATION_KEYS } from '../schemas/auth.schema'

type Translate = (key: string, fallback?: string) => string

function translateErrors(errors: unknown, t: Translate): unknown {
  if (!errors || typeof errors !== 'object') return errors
  const out: Record<string, unknown> = Array.isArray(errors) ? [] : {}
  for (const [name, value] of Object.entries(errors)) {
    if (name === 'message' && typeof value === 'string') {
      const key = AUTH_VALIDATION_KEYS[value]
      out[name] = key ? t(key, value) : value
    } else if (name === 'ref') {
      out[name] = value
    } else {
      out[name] = translateErrors(value, t)
    }
  }
  return out
}

/**
 * Wraps a form resolver so the validation messages it reports are shown in the
 * user's language. Only the message text changes: which fields fail, and when,
 * is the wrapped resolver's.
 */
export function translatingResolver<T extends FieldValues>(
  resolver: Resolver<T>,
  t: Translate
): Resolver<T> {
  return async (values, context, options) => {
    const result = await resolver(values, context, options)
    return { ...result, errors: translateErrors(result.errors, t) as FieldErrors<T> }
  }
}
