/**
 * English text for helpers that take an optional `t`: a caller without the
 * catalog (a unit test, plain code) gets the English fallback with its
 * {name} values filled and the one/other form of a count picked.
 */

export type FallbackT = (
  key: string,
  fallback: string,
  vars?: Record<string, string | number>
) => string

export const english: FallbackT = (_key, fallback, vars) => {
  if (!vars) return fallback
  const plural = fallback.replace(
    /\{(\w+),\s*plural,\s*one\s*\{([^{}]*)\}\s*other\s*\{([^{}]*)\}\s*\}/g,
    (_m, name: string, one: string, other: string) =>
      (Number(vars[name]) === 1 ? one : other).replace(/#/g, String(vars[name]))
  )
  return plural.replace(/\{(\w+)\}/g, (m, k: string) => String(vars[k] ?? m))
}
