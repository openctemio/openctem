import { humanizeIdentifier } from '@/lib/humanize-identifier'

/**
 * A message value that is the server's identifier of a thing (a data volume
 * "attachments", a certificate "sensor-ca"): read through the dictionary
 * under `keyPrefix` + identifier, so the reader sees "Uploaded files", not
 * the raw key. An identifier the dictionary does not know (one an operator
 * named) reads humanized. Several join with ", ".
 */
export interface NamedVar {
  /** The `{var}` of the message. */
  var: string
  keyPrefix: string
  values: string[]
}

/** `vars` with each named value replaced by its words. */
export function resolveNamedVars(
  t: (key: string, fallback?: string) => string,
  vars: Record<string, string | number> | undefined,
  named: NamedVar[] | undefined
): Record<string, string | number> | undefined {
  if (!named?.length) return vars
  const out = { ...vars }
  for (const n of named) {
    out[n.var] = n.values.map((v) => t(`${n.keyPrefix}${v}`, humanizeIdentifier(v))).join(', ')
  }
  return out
}
