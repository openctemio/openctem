/**
 * Merge the mapping fields a dialog shows into the stored mapping.
 *
 * The integration PUT replaces `config` wholesale, so the dialog sends the
 * full map. Keys the dialog does not show are kept. For keys it does show,
 * the field is authoritative: a value sets the key and a blank field removes
 * it (the server then uses its default). Pruning blanks and merging over the
 * stored map instead made a cleared field impossible to save (23a B16).
 */
export function mergeShownMapping(
  stored: Record<string, string> | null | undefined,
  shown: Record<string, string>
): Record<string, string> {
  const out: Record<string, string> = { ...(stored ?? {}) }
  for (const [key, raw] of Object.entries(shown)) {
    const value = raw.trim()
    if (value === '') delete out[key]
    else out[key] = value
  }
  return out
}
