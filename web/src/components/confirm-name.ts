/** Longest name a person is asked to retype before an irreversible action. */
export const TYPE_TO_CONFIRM_NAME_MAX = 64

/**
 * The typeToConfirm value for one item: its name, or a short id when the name
 * is empty or too long to retype.
 */
export function nameToTypeToConfirm(name: string | null | undefined, id: string): string {
  const trimmed = (name ?? '').trim()
  if (trimmed && trimmed.length <= TYPE_TO_CONFIRM_NAME_MAX) return trimmed
  return id.slice(0, 8)
}
