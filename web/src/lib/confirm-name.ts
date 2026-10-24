/** Names longer than this are not typed back; the short id is asked for instead. */
export const CONFIRM_NAME_MAX = 64

/**
 * The text a user types to confirm deleting one item (typeToConfirm): its name,
 * or the first 8 characters of its id when the name is empty or too long to
 * retype.
 */
export function confirmName(name: string | null | undefined, id: string): string {
  const n = (name ?? '').trim()
  if (n && n.length <= CONFIRM_NAME_MAX) return n
  return id.slice(0, 8)
}
