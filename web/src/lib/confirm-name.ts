/** Longest name a person is asked to type to confirm an action. */
export const CONFIRM_NAME_MAX = 64

/**
 * What a person types to confirm an action on one named item: its name, or a
 * short id when the name is empty or too long to retype.
 */
export function confirmNameFor(name: string | undefined | null, id: string): string {
  const n = (name ?? '').trim()
  if (n && n.length <= CONFIRM_NAME_MAX) return n
  return id.slice(0, 8)
}
