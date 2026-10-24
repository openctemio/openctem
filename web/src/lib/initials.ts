/**
 * Up to two initials for a person's avatar: the first letter of the first and
 * the last word ("Lan Anh" -> "LA", "Nguyen Van Minh" -> "NM"), "?" without a
 * name. Letters are taken by code point, so a name starting with an accented
 * or non-Latin letter keeps it whole.
 */
export function initials(name: string | null | undefined): string {
  const words = (name ?? '').trim().split(/\s+/).filter(Boolean)
  if (words.length === 0) return '?'
  const first = Array.from(words[0])[0] ?? ''
  const last = words.length > 1 ? (Array.from(words[words.length - 1])[0] ?? '') : ''
  return (first + last).toLocaleUpperCase() || '?'
}
