// Kept apart from org-card.tsx: the team switcher button needs the initials at
// once, while the card itself loads when the popover first opens.

/** Up to two initials, e.g. "ORG tenant" -> "OT", "acme" -> "AC". */
export function orgInitials(name: string): string {
  const words = name
    .trim()
    .split(/[\s_-]+/)
    .filter(Boolean)
  if (words.length === 0) return '?'
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase()
  return (words[0][0] + words[1][0]).toUpperCase()
}
