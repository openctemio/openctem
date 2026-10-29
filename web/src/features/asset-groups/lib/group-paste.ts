/** The most lines one pasted list may have (the API refuses more). */
export const MAX_PASTE_LINES = 10000

/** The lines of a pasted list (blank and `#` lines are skipped by the API). */
export function countPasteLines(text: string): number {
  if (!text) return 0
  let n = 0
  for (const line of text.split('\n')) {
    const v = line.trim()
    if (v && !v.startsWith('#')) n++
  }
  return n
}
