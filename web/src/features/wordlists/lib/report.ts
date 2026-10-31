import type { Tr } from '@/features/sensors/lib/format'

import type { WordlistReport } from '../types'

/** Largest text a list may be read from (the API's limit, 2 MiB). */
export const MAX_WORDLIST_TEXT_BYTES = 2 * 1024 * 1024

/**
 * What saving a list kept and dropped, in one sentence:
 * "Kept 412 labels. Dropped 3 lines that are not DNS labels (foo_bar, *.x)."
 */
export function reportText(r: WordlistReport, t: Tr): string {
  const parts = [t('wordlists.report.kept', 'Kept {count} labels.', { count: r.kept })]
  if (r.invalid > 0) {
    parts.push(
      t('wordlists.report.invalid', 'Dropped {count} lines that are not DNS labels.', {
        count: r.invalid,
      })
    )
  }
  if (r.secrets > 0) {
    parts.push(
      t('wordlists.report.secrets', 'Dropped {count} lines that look like secrets.', {
        count: r.secrets,
      })
    )
  }
  if (r.duplicates > 0) {
    parts.push(
      t('wordlists.report.duplicates', 'Removed {count} repeated labels.', { count: r.duplicates })
    )
  }
  if (r.examples.length > 0) {
    parts.push(
      t('wordlists.report.examples', 'Examples: {examples}', { examples: r.examples.join(', ') })
    )
  }
  return parts.join(' ')
}

/** The size of text as UTF-8 bytes. */
export function utf8Bytes(text: string): number {
  return new TextEncoder().encode(text).length
}
