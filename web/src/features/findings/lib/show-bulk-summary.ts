import { toast } from 'sonner'

import type { BulkSummary } from './bulk-result'

/**
 * Shows a bulk summary as the toast its kind calls for (never success for
 * nothing done). The text is the app's own translated sentence, built by
 * summarizeBulkResult / summarizeFixDecision from counts and registered
 * reason codes: no server or error text reaches it.
 */
export function showBulkSummary({ kind, message: sentence, description }: BulkSummary): void {
  const opts = description ? { description } : undefined
  if (kind === 'success') toast.success(sentence, opts)
  else if (kind === 'warning') toast.warning(sentence, opts)
  else toast.error(sentence, opts)
}
