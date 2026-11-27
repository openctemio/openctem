import { toast } from 'sonner'

import type { BulkSummary } from './bulk-result'

/** Shows a bulk summary as the toast its kind calls for (never success for nothing done). */
export function showBulkSummary(summary: BulkSummary): void {
  const opts = summary.description ? { description: summary.description } : undefined
  if (summary.kind === 'success') toast.success(summary.message, opts)
  else if (summary.kind === 'warning') toast.warning(summary.message, opts)
  else toast.error(summary.message, opts)
}
