import type { Metadata } from 'next'
import { LegalPage, legalTitle } from '@/features/legal/legal-page'

export const dynamic = 'force-dynamic'

export const metadata: Metadata = { title: legalTitle('dpa') }

/** Built-in template (LEGAL_PAGES_ENABLED=true); 404 otherwise. */
export default function DataProcessingAddendumPage() {
  return <LegalPage doc="dpa" />
}
