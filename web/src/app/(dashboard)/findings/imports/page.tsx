'use client'

import { Suspense } from 'react'
import { ReceiptHistory } from '@/features/findings/components/receipt-history'

/** Import and run receipts: the list the dashboard's intake figures open. */
export default function FindingImportsPage() {
  return (
    <Suspense>
      <ReceiptHistory />
    </Suspense>
  )
}
