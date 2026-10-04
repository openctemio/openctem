'use client'

/**
 * Attack surface › Review: confirm or reject the names discovery found but
 * could not prove are the organisation's (RFC-036 §6.4, §6.11).
 */

import Link from 'next/link'
import { ArrowLeft } from 'lucide-react'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { PageHeader } from '@/features/shared'
import { EASMReviewQueue } from '@/features/attack-surface'

export default function AttackSurfaceReviewPage() {
  return (
    <Main>
      <PageHeader
        title="Ownership review"
        description="Names found in Certificate Transparency and discovery that may be yours. Scans skip them until you confirm them."
      >
        <Button variant="outline" size="sm" asChild>
          <Link href="/attack-surface">
            <ArrowLeft className="h-4 w-4" aria-hidden />
            Attack surface
          </Link>
        </Button>
      </PageHeader>
      <div className="mt-6">
        <EASMReviewQueue />
      </div>
    </Main>
  )
}
