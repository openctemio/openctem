'use client'

import { Suspense } from 'react'
import { MyWorkPage } from '@/features/my-work/components/my-work-page'

export default function Page() {
  return (
    <Suspense>
      <MyWorkPage />
    </Suspense>
  )
}
