'use client'

/**
 * A finding id is always a UUID. Any other segment (a typo, an old link such
 * as /findings/imports) shows the same not-found block as an unknown finding,
 * without sending the segment to the API or mounting the detail page.
 */
import type { ReactNode } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export default function FindingIdLayout({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const router = useRouter()
  const params = useParams()
  const id = typeof params.id === 'string' ? params.id : ''

  if (UUID_RE.test(id)) return <>{children}</>

  return (
    <Main>
      <div className="flex h-[50vh] items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-semibold">
            {t('findings.detail.notFound.title', 'Finding not found')}
          </h1>
          <p className="mt-2 text-muted-foreground">
            {t(
              'findings.detail.notFound.description',
              'It does not exist, or you do not have access to it.'
            )}
          </p>
          <Button className="mt-4" onClick={() => router.push('/findings')}>
            {t('findings.detail.notFound.back', 'Back to findings')}
          </Button>
        </div>
      </div>
    </Main>
  )
}
