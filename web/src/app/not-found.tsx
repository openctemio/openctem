'use client'

import Link from '@/components/link'
import { FileQuestion } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

export default function NotFound() {
  const { t } = useTranslation()
  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="max-w-md space-y-4 text-center">
        <FileQuestion className="text-muted-foreground mx-auto h-16 w-16" />
        <h1 className="text-hero tabular-nums">404</h1>
        <h2 className="text-xl font-semibold">
          {t('common.pageNotFound.title', 'Page not found')}
        </h2>
        <p className="text-muted-foreground">
          {t(
            'common.pageNotFound.description',
            'The page you are looking for does not exist or has been moved.'
          )}
        </p>
        <div className="flex justify-center gap-2">
          <Button variant="outline" asChild>
            <Link href="/">{t('common.pageNotFound.home', 'Go to home')}</Link>
          </Button>
        </div>
      </div>
    </div>
  )
}
