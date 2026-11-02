'use client'

import { useId, useState } from 'react'
import { Search } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'

import { useWordlistPreview } from '../api/use-wordlists'

/**
 * Preview for a domain: how many labels a standard discovery run of it
 * would ask DNS for, from each source. Counts only; nothing is queried.
 */
export function WordlistPreviewCard() {
  const { t } = useTranslation()
  const id = useId()
  const [input, setInput] = useState('')
  const [root, setRoot] = useState<string | null>(null)
  const { data, error, isLoading } = useWordlistPreview(root)
  const n = (v: number) => v.toLocaleString()

  return (
    <Card data-testid="wordlist-preview">
      <CardHeader>
        <CardTitle className="text-base">
          {t('wordlists.preview.title', 'Preview for a domain')}
        </CardTitle>
        <CardDescription>
          {t(
            'wordlists.preview.description',
            'See how many names a standard discovery run of a domain would try, and where they come from. Nothing is sent.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            const v = input.trim()
            setRoot(v === '' ? null : v)
          }}
        >
          <div className="min-w-[220px] flex-1 space-y-1.5">
            <Label htmlFor={id}>{t('wordlists.preview.domain', 'Domain')}</Label>
            <Input
              id={id}
              value={input}
              placeholder="example.com"
              onChange={(e) => setInput(e.target.value)}
            />
          </div>
          <Button type="submit" variant="outline" disabled={input.trim() === ''}>
            <Search className="size-4" aria-hidden />
            {t('wordlists.preview.run', 'Preview')}
          </Button>
        </form>
        {isLoading && (
          <p className="text-sm text-muted-foreground">
            {t('wordlists.preview.loading', 'Counting...')}
          </p>
        )}
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {getErrorMessage(error, t('wordlists.preview.failed', 'Could not count the labels'))}
          </p>
        )}
        {data && !error && (
          <div className="space-y-2 text-sm" data-testid="wordlist-preview-result">
            <p className="font-medium">
              {t('wordlists.preview.total', 'Up to {count} labels for {root}', {
                count: n(data.total),
                root: data.root,
              })}
            </p>
            <ul className="space-y-1 text-muted-foreground">
              <li>
                {data.pack
                  ? t(
                      'wordlists.preview.pack',
                      'Platform list {name}, version {version}: {count}',
                      {
                        name: data.pack.name,
                        version: data.pack.version,
                        count: n(data.pack.lines),
                      }
                    )
                  : t(
                      'wordlists.preview.noPack',
                      'No platform list is installed yet: discovery waits until an administrator adds one.'
                    )}
              </li>
              <li>
                {t('wordlists.preview.learned', 'Learned from your names, with variants: {count}', {
                  count: n(data.learned),
                })}
              </li>
              <li>
                {t('wordlists.preview.yours', 'From your lists: {count}', {
                  count: n(data.organization_kept),
                })}
                {data.organization_kept < data.organization &&
                  ` ${t('wordlists.preview.cut', '(the first {kept} of {count} fit in one run)', {
                    kept: n(data.organization_kept),
                    count: n(data.organization),
                  })}`}
              </li>
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
