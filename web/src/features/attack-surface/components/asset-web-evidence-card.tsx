'use client'

/**
 * Web evidence of an asset (RFC-081): what a sensor saw when it fetched it.
 * The final URL, status, title and a short masked response snippet, and the
 * screenshot when the organization keeps them. Everything is shown as text;
 * the screenshot is a PNG the platform re-encoded. Hidden when there is none.
 */

import { useSettleSignal } from '@/features/shared/components/settle-group'
import { useState } from 'react'
import { Camera } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared'
import type { WebEvidenceItem } from '@/lib/api/generated'
import { safeImageSrc } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import { useWebEvidence, webEvidenceScreenshotUrl } from '../hooks/use-web-evidence'

function Capture({ assetId, item }: { assetId: string; item: WebEvidenceItem }) {
  const { t } = useTranslation()
  const [broken, setBroken] = useState(false)
  return (
    <article className="space-y-3 rounded-md border p-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {item.status_code ? <Badge variant="outline">{item.status_code}</Badge> : null}
        <span className="break-all font-medium">{item.title || item.final_url || item.url}</span>
        <RelativeTime date={item.captured_at} className="ms-auto text-xs" />
      </div>
      <dl className="grid gap-1 text-xs text-muted-foreground sm:grid-cols-[8rem_1fr]">
        <dt>{t('webEvidence.url', 'URL')}</dt>
        <dd className="break-all">{item.url}</dd>
        {item.final_url && item.final_url !== item.url && (
          <>
            <dt>{t('webEvidence.finalUrl', 'Final URL')}</dt>
            <dd className="break-all">{item.final_url}</dd>
          </>
        )}
        {item.server && (
          <>
            <dt>{t('webEvidence.server', 'Server')}</dt>
            <dd className="break-all">{item.server}</dd>
          </>
        )}
        {item.content_type && (
          <>
            <dt>{t('webEvidence.contentType', 'Content type')}</dt>
            <dd className="break-all">{item.content_type}</dd>
          </>
        )}
      </dl>
      {item.has_screenshot && item.id && !broken && (
        // eslint-disable-next-line @next/next/no-img-element -- an authenticated API image, not a static asset
        <img
          src={safeImageSrc(webEvidenceScreenshotUrl(assetId, item.id))}
          alt={t('webEvidence.screenshotAlt', 'Screenshot of {url}', {
            url: item.final_url || item.url || '',
          })}
          loading="lazy"
          referrerPolicy="no-referrer"
          className="max-h-[480px] w-full rounded border object-contain object-top"
          width={item.screenshot_width}
          height={item.screenshot_height}
          onError={() => setBroken(true)}
        />
      )}
      {item.snippet && (
        <div className="space-y-1">
          <p className="text-xs font-medium">
            {t('webEvidence.snippet', 'Response (start, secrets masked)')}
          </p>
          <pre
            className={cn(
              'max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-2 text-xs'
            )}
          >
            {item.snippet}
            {item.snippet_truncated ? '\n…' : ''}
          </pre>
        </div>
      )}
    </article>
  )
}

export function AssetWebEvidenceCard({
  assetId,
  className,
}: {
  assetId: string
  className?: string
}) {
  const { t } = useTranslation()
  const { items, isLoading } = useWebEvidence(assetId)
  useSettleSignal(isLoading)
  if (items.length === 0) return null
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Camera className="h-4 w-4" aria-hidden />
          {t('webEvidence.title', 'Web evidence')}
        </CardTitle>
        <CardDescription>
          {t(
            'webEvidence.description',
            'What a sensor saw when it fetched this asset. Screenshots are kept for 30 days when your organization turned them on.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {items.map((item) => (
          <Capture key={item.id} assetId={assetId} item={item} />
        ))}
      </CardContent>
    </Card>
  )
}
