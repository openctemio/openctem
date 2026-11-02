'use client'

import { useState } from 'react'
import { Copy } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { copyToClipboard } from '@/lib/clipboard'

import { useScannerAddresses } from '../api/use-proxy-pools'
import { ALLOWLIST_FORMATS, allowlistSnippet, type AllowlistFormat } from '../lib/allowlist'
import type { ScannerAddress } from '../types'

/** The anchor other pages link to (edge-blocked fixes, retest help). */
export const SCANNER_ADDRESSES_ANCHOR = 'scanner-addresses'

type Translate = ReturnType<typeof useTranslation>['t']

function sourceText(a: ScannerAddress, t: Translate): string {
  switch (a.kind) {
    case 'proxy_exit':
      return a.endpoint_label
        ? t('proxyPools.scanner.source.proxyLabel', undefined, {
            pool: a.pool_name ?? '',
            label: a.endpoint_label,
          })
        : t('proxyPools.scanner.source.proxy', undefined, { pool: a.pool_name ?? '' })
    case 'sensor':
      return t('proxyPools.scanner.source.sensor', undefined, { name: a.sensor_name ?? '' })
    default:
      return a.region
        ? t('proxyPools.scanner.source.platformRegion', undefined, { region: a.region })
        : t('proxyPools.scanner.source.platform')
  }
}

async function copy(text: string, t: Translate) {
  if (await copyToClipboard(text)) toast.success(t('proxyPools.scanner.copied'))
  else toast.error(t('proxyPools.scanner.copyFailed'))
}

/**
 * Settings, Scanning, Proxies: the addresses scans leave from, for a target
 * owner to allowlist at a WAF or edge protection. Only addresses the platform
 * observed itself (a proxy's exit through the test echo, a sensor's
 * connection); never a credential. Needs sensors:egress:read.
 */
export function ScannerAddressesCard({ enabled = true }: { enabled?: boolean }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useScannerAddresses(enabled)
  const [format, setFormat] = useState<AllowlistFormat>('lines')
  if (!enabled) return null

  const items = data?.items ?? []
  const cidrs = data?.cidrs ?? []
  const snippet = allowlistSnippet(cidrs, format)

  return (
    <Card
      id={SCANNER_ADDRESSES_ANCHOR}
      data-testid="scanner-addresses-card"
      className="scroll-mt-20"
    >
      <CardHeader>
        <CardTitle>{t('proxyPools.scanner.title')}</CardTitle>
        <CardDescription>{t('proxyPools.scanner.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error ? (
          <ErrorState
            title={t('proxyPools.scanner.title')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : items.length === 0 ? (
          <p className="text-sm text-muted-foreground" data-testid="scanner-addresses-empty">
            {t('proxyPools.scanner.empty')}
          </p>
        ) : (
          <>
            <ul
              className="divide-y rounded-md border"
              aria-label={t('proxyPools.scanner.listLabel')}
            >
              {items.map((a) => (
                <li
                  key={`${a.kind}-${a.address}-${a.endpoint_id ?? a.sensor_id ?? a.region ?? ''}`}
                  className="flex min-w-0 items-center gap-3 px-3 py-2"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm break-all">{a.address}</span>
                      <Badge variant="outline" className="text-xs font-normal">
                        {t(`proxyPools.scanner.kind.${a.kind}`)}
                      </Badge>
                      {a.private && (
                        <Badge variant="secondary" className="text-xs font-normal">
                          {t('proxyPools.scanner.private')}
                        </Badge>
                      )}
                    </div>
                    <p className="truncate text-xs text-muted-foreground">{sourceText(a, t)}</p>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 shrink-0"
                    aria-label={t('proxyPools.scanner.copyOne', undefined, { address: a.address })}
                    onClick={() => void copy(a.address, t)}
                  >
                    <Copy className="h-4 w-4" aria-hidden />
                  </Button>
                </li>
              ))}
            </ul>

            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="text-sm font-medium">{t('proxyPools.scanner.snippetsTitle')}</h3>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => void copy(snippet, t)}
                  data-testid="scanner-addresses-copy-snippet"
                >
                  <Copy className="mr-2 h-4 w-4" aria-hidden />
                  {t('proxyPools.scanner.copySnippet')}
                </Button>
              </div>
              <Tabs value={format} onValueChange={(v) => setFormat(v as AllowlistFormat)}>
                <TabsList className="h-auto max-w-full flex-wrap justify-start">
                  {ALLOWLIST_FORMATS.map((f) => (
                    <TabsTrigger key={f} value={f} className="text-xs">
                      {t(`proxyPools.scanner.format.${f}`)}
                    </TabsTrigger>
                  ))}
                </TabsList>
              </Tabs>
              <pre
                className="max-h-64 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs break-all whitespace-pre-wrap"
                data-testid="scanner-addresses-snippet"
              >
                {snippet}
              </pre>
              <p className="text-xs text-muted-foreground">{t('proxyPools.scanner.privateNote')}</p>
            </div>
          </>
        )}
        <p className="text-xs text-muted-foreground">{t('proxyPools.scanner.howLearned')}</p>
      </CardContent>
    </Card>
  )
}
