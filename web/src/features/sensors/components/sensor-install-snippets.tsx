'use client'

import { useEffect, useState } from 'react'
import { Check, Copy, Download, Info } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { copyToClipboard } from '@/lib/clipboard'
import { sensorEndpoints } from '@/lib/api/endpoints'
import { cn } from '@/lib/utils'

/** GET /sensors/{id}/config-templates (older APIs send only the first four). */
export interface SensorTemplates {
  yaml: string
  env: string
  docker: string
  cli: string
  compose?: string
  kubernetes?: string
  helm?: string
  /** The sensor-local policy template (api RFC-040 §5.7), prefilled with the zones' ranges. */
  policy?: string
  image?: string
  api_url?: string
  api_key_included?: boolean
  ca_certificate?: string
  ca_fingerprint_sha256?: string
}

export type SnippetFormat =
  'docker' | 'compose' | 'kubernetes' | 'helm' | 'policy' | 'yaml' | 'env' | 'cli'

/** `labelKey` is a catalog key; formats without one are product names shown verbatim. */
const FORMATS: { key: SnippetFormat; label: string; labelKey?: string; file?: string }[] = [
  { key: 'docker', label: 'docker run' },
  { key: 'compose', label: 'Compose', file: 'compose.yaml' },
  { key: 'kubernetes', label: 'Kubernetes', file: 'sensor.yaml' },
  { key: 'helm', label: 'Helm' },
  {
    key: 'policy',
    label: 'Local policy',
    labelKey: 'sensors.snippets.format.policy',
    file: 'sensor-policy.yaml',
  },
  {
    key: 'yaml',
    label: 'Config file',
    labelKey: 'sensors.snippets.format.yaml',
    file: 'sensor.yaml',
  },
  { key: 'env', label: 'Env' },
  { key: 'cli', label: 'Binary', labelKey: 'sensors.snippets.format.cli' },
]

/** The formats a templates response carries, in display order. */
export function availableFormats(t: SensorTemplates | null | undefined): SnippetFormat[] {
  if (!t) return []
  return FORMATS.filter((f) => (t[f.key] ?? '').trim() !== '').map((f) => f.key)
}

/**
 * Fetch the rendered snippets. The key (shown once, right after create or
 * rotate) travels in a header, never the URL, and is not kept in any cache.
 */
export function useSensorTemplates(sensorId: string | null, apiKey?: string) {
  const [data, setData] = useState<SensorTemplates | null>(null)
  const [error, setError] = useState<Error | null>(null)
  const [loading, setLoading] = useState(false)
  const { t } = useTranslation()
  useEffect(() => {
    if (!sensorId) return
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (apiKey) headers['X-Sensor-API-Key'] = apiKey
    fetch(`${sensorEndpoints.get(sensorId)}/config-templates`, {
      credentials: 'include',
      headers,
      signal: controller.signal,
      cache: 'no-store',
    })
      .then(async (res) => {
        if (!res.ok)
          throw new Error(t('sensors.snippets.loadFailed', undefined, { status: res.status }))
        return (await res.json()) as SensorTemplates
      })
      .then(setData)
      .catch((err: Error) => {
        if (err.name !== 'AbortError') setError(err)
      })
      .finally(() => setLoading(false))
    return () => controller.abort()
  }, [sensorId, apiKey, t])
  return { data, error, loading }
}

function downloadText(content: string, filename: string, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

/** One snippet with Copy (and Download for files). */
export function Snippet({ text, label, file }: { text: string; label: string; file?: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  return (
    <div className="relative min-w-0 rounded-lg border bg-muted/50">
      <div className="absolute end-2 top-2 flex gap-1.5">
        {file && (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7 bg-background px-2 text-xs"
            onClick={() => downloadText(text, file)}
            aria-label={t('sensors.snippets.download', undefined, { file })}
          >
            <Download className="h-3.5 w-3.5" />
          </Button>
        )}
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-7 bg-background px-2 text-xs"
          onClick={async () => {
            await copyToClipboard(text)
            setCopied(true)
            toast.success(t('sensors.snippets.copiedToast', undefined, { label }))
            setTimeout(() => setCopied(false), 1500)
          }}
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? t('sensors.snippets.copied') : t('sensors.snippets.copy')}
        </Button>
      </div>
      <pre
        className="max-h-96 overflow-auto p-4 pe-28 font-mono text-xs leading-relaxed whitespace-pre"
        data-format={label}
      >
        {text}
      </pre>
    </div>
  )
}

/**
 * The commands that install a sensor (docker run, Compose, Kubernetes, Helm)
 * and its config file, as the API renders them: pinned image, the platform's
 * public URL, the key when it was just issued, and the platform CA when it
 * uses a private one.
 */
export function SensorInstallSnippets({
  sensorId,
  apiKey,
  defaultFormat = 'docker',
  className,
}: {
  sensorId: string
  /** The freshly issued key (create / rotate); embedded in the commands. */
  apiKey?: string
  defaultFormat?: SnippetFormat
  className?: string
}) {
  const { t } = useTranslation()
  const { data, error, loading } = useSensorTemplates(sensorId, apiKey)
  const formats = availableFormats(data)
  const [format, setFormat] = useState<SnippetFormat>(defaultFormat)
  const active = formats.includes(format) ? format : (formats[0] ?? defaultFormat)
  const formatLabel = (f: (typeof FORMATS)[number]) => (f.labelKey ? t(f.labelKey) : f.label)

  if (loading && !data) {
    return (
      <div className={cn('space-y-3', className)} aria-busy="true" aria-label={t('common.loading')}>
        <Skeleton className="h-8 w-72" />
        <Skeleton className="h-48 w-full" />
      </div>
    )
  }
  if (error) {
    return (
      <div className={className}>
        <ErrorState title={t('sensors.snippets.errorTitle')} error={error} />
      </div>
    )
  }
  if (!data) return null

  return (
    <div className={cn('min-w-0 space-y-3', className)}>
      <Tabs value={active} onValueChange={(v) => setFormat(v as SnippetFormat)}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <TabsList className="no-scrollbar max-w-full overflow-x-auto">
            {FORMATS.filter((f) => formats.includes(f.key)).map((f) => (
              <TabsTrigger key={f.key} value={f.key}>
                {formatLabel(f)}
              </TabsTrigger>
            ))}
          </TabsList>
          {data.image && (
            <span className="text-xs text-muted-foreground">
              {t('sensors.snippets.image')} <span className="font-mono">{data.image}</span>
            </span>
          )}
        </div>
        {FORMATS.filter((f) => formats.includes(f.key)).map((f) => (
          <TabsContent key={f.key} value={f.key} className="mt-3 space-y-2">
            {f.key === 'policy' && (
              <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
                <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                <span>{t('sensors.snippets.policyNote')}</span>
              </p>
            )}
            <Snippet text={data[f.key] ?? ''} label={formatLabel(f)} file={f.file} />
          </TabsContent>
        ))}
      </Tabs>

      {data.ca_certificate ? (
        <div className="flex gap-2 rounded-lg border p-3 text-xs">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
          <div className="min-w-0 space-y-1.5">
            <p>
              {t('sensors.snippets.caNoteBefore')} <span className="font-mono">SSL_CERT_DIR</span>
              {t('sensors.snippets.caNoteAfter')}
            </p>
            {data.ca_fingerprint_sha256 && (
              <p className="break-all text-muted-foreground">
                {t('sensors.snippets.fingerprint')}{' '}
                <span className="font-mono">{data.ca_fingerprint_sha256}</span>
              </p>
            )}
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              onClick={() =>
                downloadText(
                  data.ca_certificate ?? '',
                  'openctem-root-ca.crt',
                  'application/x-pem-file'
                )
              }
            >
              <Download className="h-3.5 w-3.5" />
              {t('sensors.snippets.downloadCa')}
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
