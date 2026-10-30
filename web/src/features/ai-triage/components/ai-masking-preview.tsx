'use client'

import { useState } from 'react'
import { ScanEye } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { TruncatedText } from '@/features/shared/components/truncated-text'
import { UntrustedTextBlock } from '@/features/shared/components/untrusted-text-block'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'

import {
  AI_ERR_NOTHING_TO_SEND,
  AI_ERR_POLICY_RESTRICTED,
  previewAIMasking,
  type AIMaskingPreview,
  type AIPreviewDataClass,
} from '../api/use-ai-masking'

type T = ReturnType<typeof useTranslation>['t']

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const DATA_CLASSES: AIPreviewDataClass[] = ['public', 'internal', 'restricted']
const DATA_CLASS_FALLBACK: Record<AIPreviewDataClass, string> = {
  public: 'Public',
  internal: 'Internal',
  restricted: 'Restricted',
}

function previewError(t: T, err: unknown): string {
  if (err instanceof ApiClientError) {
    if (err.code === AI_ERR_POLICY_RESTRICTED) {
      return t(
        'settings.ai.masking.preview.restricted',
        'Your AI data policy keeps this finding away from AI, so nothing would be sent.'
      )
    }
    if (err.code === AI_ERR_NOTHING_TO_SEND) {
      return t(
        'settings.ai.masking.preview.nothing',
        'Nothing of this finding may be sent under this data class.'
      )
    }
    if (err.statusCode === 404) {
      return t('settings.ai.masking.preview.notFound', 'No finding with this id that you can see.')
    }
    if (err.statusCode === 503) {
      return t(
        'settings.ai.masking.preview.unavailable',
        'The preview is not available on this server.'
      )
    }
  }
  return getErrorMessage(err)
}

/**
 * Shows exactly what the AI model would get for one finding under the saved
 * policy: the masked text (plain text, escaped), the placeholders with their
 * class (never their values) and the fields sent and withheld. Nothing is
 * sent to a model; the server builds the real bundle under the caller's own
 * data scope and audits the preview.
 */
export function AIMaskingPreviewPanel() {
  const { t } = useTranslation()
  const [findingId, setFindingId] = useState('')
  const [dataClass, setDataClass] = useState<AIPreviewDataClass>('internal')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AIMaskingPreview | null>(null)
  const [error, setError] = useState<string | null>(null)

  const id = findingId.trim()
  const valid = UUID.test(id)

  const run = async () => {
    if (!valid) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await previewAIMasking(id, dataClass))
    } catch (err) {
      setError(previewError(t, err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3 rounded-md border p-3" data-testid="ai-masking-preview">
      <div>
        <p className="flex items-center gap-1.5 text-sm font-medium">
          <ScanEye className="h-4 w-4" aria-hidden />
          {t('settings.ai.masking.preview.title', 'Preview')}
        </p>
        <p className="text-sm text-muted-foreground">
          {t(
            'settings.ai.masking.preview.description',
            'See exactly what the AI would get for one finding under the saved policy. Nothing is sent to a model, and the preview is audited.'
          )}
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-[1fr_180px_auto] sm:items-end">
        <div className="space-y-1.5">
          <Label htmlFor="ai-mask-preview-id">
            {t('settings.ai.masking.preview.findingId', 'Finding id')}
          </Label>
          <Input
            id="ai-mask-preview-id"
            value={findingId}
            onChange={(e) => setFindingId(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault()
                void run()
              }
            }}
            className="font-mono"
            spellCheck={false}
            aria-invalid={id !== '' && !valid}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="ai-mask-preview-class">
            {t('settings.ai.masking.preview.dataClass', 'Data class')}
          </Label>
          <Select value={dataClass} onValueChange={(v) => setDataClass(v as AIPreviewDataClass)}>
            <SelectTrigger id="ai-mask-preview-class">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {DATA_CLASSES.map((c) => (
                <SelectItem key={c} value={c}>
                  {t(`settings.ai.useCases.ceilingName.${c}`, DATA_CLASS_FALLBACK[c])}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button type="button" variant="outline" onClick={run} disabled={!valid || loading}>
          {t('settings.ai.masking.preview.run', 'Preview')}
        </Button>
      </div>
      {id !== '' && !valid && (
        <p className="text-xs text-destructive">
          {t('settings.ai.masking.preview.invalidId', 'Enter a finding id (a UUID).')}
        </p>
      )}
      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}
      {result && (
        <div className="space-y-3">
          <UntrustedTextBlock
            text={result.text}
            label={t('settings.ai.masking.preview.text', 'What the model gets')}
          />
          <div className="space-y-1">
            <p className="text-sm font-medium">
              {t('settings.ai.masking.preview.placeholders', 'Placeholders ({count})', {
                count: result.placeholders.length,
              })}
            </p>
            {result.placeholders.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {t('settings.ai.masking.preview.noPlaceholders', 'Nothing was masked.')}
              </p>
            ) : (
              <ul className="flex flex-wrap gap-1.5" data-testid="ai-masking-placeholders">
                {result.placeholders.map((p) => (
                  <li
                    key={p.token}
                    className="inline-flex items-center gap-1.5 rounded-md border bg-muted/40 px-1.5 py-0.5 text-xs"
                  >
                    <TruncatedText value={p.token} className="max-w-[200px] font-mono" />
                    <span className="text-muted-foreground">
                      {t(`settings.ai.masking.placeholderClass.${p.class.toLowerCase()}`, p.class)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <FieldLine
            label={t('settings.ai.masking.preview.sent', 'Fields sent')}
            items={result.fields_sent}
            none={t('settings.ai.masking.preview.none', 'None')}
          />
          <FieldLine
            label={t('settings.ai.masking.preview.withheld', 'Fields withheld')}
            items={result.fields_withheld}
            none={t('settings.ai.masking.preview.none', 'None')}
          />
        </div>
      )}
    </div>
  )
}

function FieldLine({ label, items, none }: { label: string; items: string[]; none: string }) {
  return (
    <div className="space-y-1">
      <p className="text-sm font-medium">{label}</p>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{none}</p>
      ) : (
        <ul className="flex flex-wrap gap-1.5">
          {items.map((f) => (
            <li key={f} className="rounded border bg-muted/40 px-1.5 py-0.5 font-mono text-xs">
              <TruncatedText value={f} className="max-w-[220px]" />
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
