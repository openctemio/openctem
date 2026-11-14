'use client'

/**
 * The message settings of a notification channel, shared by the add and
 * edit dialogs: how much of an event the channel receives (detail level),
 * an optional template over the closed variable set, and a live preview
 * rendered by the API from sample data with the same code real messages use.
 */

import { useEffect, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useDebounce } from '@/hooks/use-debounce'
import { getErrorMessage } from '@/lib/api/error-handler'
import { SEVERITY_DOT_COLORS, type SeverityLevel } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'
import {
  previewNotificationMessage,
  type NotificationPreview,
} from '@/features/integrations/api/use-integrations-api'
import {
  DETAIL_LEVELS,
  TEMPLATE_PRESETS,
  TEMPLATE_VARIABLES,
  presetOf,
  type DetailLevel,
  type TemplatePresetId,
} from '../lib/message-template'

const PREVIEW_EVENTS = ['new_exposure', 'new_finding', 'new_asset'] as const

interface ChannelMessageSettingsProps {
  idPrefix: string
  detailLevel: DetailLevel
  onDetailLevelChange: (level: DetailLevel) => void
  template: string
  onTemplateChange: (template: string) => void
}

export function ChannelMessageSettings({
  idPrefix,
  detailLevel,
  onDetailLevelChange,
  template,
  onTemplateChange,
}: ChannelMessageSettingsProps) {
  const { t, locale } = useTranslation()
  const [preset, setPreset] = useState<TemplatePresetId>(() => presetOf(template))
  const [eventType, setEventType] = useState<(typeof PREVIEW_EVENTS)[number]>('new_exposure')
  const [preview, setPreview] = useState<NotificationPreview | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const debouncedTemplate = useDebounce(template, 300)

  useEffect(() => {
    let cancelled = false
    previewNotificationMessage({
      detail_level: detailLevel,
      message_template: debouncedTemplate,
      event_type: eventType,
      locale,
    })
      .then((p) => {
        if (cancelled) return
        setPreview(p)
        setPreviewError(null)
      })
      .catch((err) => {
        if (cancelled) return
        setPreviewError(getErrorMessage(err, t('notificationTypes.message.previewFailed')))
      })
    return () => {
      cancelled = true
    }
  }, [detailLevel, debouncedTemplate, eventType, locale, t])

  const choosePreset = (id: TemplatePresetId) => {
    setPreset(id)
    const p = TEMPLATE_PRESETS.find((x) => x.id === id)
    if (p && p.template !== null) onTemplateChange(p.template)
  }

  const severity = (preview?.severity ?? 'info') as SeverityLevel

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}_detail_level`}>
          {t('notificationTypes.message.levelLabel')}
        </Label>
        <Select value={detailLevel} onValueChange={(v) => onDetailLevelChange(v as DetailLevel)}>
          <SelectTrigger id={`${idPrefix}_detail_level`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {DETAIL_LEVELS.map((level) => (
              <SelectItem key={level} value={level}>
                {t(`notificationTypes.message.level.${level}`)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          {t(`notificationTypes.message.level.${detailLevel}.hint`)}
        </p>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <Label htmlFor={`${idPrefix}_message_template`}>
            {t('notificationTypes.message.templateLabel')}
          </Label>
          <Select value={preset} onValueChange={(v) => choosePreset(v as TemplatePresetId)}>
            <SelectTrigger
              className="w-[180px]"
              aria-label={t('notificationTypes.message.presetLabel')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TEMPLATE_PRESETS.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {t(`notificationTypes.message.preset.${p.id}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Textarea
          id={`${idPrefix}_message_template`}
          value={template}
          onChange={(e) => {
            setPreset('custom')
            onTemplateChange(e.target.value)
          }}
          placeholder={t('notificationTypes.message.templatePlaceholder')}
          className="min-h-[88px] resize-none font-mono text-sm"
          aria-invalid={!!previewError}
        />
        <p className="text-xs text-muted-foreground">
          {t('notificationTypes.message.variables')}{' '}
          {TEMPLATE_VARIABLES.map((v) => (
            <code key={v} className="mr-1 rounded bg-muted px-1 font-mono">
              {`{${v}}`}
            </code>
          ))}
        </p>
        <p className="text-xs text-muted-foreground">
          {t('notificationTypes.message.templateHint')}
        </p>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <Label>{t('notificationTypes.message.previewLabel')}</Label>
          <Select
            value={eventType}
            onValueChange={(v) => setEventType(v as (typeof PREVIEW_EVENTS)[number])}
          >
            <SelectTrigger
              className="w-[180px]"
              aria-label={t('notificationTypes.message.previewEvent')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PREVIEW_EVENTS.map((e) => (
                <SelectItem key={e} value={e}>
                  {t(`notificationTypes.message.event.${e}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {previewError ? (
          <p role="alert" className="text-sm text-destructive">
            {previewError}
          </p>
        ) : preview ? (
          <div className="rounded-md border bg-muted/40 p-3 text-sm" aria-live="polite">
            <div className="flex items-center gap-2 font-semibold">
              <span
                aria-hidden
                className={cn('inline-block size-2.5 rounded-full', SEVERITY_DOT_COLORS[severity])}
              />
              {preview.headline}
            </div>
            <div className="mt-1 space-y-0.5">
              {preview.lines.map((l, i) => (
                <div key={i}>
                  {l.label ? <span className="font-medium">{l.label}: </span> : null}
                  {l.value}
                </div>
              ))}
            </div>
            <div className="mt-2 inline-block rounded border bg-background px-2 py-1 text-xs font-medium">
              {preview.action_label}
            </div>
          </div>
        ) : null}
        <p className="text-xs text-muted-foreground">
          {t('notificationTypes.message.previewHint')}
        </p>
      </div>
    </div>
  )
}
