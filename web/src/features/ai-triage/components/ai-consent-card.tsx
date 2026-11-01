'use client'

import { useState } from 'react'
import { ChevronDown, Sparkles } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'

import { updateAISettings, type AISettings } from '../api/use-ai-settings'

interface AIConsentCardProps {
  settings?: AISettings
  isLoading: boolean
  error?: unknown
  canEdit: boolean
  onSaved: (next: AISettings) => Promise<void>
}

/**
 * The organization's consent to AI triage (api: docs/architecture/ai-triage.md).
 * Until an owner or administrator turns it on, no finding content is sent to
 * an AI provider. Turning it on asks for confirmation, needs a recent sign-in
 * (the shared client asks for it) and is audited. What is sent stays one
 * click away instead of always open.
 */
export function AIConsentCard({
  settings,
  isLoading,
  error,
  canEdit,
  onSaved,
}: AIConsentCardProps) {
  const { t } = useTranslation()
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const enabled = settings?.enabled === true

  const save = async (on: boolean) => {
    setSaving(true)
    try {
      const next = await updateAISettings({ enabled: on })
      await onSaved(next)
      toast.success(
        on
          ? t('settings.ai.turnedOn', 'AI triage is on for this organization')
          : t('settings.ai.turnedOff', 'AI triage is off for this organization')
      )
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const since =
    settings?.enabled_by === 'upgrade'
      ? t(
          'settings.ai.sinceUpgrade',
          'On since {date}: your organization used AI triage before this setting existed.',
          { date: formatDateSafe(settings?.enabled_at) }
        )
      : t('settings.ai.since', 'On since {date}.', { date: formatDateSafe(settings?.enabled_at) })

  return (
    <Card id="ai-triage">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="h-4 w-4" aria-hidden />
          {t('settings.ai.triageTitle', 'AI triage')}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.ai.triageDescription',
            'Members can ask AI for a severity assessment, exploitability, false-positive likelihood and remediation steps on a finding. The result is a suggestion: nothing on a finding changes without a person.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading ? (
          <Skeleton className="h-6 w-1/2" />
        ) : error ? (
          <p className="text-sm text-destructive">{getErrorMessage(error)}</p>
        ) : (
          <div className="flex items-start gap-3">
            <Switch
              id="ai-triage-enabled"
              checked={enabled}
              disabled={!canEdit || saving}
              onCheckedChange={(on) => (on ? setConfirmOpen(true) : void save(false))}
            />
            <div className="space-y-1">
              <Label htmlFor="ai-triage-enabled">
                {t('settings.ai.toggle', 'Turn on AI triage for this organization')}
              </Label>
              <p className="text-sm text-muted-foreground">
                {enabled
                  ? since
                  : t('settings.ai.off', 'Off: no finding content is sent to an AI provider.')}
              </p>
            </div>
          </div>
        )}

        <Collapsible className="rounded-md border">
          <CollapsibleTrigger className="group flex w-full items-center justify-between gap-3 px-3 py-2 text-start text-sm font-medium">
            {t('settings.ai.dataTitle', 'What is sent')}
            <ChevronDown
              className="h-4 w-4 text-muted-foreground transition-transform group-data-[state=open]:rotate-180"
              aria-hidden
            />
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-2 px-3 pb-3 text-sm text-muted-foreground">
            <p>
              {t(
                'settings.ai.dataSent',
                'For each analysis: the finding’s title, description, severity and score, source and tool, file path and code snippet, CVE, CWE and OWASP ids, and whether the asset is internet-facing. Detected secrets are masked before they are stored.'
              )}
            </p>
            <p>
              {t(
                'settings.ai.dataPolicy',
                'Pentest findings follow your AI data policy: a campaign above your TLP limit for AI (Settings > AI assistants (MCP), Policy), or with AI turned off by its lead, is never sent.'
              )}
            </p>
          </CollapsibleContent>
        </Collapsible>
      </CardContent>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={t('settings.ai.confirmTitle', 'Turn on AI triage?')}
        desc={
          settings?.source === 'own'
            ? t(
                'settings.ai.confirmDescOwn',
                'Finding content (see "What is sent") will be sent to the AI provider your organization set up, each time a member asks for an analysis. You can turn it off at any time.'
              )
            : t(
                'settings.ai.confirmDesc',
                'Finding content (see "What is sent") will be sent to the AI provider your platform administrator set up, each time a member asks for an analysis. You can turn it off at any time.'
              )
        }
        confirmText={t('settings.ai.confirm', 'Turn on')}
        handleConfirm={async () => {
          await save(true)
          setConfirmOpen(false)
        }}
      />
    </Card>
  )
}
