'use client'

import { useState } from 'react'
import { AlertTriangle, Sparkles } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Main } from '@/components/layout'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { useAIConfig } from '@/features/ai-triage/api/use-ai-triage-api'
import { updateAISettings, useAISettings } from '@/features/ai-triage/api/use-ai-settings'
import { PageHeader, ReadOnlyNotice } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'
import { useCanMutate } from '@/lib/permissions'

/**
 * Settings > AI: the organization's consent to AI triage (API docs:
 * architecture/ai-triage.md). Until an owner or administrator turns it on, no
 * finding content is sent to an AI provider. Turning it on needs a recent
 * sign-in (the shared client asks for it) and is audited.
 */
export default function AISettingsPage() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const canEdit = useCanMutate('PUT /api/v1/organization/settings/ai')
  const settings = useAISettings(true)
  const config = useAIConfig()
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [saving, setSaving] = useState(false)

  const enabled = settings.data?.enabled === true
  const platformMissing = config.data?.reason === 'platform_not_configured'
  const limit = config.data?.monthlyTokenLimit ?? 0
  const used = config.data?.tokensUsedThisMonth ?? 0

  const save = async (on: boolean) => {
    if (!currentTenant) return
    setSaving(true)
    try {
      const next = await updateAISettings(on)
      await settings.mutate(next, { revalidate: false })
      await config.mutate()
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

  const onToggle = (on: boolean) => {
    if (on) {
      setConfirmOpen(true)
      return
    }
    void save(false)
  }

  const since =
    settings.data?.enabled_by === 'upgrade'
      ? t(
          'settings.ai.sinceUpgrade',
          'On since {date}: your organization used AI triage before this setting existed.',
          { date: formatDateSafe(settings.data?.enabled_at) }
        )
      : t('settings.ai.since', 'On since {date}.', {
          date: formatDateSafe(settings.data?.enabled_at),
        })

  return (
    <Main>
      <PageHeader
        title={t('settings.ai.title', 'AI')}
        description={t(
          'settings.ai.description',
          'Decide whether this organization’s findings may be sent to an AI provider for triage.'
        )}
      />

      <div className="mt-5 space-y-5">
        {!canEdit && (
          <ReadOnlyNotice
            reason={t(
              'settings.ai.readOnly',
              'Only owners and administrators can change this setting.'
            )}
          />
        )}

        {platformMissing && (
          <Alert role="status">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>
              {t('settings.ai.platformMissingTitle', 'No AI provider is set up yet')}
            </AlertTitle>
            <AlertDescription>
              {t(
                'settings.ai.platformMissing',
                'A platform administrator sets up the AI provider in the console (System > AI provider). You can turn AI triage on now; it works once a provider is set up.'
              )}
            </AlertDescription>
          </Alert>
        )}

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
            {settings.isLoading ? (
              <Skeleton className="h-6 w-1/2" />
            ) : settings.error ? (
              <p className="text-sm text-destructive">{getErrorMessage(settings.error)}</p>
            ) : (
              <div className="flex items-start gap-3">
                <Switch
                  id="ai-triage-enabled"
                  checked={enabled}
                  disabled={!canEdit || saving}
                  onCheckedChange={onToggle}
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

            <div className="rounded-md border bg-muted/40 p-3 text-sm">
              <p className="font-medium">{t('settings.ai.dataTitle', 'What is sent')}</p>
              <p className="mt-1 text-muted-foreground">
                {t(
                  'settings.ai.dataSent',
                  'For each analysis: the finding’s title, description, severity and score, source and tool, file path and code snippet, CVE, CWE and OWASP ids, and whether the asset is internet-facing. Detected secrets are masked before they are stored.'
                )}
              </p>
              <p className="mt-2 text-muted-foreground">
                {t(
                  'settings.ai.dataPolicy',
                  'Pentest findings follow your AI data policy: a campaign above your TLP limit for AI (Settings > AI assistants (MCP), Policy), or with AI turned off by its lead, is never sent.'
                )}
              </p>
            </div>

            {config.data?.provider && !platformMissing && (
              <p className="text-sm text-muted-foreground">
                {t('settings.ai.provider', 'Provider: {provider}, model {model}.', {
                  provider: config.data.provider,
                  model: config.data.model || '—',
                })}
              </p>
            )}
            {limit > 0 && (
              <p className="text-sm text-muted-foreground">
                {t('settings.ai.usage', 'This month: {used} of {limit} tokens used.', {
                  used: used.toLocaleString(),
                  limit: limit.toLocaleString(),
                })}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={t('settings.ai.confirmTitle', 'Turn on AI triage?')}
        desc={t(
          'settings.ai.confirmDesc',
          'Finding content (see "What is sent") will be sent to the AI provider your platform administrator set up, each time a member asks for an analysis. You can turn it off at any time.'
        )}
        confirmText={t('settings.ai.confirm', 'Turn on')}
        handleConfirm={async () => {
          await save(true)
          setConfirmOpen(false)
        }}
      />
    </Main>
  )
}
