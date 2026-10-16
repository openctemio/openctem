'use client'

import { useState } from 'react'
import { Clock } from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardContent } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { DetailCallout, ErrorState, SettingsSection } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'
import { usePermissions, Permission } from '@/lib/permissions'
import { putContentSettings, useContentSettings } from '../api'
import { approvalState } from '../lib'

/**
 * Whether installs, updates, rollbacks and uninstalls need a second member's
 * approval. Switching it on is immediate; switching it off waits a day, so a
 * single account cannot turn the check off and install in the same minute.
 */
export function ApprovalSettings() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canEdit = can(Permission.SettingsWrite)
  const settings = useContentSettings()
  const [saving, setSaving] = useState(false)
  const state = approvalState(settings.data)
  const switchId = 'content-require-approval'

  async function change(on: boolean) {
    setSaving(true)
    try {
      const next = await putContentSettings(on)
      await settings.mutate(next, { revalidate: false })
      const s = approvalState(next)
      toast.success(
        s.mode === 'on'
          ? t('contentCatalog.approval.savedOn', 'Approval is required from now on')
          : s.mode === 'switching-off'
            ? t('contentCatalog.approval.savedPending', 'Approval will be switched off in 24 hours')
            : t('contentCatalog.approval.savedOff', 'Approval is off')
      )
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('contentCatalog.error.generic', 'The change was refused.'))
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <SettingsSection
      id="content-approval-heading"
      title={t('contentCatalog.approval.title', 'Approval')}
      description={t(
        'contentCatalog.approval.desc',
        'Ask a second member to approve every install, update, rollback and uninstall.'
      )}
    >
      <Card>
        <CardContent className="space-y-3">
          {settings.error ? (
            <ErrorState
              title={t('contentCatalog.approval.what', 'the approval option')}
              error={settings.error}
              onRetry={() => void settings.mutate()}
            />
          ) : !settings.data ? (
            <Skeleton className="h-10 w-full" />
          ) : (
            <>
              <div className="flex items-center justify-between gap-4">
                <Label htmlFor={switchId} className="flex flex-col items-start gap-0.5">
                  <span>{t('contentCatalog.approval.label', 'Require approval')}</span>
                  <span className="text-xs font-normal text-muted-foreground text-pretty">
                    {t(
                      'contentCatalog.approval.hint',
                      'Turning it on takes effect at once. Turning it off takes effect 24 hours later.'
                    )}
                  </span>
                </Label>
                <Switch
                  id={switchId}
                  checked={state.mode === 'on'}
                  disabled={!canEdit || saving}
                  onCheckedChange={(on) => void change(on)}
                />
              </div>
              {state.mode === 'switching-off' && (
                <DetailCallout
                  tone="warning"
                  icon={Clock}
                  title={t(
                    'contentCatalog.approval.pendingTitle',
                    'Approval will be switched off at {time}',
                    { time: formatDateSafe(state.offAt, 'PPp') }
                  )}
                >
                  {t(
                    'contentCatalog.approval.pendingHint',
                    'Until then every change still needs approval. Turn it back on to cancel.'
                  )}
                </DetailCallout>
              )}
              {!canEdit && (
                <p className="text-xs text-muted-foreground">
                  {t(
                    'contentCatalog.approval.readOnly',
                    'Changing this needs the permission to manage organization settings.'
                  )}
                </p>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </SettingsSection>
  )
}
