'use client'

/**
 * Settings > Finding approvals: how the organization governs false-positive
 * and accepted-risk decisions (api/docs/architecture/finding-status-lifecycle.md).
 * Saving needs settings:write and a recent sign-in (the API client asks for
 * re-authentication); every change is audited and the approvers are told.
 */

import { useEffect, useId, useState } from 'react'
import { Loader2, Save } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  updateFindingApprovalSettings,
  type FindingApprovalSettings,
} from '../api/use-findings-api'

interface FindingApprovalSettingsFormProps {
  settings: FindingApprovalSettings
  canEdit: boolean
  onSaved?: (next: FindingApprovalSettings) => void
}

export function FindingApprovalSettingsForm({
  settings,
  canEdit,
  onSaved,
}: FindingApprovalSettingsFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [email, setEmail] = useState(settings.backup_contact_email ?? '')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setEmail(settings.backup_contact_email ?? '')
  }, [settings.backup_contact_email])

  const dirty = email.trim() !== (settings.backup_contact_email ?? '')

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      const next = await updateFindingApprovalSettings({ backup_contact_email: email.trim() })
      toast.success(t('findingApprovals.settings.saved', 'Finding approval settings saved'))
      onSaved?.(next)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('findingApprovals.settings.saveFailed', 'Could not save the settings')
        )
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={save} className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('findingApprovals.settings.backupTitle', 'Backup contact')}
          </CardTitle>
          <CardDescription>
            {t(
              'findingApprovals.settings.backupDescription',
              'An advisor or auditor outside the organization who is emailed whenever its only member approves their own finding request.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <Label htmlFor={`${id}-email`}>
            {t('findingApprovals.settings.backupLabel', 'Email address')}
          </Label>
          <Input
            id={`${id}-email`}
            type="email"
            maxLength={254}
            autoComplete="email"
            placeholder={t('findingApprovals.settings.backupPlaceholder', 'advisor@example.com')}
            value={email}
            disabled={!canEdit}
            onChange={(e) => setEmail(e.target.value)}
            className="max-w-sm"
          />
        </CardContent>
      </Card>
      {canEdit && (
        <div className="flex justify-end">
          <Button type="submit" size="sm" disabled={!dirty || saving}>
            {saving ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
            ) : (
              <Save className="h-4 w-4" aria-hidden />
            )}
            {t('findingApprovals.settings.save', 'Save changes')}
          </Button>
        </div>
      )}
    </form>
  )
}
