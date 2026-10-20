'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ExternalLink } from 'lucide-react'
import { useCreateCampaignTicket } from '@/features/remediation/api/use-remediation-campaigns'
import { getErrorMessage } from '@/lib/api/error-handler'

interface CreateJiraEpicDialogProps {
  /** Campaign id + name; null closes the dialog. */
  campaign: { id: string; name: string } | null
  onOpenChange: (open: boolean) => void
}

/**
 * Creates a Jira epic for a remediation campaign. The backend is idempotent —
 * if the campaign is already linked it returns the existing epic
 * (already_existed=true) rather than opening a duplicate.
 */
export function CreateJiraEpicDialog({ campaign, onOpenChange }: CreateJiraEpicDialogProps) {
  const { t } = useTranslation()
  const [projectKey, setProjectKey] = useState('')
  const { trigger, isMutating } = useCreateCampaignTicket(campaign?.id ?? '')

  const handleCreate = async () => {
    const key = projectKey.trim().toUpperCase()
    if (!key) {
      toast.error(t('remediationCampaigns.jira.keyRequired'))
      return
    }
    try {
      const info = await trigger({ project_key: key })
      if (info?.already_existed) {
        toast.info(
          t('remediationCampaigns.jira.alreadyLinked', undefined, { key: info.issue_key }),
          {
            description: info.issue_url,
          }
        )
      } else {
        toast.success(
          t('remediationCampaigns.jira.created', undefined, { key: info?.issue_key ?? '' }),
          {
            description: info?.issue_url,
          }
        )
      }
      setProjectKey('')
      onOpenChange(false)
    } catch (err) {
      toast.error(getErrorMessage(err, t('remediationCampaigns.jira.failed')))
    }
  }

  // The campaign name renders in bold inside the translated sentence.
  const [descBefore, descAfter = ''] = t('remediationCampaigns.jira.description', undefined, {
    name: '{name}',
  }).split('{name}')

  return (
    <Dialog open={campaign !== null} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ExternalLink className="h-4 w-4" />
            {t('remediationCampaigns.jira.title')}
          </DialogTitle>
          <DialogDescription>
            {descBefore}
            <span className="font-medium">{campaign?.name}</span>
            {descAfter}
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-2">
            <Label htmlFor="jira-project-key">{t('remediationCampaigns.jira.projectKey')}</Label>
            <Input
              id="jira-project-key"
              placeholder="SEC"
              value={projectKey}
              onChange={(e) => setProjectKey(e.target.value)}
              autoComplete="off"
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleCreate()
              }}
            />
            <p className="text-muted-foreground text-xs">{t('remediationCampaigns.jira.hint')}</p>
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isMutating}>
            {t('remediationCampaigns.jira.cancel')}
          </Button>
          <Button onClick={handleCreate} disabled={isMutating || !projectKey.trim()}>
            {isMutating
              ? t('remediationCampaigns.jira.creating')
              : t('remediationCampaigns.jira.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
