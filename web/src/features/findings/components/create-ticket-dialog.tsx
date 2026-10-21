'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useState } from 'react'
import { toast } from 'sonner'
import { mutate } from 'swr'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ExternalLink } from 'lucide-react'
import { useCreateFindingTicketApi } from '../api/use-findings-api'
import { useJiraProjectsApi } from '@/features/integrations/api/use-integrations-api'
import { safeHref } from '@/lib/safe-href'
import { ApiClientError } from '@/lib/api/error-handler'
import { useSeverityLabel } from '@/hooks/use-scale-labels'
import type { SeverityLevel } from '@/lib/severity'

/** The policy a finding is below, from a 409 TICKET_BELOW_THRESHOLD. */
export interface BelowThresholdInfo {
  min_severity?: string
  min_priority_class?: string
  always_kev?: boolean
}

/** Reads a 409 TICKET_BELOW_THRESHOLD answer; null for any other error. */
export function belowThresholdOf(err: unknown): BelowThresholdInfo | null {
  if (!(err instanceof ApiClientError) || err.code !== 'TICKET_BELOW_THRESHOLD') return null
  return (err.details as BelowThresholdInfo | undefined) ?? {}
}

interface CreateTicketDialogProps {
  findingId: string
  findingTitle?: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

/**
 * Create a Jira ticket from a finding. The project is optional — leaving it
 * blank routes the ticket to the tenant's configured default project / routing
 * rules (backend api#207/#209). When the tenant's Jira projects can be listed,
 * a picker is offered; otherwise the operator types a key (or leaves it blank).
 */
export function CreateTicketDialog({
  findingId,
  findingTitle,
  open,
  onOpenChange,
}: CreateTicketDialogProps) {
  const { t } = useTranslation()
  const [projectKey, setProjectKey] = useState('')
  const [issueType, setIssueType] = useState('')
  const [below, setBelow] = useState<BelowThresholdInfo | null>(null)
  const severityLabel = useSeverityLabel()

  const { trigger, isMutating } = useCreateFindingTicketApi(findingId)
  const { data: projectsData } = useJiraProjectsApi(open)
  const projects = projectsData?.projects ?? []

  async function handleCreate() {
    try {
      const info = await trigger({
        project_key: projectKey.trim() || undefined,
        issue_type: issueType.trim() || undefined,
        confirm_below_threshold: below ? true : undefined,
      })
      // Only offer "Open" for a real http(s) ticket URL (guard against a
      // javascript:/data: URL slipping through to window.open).
      const safeUrl = safeHref(info.ticket_url, { allowRelative: false })
      toast.success(t('findings.createTicket.created', 'Created {key}', { key: info.ticket_key }), {
        description: t('findings.createTicket.linked', 'Jira ticket linked to this finding.'),
        action: safeUrl
          ? {
              label: t('findings.createTicket.open', 'Open'),
              onClick: () => window.open(safeUrl, '_blank', 'noopener,noreferrer'),
            }
          : undefined,
      })
      // Refresh the finding so its linked work items show the new ticket.
      await mutate((key) => typeof key === 'string' && key.includes(`/findings/${findingId}`))
      onOpenChange(false)
      setProjectKey('')
      setIssueType('')
      setBelow(null)
    } catch (err) {
      const policy = belowThresholdOf(err)
      if (policy && !below) {
        // Ask once: the finding is below the integration's create policy.
        setBelow(policy)
        return
      }
      const message =
        err instanceof Error
          ? err.message
          : t('findings.createTicket.failed', 'Failed to create ticket')
      // Match the backend's specific "no destination project" validation, not any
      // error that merely contains the word "project" (e.g. "project not found",
      // permission errors) — those should surface their real message.
      const noProject = /no default project|project_key is required/i.test(message)
      toast.error(t('findings.createTicket.couldNot', 'Could not create ticket'), {
        description: noProject
          ? t(
              'findings.createTicket.noProject',
              'No project specified and no default project is configured. Set a default project under Settings → Integrations → Ticketing, or enter a project key here.'
            )
          : message,
      })
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) setBelow(null)
        onOpenChange(o)
      }}
    >
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('findings.createTicket.title', 'Create Jira ticket')}</DialogTitle>
          <DialogDescription>
            {findingTitle
              ? t(
                  'findings.createTicket.descriptionTitled',
                  'Create and link a Jira ticket for "{title}".',
                  {
                    title: findingTitle,
                  }
                )
              : t(
                  'findings.createTicket.description',
                  'Create and link a Jira ticket for this finding.'
                )}
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4">
            {below && (
              <div
                role="alert"
                className="rounded-md border border-warning/40 bg-warning/10 p-3 text-sm"
              >
                <p className="font-medium">
                  {t('findings.createTicket.belowTitle', 'Below the create policy')}
                </p>
                <p className="text-muted-foreground mt-1">
                  {below.min_priority_class
                    ? t(
                        'findings.createTicket.belowDescClass',
                        'Automations only create issues for findings of {severity} or above, or priority {cls} or above. Create this one anyway? This is recorded in the audit log.',
                        {
                          severity: severityLabel(
                            (below.min_severity ?? 'medium') as SeverityLevel
                          ),
                          cls: below.min_priority_class,
                        }
                      )
                    : t(
                        'findings.createTicket.belowDesc',
                        'Automations only create issues for findings of {severity} or above. Create this one anyway? This is recorded in the audit log.',
                        {
                          severity: severityLabel(
                            (below.min_severity ?? 'medium') as SeverityLevel
                          ),
                        }
                      )}
                </p>
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="ticket-project">
                {t('findings.createTicket.project', 'Project')}
              </Label>
              {projects.length > 0 && (
                <Select value={projectKey || undefined} onValueChange={setProjectKey}>
                  <SelectTrigger id="ticket-project-picker">
                    <SelectValue
                      placeholder={t('findings.createTicket.useDefault', 'Use default project')}
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {projects.map((p) => (
                      <SelectItem key={p.id} value={p.key}>
                        {p.key} — {p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
              <Input
                id="ticket-project"
                value={projectKey}
                onChange={(e) => setProjectKey(e.target.value.toUpperCase())}
                placeholder={t(
                  'findings.createTicket.blankPlaceholder',
                  'Leave blank to use the default project'
                )}
              />
              <p className="text-muted-foreground text-xs">
                {t(
                  'findings.createTicket.blankHint',
                  'Leave blank to route by your configured default project / routing rules.'
                )}
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="ticket-issue-type">
                {t('findings.createTicket.issueType', 'Issue type (optional)')}
              </Label>
              <Input
                id="ticket-issue-type"
                value={issueType}
                onChange={(e) => setIssueType(e.target.value)}
                placeholder={t('findings.createTicket.issueTypePlaceholder', 'e.g. Bug')}
              />
            </div>
          </div>
        </DialogBody>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button type="button" onClick={handleCreate} disabled={isMutating}>
            <ExternalLink className="me-2 h-4 w-4" />
            {isMutating
              ? t('findings.createTicket.creating', 'Creating...')
              : below
                ? t('findings.createTicket.createAnyway', 'Create anyway')
                : t('findings.createTicket.submit', 'Create ticket')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
