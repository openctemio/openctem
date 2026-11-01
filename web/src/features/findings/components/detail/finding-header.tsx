'use client'

/**
 * The finding page's header: what it is (type, CVE / CWE, title) and what you
 * can do with it. Status, severity, assignee and dates live in the properties
 * rail (finding-properties.tsx), not here, so the header stays one short block.
 *
 *   [KEV] [SCA] [CVE-2024-21538 ↗] [CWE-1333]   (KEV only when CISA lists the CVE)
 *   cross-spawn ReDoS vulnerability
 *   [Re-verify] [Add to task] [AI triage] [⋯]
 *
 * Verifying a fix is the Retest section's job (RFC-039): it re-runs the check
 * that found the issue. The old whole-asset "verification scan" is retired.
 */

import { CveLink } from '@/features/vulnerabilities/components/cve-link'
import { useState } from 'react'
import { ConfirmDialog } from '@/components/confirm-dialog'
import Link from '@/components/link'
import { useRouter } from 'next/navigation'
import {
  Copy,
  ExternalLink,
  Link2,
  Loader2,
  MoreHorizontal,
  ListPlus,
  ShieldCheck,
  Ticket,
} from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { BranchOnlyBadge } from '../branch-only-badge'
import { ExploitSignals } from '../exploit-signals'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { copyToClipboard } from '@/lib/clipboard'
import { safeHref } from '@/lib/safe-href'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions } from '@/context/permission-provider'
import { useCanMutate } from '@/lib/permissions'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { AddFindingsToTaskDialog } from '@/features/remediation-hub/components/add-findings-to-task-dialog'
import { AITriageButton } from '@/features/ai-triage/components'
import { isNoValidationSensorError, useRequestValidationApi } from '../../api/use-findings-api'
import type { FindingDetail, FindingStatus } from '../../types'
import { FINDING_TYPE_CONFIG } from '../../types'
import { CreateTicketDialog } from '../create-ticket-dialog'
import { useCanCreateTicket } from '../../hooks/use-can-create-ticket'
import { MarkDuplicateDialog } from '../mark-duplicate-dialog'
import { findingSourceLabel, HUMAN_SOURCES } from '../../lib/finding-detail'
import { shareableLink } from '@/lib/org-link'

interface FindingHeaderProps {
  finding: FindingDetail
  /** The live status (from the triage state). */
  status: FindingStatus
  onTriageCompleted?: () => void
}

export function FindingHeader({ finding, status, onTriageCompleted }: FindingHeaderProps) {
  const { t } = useTranslation()
  const isHuman = HUMAN_SOURCES.has(finding.source)
  const { hasPermission } = usePermissions()
  const router = useRouter()
  // Re-verify dispatches the reachability check (POST /validate): findings:verify.
  const canVerify = hasPermission('findings:verify')
  const canCreateTicket = useCanCreateTicket()
  // Adding to a task needs the task write permission and the remediation module.
  const canCreateTask = useCanMutate('POST /api/v1/remediation/tasks')
  const remediationEnabled = useModuleEnabled('remediation')
  const canAddToTask = canCreateTask && remediationEnabled
  const [taskOpen, setTaskOpen] = useState(false)
  const [ticketOpen, setTicketOpen] = useState(false)
  const [duplicateOpen, setDuplicateOpen] = useState(false)
  const [reverifyOpen, setReverifyOpen] = useState(false)
  // An inventory asset (not a free-text pentest target) the duplicate must share.
  const assetId = isHuman ? undefined : finding.assets[0]?.id
  const canMarkDuplicate =
    hasPermission('findings:triage') && !!assetId && status !== 'duplicate' && !finding.duplicateOf
  const duplicateOfHref = finding.duplicateOf
    ? safeHref(`/findings/${encodeURIComponent(finding.duplicateOf)}`)
    : undefined

  const { trigger: requestValidation, isMutating: reverifying } = useRequestValidationApi(
    finding.id
  )

  const reverify = async () => {
    setReverifyOpen(false)
    try {
      await requestValidation()
      toast.success(t('findings.header.reverifyQueued', 'Re-verification queued'), {
        description: t(
          'findings.header.reverifyQueuedDesc',
          'The result is recorded as evidence. A reachability check never changes the status; use Retest to confirm a fix.'
        ),
      })
    } catch (error) {
      if (isNoValidationSensorError(error)) {
        toast.error(t('findings.header.noSensor', 'No validation sensor is online'), {
          description: t(
            'findings.header.noSensorDesc',
            'Deploy a validation sensor to run re-verification.'
          ),
        })
        return
      }
      toast.error(
        getErrorMessage(
          error,
          t('findings.header.reverifyFailed', 'Failed to queue re-verification')
        )
      )
    }
  }

  const typeCfg =
    finding.findingType && finding.findingType !== 'vulnerability'
      ? FINDING_TYPE_CONFIG[finding.findingType]
      : undefined
  const cweNum = finding.cwe?.replace(/^CWE-/i, '')

  return (
    <header className="min-w-0" data-slot="finding-header">
      <div className="flex flex-wrap items-center gap-1.5">
        {finding.isInKev && (
          <ExploitSignals
            isInKev
            kevDueDate={finding.kevDueDate}
            kevRansomware={finding.kevRansomware}
          />
        )}
        <Badge variant="outline" className="text-xs">
          {findingSourceLabel(finding.source)}
        </Badge>
        {typeCfg && (
          <Badge variant="outline" className="text-xs">
            {typeCfg.label}
          </Badge>
        )}
        {finding.branchOnly && <BranchOnlyBadge />}
        {finding.cve && (
          <Badge variant="outline" className="text-xs">
            <CveLink id={finding.cve} />
          </Badge>
        )}
        {duplicateOfHref && (
          <Badge variant="secondary" asChild className="text-xs">
            <Link href={duplicateOfHref} data-slot="duplicate-of">
              <Copy className="h-3 w-3" aria-hidden />
              {t('findings.header.duplicateOf', 'Duplicate of another finding')}
            </Link>
          </Badge>
        )}
        {finding.cwe && cweNum && (
          <Badge variant="outline" asChild className="font-mono text-xs">
            <a
              href={`https://cwe.mitre.org/data/definitions/${encodeURIComponent(cweNum)}.html`}
              target="_blank"
              rel="noopener noreferrer"
              aria-label={`${t('findings.header.cweOnMitre', '{cwe} on MITRE', { cwe: finding.cwe })} ${t('common.opensNewTab', '(opens in a new tab)')}`}
            >
              {finding.cwe}
              <ExternalLink className="h-3 w-3" aria-hidden />
            </a>
          </Badge>
        )}
      </div>

      <h1 className="mt-2 text-xl leading-snug font-semibold tracking-tight break-words sm:text-2xl">
        {finding.title}
      </h1>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {!isHuman && canVerify && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setReverifyOpen(true)}
            disabled={reverifying}
            title={t(
              'findings.header.reverifyTitle',
              'Re-run a safe check to confirm the finding is still present'
            )}
          >
            {reverifying ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <ShieldCheck className="h-3.5 w-3.5" />
            )}
            {t('findings.header.reverify', 'Re-verify')}
          </Button>
        )}
        {canAddToTask && (
          <Button variant="outline" size="sm" onClick={() => setTaskOpen(true)}>
            <ListPlus className="h-3.5 w-3.5" aria-hidden />
            {t('remediationClaim.add.addToTask', 'Add to task')}
          </Button>
        )}
        <AITriageButton
          findingId={finding.id}
          variant="ai"
          size="sm"
          onTriageCompleted={onTriageCompleted}
        />
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="size-8"
              aria-label={t('findings.header.moreActions', 'More actions')}
            >
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-52">
            <DropdownMenuItem
              onClick={async () => {
                const ok = await copyToClipboard(shareableLink(`/findings/${finding.id}`))
                if (ok) toast.success(t('findings.header.linkCopied', 'Link copied'))
                else toast.error(t('common.copyFailed', 'Could not copy'))
              }}
            >
              <Link2 className="h-4 w-4" />
              {t('findings.header.copyLink', 'Copy link')}
            </DropdownMenuItem>
            {canCreateTicket && (
              <DropdownMenuItem onClick={() => setTicketOpen(true)}>
                <Ticket className="h-4 w-4" />
                {t('findings.header.createTicket', 'Create ticket')}
              </DropdownMenuItem>
            )}
            {canMarkDuplicate && (
              <DropdownMenuItem onClick={() => setDuplicateOpen(true)}>
                <Copy className="h-4 w-4" />
                {t('findings.header.markDuplicate', 'Mark as duplicate')}
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <ConfirmDialog
        open={reverifyOpen}
        onOpenChange={setReverifyOpen}
        title={t('findings.header.reverifyConfirmTitle', 'Re-verify "{title}" now?', {
          title: finding.title,
        })}
        desc={t(
          'findings.header.reverifyConfirmDesc',
          "A safe check sends a request to the finding's target now. The result is recorded as evidence and never changes the status."
        )}
        confirmText={t('findings.header.reverifyConfirmButton', 'Run safe check')}
        handleConfirm={reverify}
      />

      {canMarkDuplicate && assetId && (
        <MarkDuplicateDialog
          findingId={finding.id}
          assetId={assetId}
          open={duplicateOpen}
          onOpenChange={setDuplicateOpen}
          onMarked={(canonicalId) => router.push(`/findings/${encodeURIComponent(canonicalId)}`)}
        />
      )}

      {canAddToTask && taskOpen && (
        <AddFindingsToTaskDialog
          open
          onOpenChange={(open) => {
            if (!open) setTaskOpen(false)
          }}
          findings={[{ id: finding.id, title: finding.title }]}
        />
      )}

      {canCreateTicket && (
        <CreateTicketDialog
          findingId={finding.id}
          findingTitle={finding.title}
          open={ticketOpen}
          onOpenChange={setTicketOpen}
        />
      )}
    </header>
  )
}
