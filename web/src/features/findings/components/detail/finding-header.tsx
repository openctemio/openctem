'use client'

/**
 * The finding page's header: what it is (type, CVE / CWE, title) and what you
 * can do with it, on the shared `DetailPageHeader`. Status, severity, assignee,
 * who found it and the dates are rows of the properties list
 * (finding-properties.tsx), not here.
 *
 *   [KEV] [Vulnerability] [CVE-2024-21538] [CWE-1333]          ‹ 2 of 27 ›
 *   cross-spawn ReDoS vulnerability      [More] [Re-verify] [AI triage] [main action]
 *
 * One main action chosen by the finding's state (finding-main-action.tsx: Open
 * the original, Retest now, Mark fix applied, otherwise Add to task), two
 * secondary ones, the rest in More.
 * Verifying a fix is the Retest section's job (RFC-039): it re-runs the check
 * that found the issue.
 */

import { CveLink } from '@/features/vulnerabilities/components/cve-link'
import { useState } from 'react'
import { ConfirmDialog } from '@/components/confirm-dialog'
import Link from '@/components/link'
import { useRouter } from 'next/navigation'
import {
  Bug,
  ClipboardCheck,
  Coins,
  Copy,
  ExternalLink,
  FileText,
  KeyRound,
  Settings2,
  Hash,
  Link2,
  Loader2,
  ShieldCheck,
  Ticket,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { BranchOnlyBadge } from '../branch-only-badge'
import { ExploitSignals } from '../exploit-signals'
import { Button } from '@/components/ui/button'
import type { ActionMenuEntry } from '@/components/ui/action-menu'
import { DetailPageHeader } from '@/features/shared/components/detail'
import { useFindingPosition } from './finding-position'
import { copyToClipboard } from '@/lib/clipboard'
import { safeHref } from '@/lib/safe-href'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions } from '@/context/permission-provider'
import { AITriageButton } from '@/features/ai-triage/components'
import { isNoValidationSensorError, useRequestValidationApi } from '../../api/use-findings-api'
import type { FindingDetail, FindingStatus } from '../../types'
import type { TransitionDecision } from '../../api/use-finding-transitions'
import { FindingMainAction } from './finding-main-action'
import { Tag } from '@/components/ui/tag'
import { CreateTicketDialog } from '../create-ticket-dialog'
import { useCanCreateTicket } from '../../hooks/use-can-create-ticket'
import { MarkDuplicateDialog } from '../mark-duplicate-dialog'
import { findingTypeText, HUMAN_SOURCES } from '../../lib/finding-detail'
import { shareableLink } from '@/lib/org-link'

/** The icon of each finding type: shape, not colour, names the kind. */
const TYPE_ICON: Record<string, LucideIcon> = {
  vulnerability: Bug,
  compliance: ClipboardCheck,
  misconfiguration: Settings2,
  secret: KeyRound,
  license: FileText,
  web3: Coins,
}

interface FindingHeaderProps {
  finding: FindingDetail
  /** The live status (from the triage state). */
  status: FindingStatus
  onTriageCompleted?: () => void
  /** The page's status move, for the "Mark fix applied" main action. */
  onStatusMove?: (status: FindingStatus, move?: TransitionDecision) => void
}

export function FindingHeader({
  finding,
  status,
  onTriageCompleted,
  onStatusMove,
}: FindingHeaderProps) {
  const { t } = useTranslation()
  const isHuman = HUMAN_SOURCES.has(finding.source)
  const { hasPermission } = usePermissions()
  const router = useRouter()
  // Re-verify dispatches the reachability check (POST /validate): findings:verify.
  const canVerify = hasPermission('findings:verify')
  const canCreateTicket = useCanCreateTicket()
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

  const TypeIcon = TYPE_ICON[finding.findingType ?? 'vulnerability'] ?? Bug
  const cweNum = finding.cwe?.replace(/^CWE-/i, '')
  const position = useFindingPosition(finding.id)

  const copy = async (text: string, done: string) => {
    const ok = await copyToClipboard(text)
    if (ok) toast.success(done)
    else toast.error(t('common.copyFailed', 'Could not copy'))
  }
  const menu: ActionMenuEntry[] = [
    {
      id: 'copy-link',
      label: t('findings.header.copyLink', 'Copy link'),
      icon: Link2,
      onSelect: () =>
        void copy(
          shareableLink(`/findings/${finding.id}`),
          t('findings.header.linkCopied', 'Link copied')
        ),
    },
    {
      id: 'copy-id',
      label: t('findings.drawer.copyId', 'Copy finding ID'),
      icon: Hash,
      onSelect: () => void copy(finding.id, t('findings.header.idCopied', 'Finding ID copied')),
    },
  ]
  if (canCreateTicket) {
    menu.push({
      id: 'create-ticket',
      label: t('findings.header.createTicket', 'Create ticket'),
      icon: Ticket,
      section: 'track',
      onSelect: () => setTicketOpen(true),
    })
  }
  if (canMarkDuplicate) {
    menu.push({
      id: 'mark-duplicate',
      label: t('findings.header.markDuplicate', 'Mark as duplicate'),
      icon: Copy,
      section: 'track',
      onSelect: () => setDuplicateOpen(true),
    })
  }

  return (
    <>
      <DetailPageHeader
        title={finding.title}
        parent={{ href: position.listHref, label: position.listLabel }}
        position={position.control}
        menu={menu}
        chips={
          <>
            {finding.isInKev && (
              <ExploitSignals
                isInKev
                kevDueDate={finding.kevDueDate}
                kevRansomware={finding.kevRansomware}
              />
            )}
            <Tag icon={TypeIcon} label={findingTypeText(t, finding.findingType)} />
            {finding.branchOnly && <BranchOnlyBadge />}
            {finding.cve && (
              <Badge variant="outline">
                <CveLink id={finding.cve} />
              </Badge>
            )}
            {duplicateOfHref && (
              <Badge variant="secondary" asChild>
                <Link href={duplicateOfHref} data-slot="duplicate-of">
                  <Copy aria-hidden />
                  {t('findings.header.duplicateOf', 'Duplicate of another finding')}
                </Link>
              </Badge>
            )}
            {finding.cwe && cweNum && (
              <Badge variant="outline" asChild>
                <a
                  href={`https://cwe.mitre.org/data/definitions/${encodeURIComponent(cweNum)}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={`${t('findings.header.cweOnMitre', '{cwe} on MITRE', { cwe: finding.cwe })} ${t('common.opensNewTab', '(opens in a new tab)')}`}
                >
                  <span className="font-mono">{finding.cwe}</span>
                  <ExternalLink aria-hidden />
                </a>
              </Badge>
            )}
          </>
        }
        secondary={
          <>
            {!isHuman && canVerify && (
              <Button
                variant="outline"
                onClick={() => setReverifyOpen(true)}
                disabled={reverifying}
                title={t(
                  'findings.header.reverifyTitle',
                  'Re-run a safe check to confirm the finding is still present'
                )}
              >
                {reverifying ? (
                  <Loader2 className="animate-spin" aria-hidden />
                ) : (
                  <ShieldCheck aria-hidden />
                )}
                {t('findings.header.reverify', 'Re-verify')}
              </Button>
            )}
            <AITriageButton
              findingId={finding.id}
              variant="outline"
              onTriageCompleted={onTriageCompleted}
            />
          </>
        }
        primary={
          <FindingMainAction finding={finding} status={status} onStatusMove={onStatusMove} />
        }
      />

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

      {canCreateTicket && (
        <CreateTicketDialog
          findingId={finding.id}
          findingTitle={finding.title}
          open={ticketOpen}
          onOpenChange={setTicketOpen}
        />
      )}
    </>
  )
}
