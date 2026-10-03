'use client'

/**
 * The finding page's header: what it is (type, CVE / CWE, title) and what you
 * can do with it. Status, severity, assignee and dates live in the properties
 * rail (finding-properties.tsx), not here, so the header stays one short block.
 *
 *   [SCA] [CVE-2024-21538 ↗] [CWE-1333]
 *   cross-spawn ReDoS vulnerability
 *   [Re-verify] [AI triage] [⋯]
 *
 * Verifying a fix is the Retest section's job (RFC-039): it re-runs the check
 * that found the issue. The old whole-asset "verification scan" is retired.
 */

import { useState } from 'react'
import { ExternalLink, Link2, Loader2, MoreHorizontal, ShieldCheck, Ticket } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { copyToClipboard } from '@/lib/clipboard'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions } from '@/context/permission-provider'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { AITriageButton } from '@/features/ai-triage/components'
import { isNoValidationSensorError, useRequestValidationApi } from '../../api/use-findings-api'
import type { FindingDetail, FindingStatus } from '../../types'
import { FINDING_TYPE_CONFIG } from '../../types'
import { CreateTicketDialog } from '../create-ticket-dialog'
import { findingSourceLabel, HUMAN_SOURCES } from '../../lib/finding-detail'

interface FindingHeaderProps {
  finding: FindingDetail
  /** The live status (from the triage state). */
  status: FindingStatus
  onTriageCompleted?: () => void
}

export function FindingHeader({ finding, onTriageCompleted }: FindingHeaderProps) {
  const isHuman = HUMAN_SOURCES.has(finding.source)
  const { hasPermission } = usePermissions()
  const canWrite = hasPermission('findings:write')
  const integrationsEnabled = useModuleEnabled('integrations')
  const [ticketOpen, setTicketOpen] = useState(false)

  const { trigger: requestValidation, isMutating: reverifying } = useRequestValidationApi(
    finding.id
  )

  const reverify = async () => {
    try {
      await requestValidation()
      toast.success('Re-verification queued', {
        description:
          'The result is recorded as evidence. A reachability check never changes the status; use Retest to confirm a fix.',
      })
    } catch (error) {
      if (isNoValidationSensorError(error)) {
        toast.error('No validation sensor is online', {
          description: 'Deploy a validation sensor to run re-verification.',
        })
        return
      }
      toast.error(getErrorMessage(error, 'Failed to queue re-verification'))
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
        <Badge variant="outline" className="text-xs">
          {findingSourceLabel(finding.source)}
        </Badge>
        {typeCfg && (
          <Badge variant="outline" className="text-xs">
            {typeCfg.label}
          </Badge>
        )}
        {finding.cve && (
          <Badge variant="outline" asChild className="font-mono text-xs">
            <a
              href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(finding.cve)}`}
              target="_blank"
              rel="noopener noreferrer"
              aria-label={`${finding.cve} on NVD`}
            >
              {finding.cve}
              <ExternalLink className="h-3 w-3" aria-hidden />
            </a>
          </Badge>
        )}
        {finding.cwe && cweNum && (
          <Badge variant="outline" asChild className="font-mono text-xs">
            <a
              href={`https://cwe.mitre.org/data/definitions/${encodeURIComponent(cweNum)}.html`}
              target="_blank"
              rel="noopener noreferrer"
              aria-label={`${finding.cwe} on MITRE`}
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
        {!isHuman && canWrite && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => void reverify()}
            disabled={reverifying}
            title="Re-run a safe check to confirm the finding is still present"
          >
            {reverifying ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <ShieldCheck className="h-3.5 w-3.5" />
            )}
            Re-verify
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
            <Button variant="ghost" size="icon" className="size-8" aria-label="More actions">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-52">
            <DropdownMenuItem
              onClick={() => {
                void copyToClipboard(`${window.location.origin}/findings/${finding.id}`)
                toast.success('Link copied')
              }}
            >
              <Link2 className="h-4 w-4" />
              Copy link
            </DropdownMenuItem>
            {integrationsEnabled && canWrite && (
              <DropdownMenuItem onClick={() => setTicketOpen(true)}>
                <Ticket className="h-4 w-4" />
                Create ticket
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {integrationsEnabled && (
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
