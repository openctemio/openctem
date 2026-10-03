'use client'

/**
 * The finding page's header: what it is (type, CVE / CWE, title) and what you
 * can do with it. Status, severity, assignee and dates live in the properties
 * rail (finding-properties.tsx), not here, so the header stays one short block.
 *
 *   [SCA] [CVE-2024-21538 ↗] [CWE-1333]
 *   cross-spawn ReDoS vulnerability
 *   [Re-verify] [AI triage] [⋯]
 */

import { useState } from 'react'
import {
  ExternalLink,
  Link2,
  Loader2,
  MoreHorizontal,
  ScanSearch,
  ShieldCheck,
  Ticket,
} from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
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
import {
  isNoValidationSensorError,
  useRequestValidationApi,
  useRequestVerificationScanApi,
} from '../../api/use-findings-api'
import type { FindingDetail, FindingStatus } from '../../types'
import { FINDING_TYPE_CONFIG } from '../../types'
import { CreateTicketDialog } from '../create-ticket-dialog'
import { findingSourceLabel, HUMAN_SOURCES } from '../../lib/finding-detail'

interface FindingHeaderProps {
  finding: FindingDetail
  /** The live status (from the triage state), to offer "Request verification scan". */
  status: FindingStatus
  onTriageCompleted?: () => void
}

export function FindingHeader({ finding, status, onTriageCompleted }: FindingHeaderProps) {
  const isHuman = HUMAN_SOURCES.has(finding.source)
  const { hasPermission } = usePermissions()
  const canWrite = hasPermission('findings:write')
  const integrationsEnabled = useModuleEnabled('integrations')
  const [ticketOpen, setTicketOpen] = useState(false)
  const [scanOpen, setScanOpen] = useState(false)
  const [scanner, setScanner] = useState('')

  const { trigger: requestValidation, isMutating: reverifying } = useRequestValidationApi(
    finding.id
  )
  const { trigger: requestScan, isMutating: requestingScan } = useRequestVerificationScanApi(
    finding.id
  )

  const reverify = async () => {
    try {
      await requestValidation()
      toast.success('Re-verification queued', {
        description: 'A safe-check validation job was sent to a sensor.',
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

  const triggerScan = async () => {
    if (!scanner.trim()) return
    try {
      const result = await requestScan({ scanner_name: scanner.trim() })
      toast.success(`Verification scan started for ${result.asset_name}`)
      setScanOpen(false)
      setScanner('')
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to start the verification scan'))
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
        {status === 'fix_applied' && !isHuman && canWrite && (
          <Button variant="outline" size="sm" onClick={() => setScanOpen(true)}>
            <ScanSearch className="h-3.5 w-3.5" />
            Verify fix
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
            {!isHuman && canWrite && status !== 'fix_applied' && (
              <DropdownMenuItem onClick={() => setScanOpen(true)}>
                <ScanSearch className="h-4 w-4" />
                Request verification scan
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

      <Dialog open={scanOpen} onOpenChange={setScanOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Request verification scan</DialogTitle>
            <DialogDescription>
              Scan the asset again to check the fix. If the scanner finds the issue again, the
              finding is reopened.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <label htmlFor="verify-scanner" className="text-sm font-medium">
              Scanner
            </label>
            <Input
              id="verify-scanner"
              placeholder="e.g. trivy, semgrep, nuclei"
              value={scanner}
              onChange={(e) => setScanner(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && void triggerScan()}
            />
            {finding.assets[0] && (
              <p className="text-xs text-muted-foreground">
                Asset: <span className="font-medium">{finding.assets[0].name}</span>
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setScanOpen(false)} disabled={requestingScan}>
              Cancel
            </Button>
            <Button onClick={() => void triggerScan()} disabled={requestingScan || !scanner.trim()}>
              {requestingScan && <Loader2 className="h-4 w-4 animate-spin" />}
              Start scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </header>
  )
}
