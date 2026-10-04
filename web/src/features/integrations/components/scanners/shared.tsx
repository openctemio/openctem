'use client'

/**
 * Parts shared by the Tenable connector view and the paused scanner-imports
 * view of Settings > Integrations > Vulnerability scanners.
 */

import { useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import type {
  Integration,
  IntegrationStatus,
} from '@/features/integrations/types/integration.types'
import { csrfFetch } from '@/lib/api/client'
import { toast } from 'sonner'

export function getConfigString(integration: Integration, key: string): string {
  const config = integration.config as Record<string, unknown> | undefined
  return (config?.[key] as string) ?? ''
}

export function StatusBadge({ status }: { status: IntegrationStatus }) {
  const config: Record<string, { className: string; label: string }> = {
    connected: {
      className: 'bg-success/10 text-success border-success/20',
      label: 'Connected',
    },
    disconnected: { className: 'bg-muted text-muted-foreground', label: 'Not Connected' },
    error: {
      className: 'bg-destructive/10 text-destructive border-destructive/20',
      label: 'Error',
    },
    pending: {
      className: 'bg-warning/10 text-warning border-warning/20',
      label: 'Pending',
    },
    expired: {
      className: 'bg-warning/15 text-warning border-warning/30',
      label: 'Expired',
    },
    disabled: { className: 'bg-muted text-muted-foreground', label: 'Disabled' },
  }
  const { className, label } = config[status] ?? config.disconnected
  return (
    <Badge variant="outline" className={className}>
      {label}
    </Badge>
  )
}

// ─────────────────────────────────────────────────────────
// Import .nessus results
// ─────────────────────────────────────────────────────────

export function ImportResultsDialog({
  open,
  onOpenChange,
  onSuccess,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess: () => void
}) {
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)

  async function handleUpload() {
    if (!file) return toast.error('Choose a .nessus file')
    setBusy(true)
    try {
      const text = await file.text()
      const res = await csrfFetch(
        '/api/v1/assets/import/nessus-findings?tool=tenable&min_severity=1',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/xml' },
          body: text,
        }
      )
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = (await res.json()) as { result?: Record<string, number> }
      const r = data.result ?? {}
      toast.success(
        `Imported: ${r.assets_created ?? 0} assets, ${r.findings_created ?? 0} findings`
      )
      onSuccess()
      onOpenChange(false)
      setFile(null)
    } catch {
      toast.error('Import failed — check the .nessus file')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Import .nessus results</DialogTitle>
          <DialogDescription>
            Upload a Nessus/Tenable export. Hosts become assets and vulnerabilities become findings;
            stale Tenable findings on the uploaded hosts are auto-resolved.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <Input
            type="file"
            accept=".nessus,.xml,text/xml,application/xml"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
          <p className="text-muted-foreground text-xs">
            Tip: export with all scanned hosts included so clean hosts also auto-resolve.
          </p>
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleUpload} disabled={busy || !file}>
            {busy ? 'Importing...' : 'Import'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
