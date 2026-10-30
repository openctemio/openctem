'use client'

/**
 * The edge label (research/259 edge addresses; owner decision 2026-10-30 in
 * research/274): one chip for a CDN, edge, hosting or cloud-shared address,
 * and for a name or service served through one. The platform never refuses
 * these by itself; the organization decides. On an address (an IP asset, an
 * address or range scope entry) a person with scope write can add it to out
 * of scope from the chip: a confirm dialog explains why and shows what the
 * exclusion also stops, then the ordinary bulk exclusion (scope write,
 * audited, the Strict approval rule) adds it. An exclusion of an address
 * also leaves out the names that resolve to it (the dispatch gate matches an
 * asset's addresses), and the dialog says so. The API computes the label
 * (`edge` on assets and scope entries); this only shows it.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { createExclusions, type ExclusionItem } from '@/features/assets/api/triage-api'
import { FactChip, factChipBase } from '@/features/assets/components/service-cells/fact-chip'
import type { AssetEdge } from '@/features/assets/types/asset.types'

/** The exclusion an edge address takes: an address, else a range or CIDR. */
export function edgeExclusionItem(address: string): ExclusionItem {
  const a = address.trim()
  if (a.includes('/')) return { exclusion_type: 'cidr', pattern: a }
  if (a.includes('-')) return { exclusion_type: 'ip_range', pattern: a }
  return { exclusion_type: 'ip_address', pattern: a }
}

interface EdgeLabelProps {
  edge: AssetEdge
  /** The address is already out of scope: the label only, no action. */
  excluded?: boolean
  /** After the exclusion was added (refresh the list). */
  onExcluded?: () => void
}

export function EdgeLabel({ edge, excluded, onExcluded }: EdgeLabelProps) {
  const { t } = useTranslation()
  const provider = edge.provider
  if (!edge.address) {
    return (
      <EdgeChipView
        text={t('assets.facts.behind', 'Behind {provider}', { provider })}
        hint={t(
          'assets.facts.behindHint',
          "Served through {provider}'s edge: its addresses belong to {provider}, not to this service.",
          { provider }
        )}
      />
    )
  }
  return (
    <EdgeAddressLabel
      edge={edge}
      address={edge.address}
      excluded={excluded}
      onExcluded={onExcluded}
    />
  )
}

/** The chip alone, with its explanation on hover and focus. */
function EdgeChipView({ text, hint }: { text: string; hint: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <FactChip tone="muted" data-slot="edge-chip">
          <span className="max-w-[10rem] truncate">{text}</span>
        </FactChip>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        {hint}
      </TooltipContent>
    </Tooltip>
  )
}

/** The provider's own address: the chip opens "Add to out of scope". */
function EdgeAddressLabel({
  edge,
  address,
  excluded,
  onExcluded,
}: EdgeLabelProps & { address: string }) {
  const { t } = useTranslation()
  const canExclude = useHasPermission(Permission.ScopeWrite)
  const [open, setOpen] = useState(false)
  const provider = edge.provider
  const text =
    edge.class === 'saas_hosting'
      ? t('assets.facts.edgeHosting', '{provider} hosting', { provider })
      : edge.class === 'cloud_shared'
        ? t('assets.facts.edgeShared', '{provider} shared', { provider })
        : t('assets.facts.edgeAddress', '{provider} edge', { provider })
  const hint = t(
    'assets.facts.edgeAddressHint',
    'This address belongs to {provider} and serves many organizations. Scanning it tests {provider}, not you. Add it to out of scope to stop every scan of it.',
    { provider }
  )
  if (!canExclude || excluded) return <EdgeChipView text={text} hint={hint} />

  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            data-slot="edge-chip"
            aria-haspopup="dialog"
            aria-label={t('assets.facts.edgeExcludeAria', '{label}: add to out of scope', {
              label: text,
            })}
            className={cn(
              factChipBase,
              'border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring'
            )}
            // A table row opens its drawer on click: the chip acts alone.
            onClick={(e) => {
              e.stopPropagation()
              setOpen(true)
            }}
            onKeyDown={(e) => e.stopPropagation()}
          >
            <span className="max-w-[10rem] truncate">{text}</span>
          </button>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs">
          {hint}
        </TooltipContent>
      </Tooltip>
      <EdgeExcludeDialog
        open={open}
        onOpenChange={setOpen}
        address={address}
        provider={provider}
        onExcluded={onExcluded}
      />
    </>
  )
}

interface DialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  address: string
  provider: string
  onExcluded?: () => void
}

/** Confirm, then add one edge address to out of scope (Do not scan). */
export function EdgeExcludeDialog({
  open,
  onOpenChange,
  address,
  provider,
  onExcluded,
}: DialogProps) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      const res = await createExclusions([edgeExclusionItem(address)], {
        kind: 'do_not_scan',
        reason: t(
          'scope.edge.reason',
          'Shared {provider} address: scanning it tests the provider',
          {
            provider,
          }
        ),
      })
      const r = res.results?.[0]
      if (r?.result === 'refused') {
        toast.error(r.message || t('scope.edge.refused', 'The exclusion was refused'))
        return
      }
      if (r?.result === 'exists') {
        toast.success(t('scope.edge.exists', '{address} is already out of scope', { address }))
      } else if (r?.status === 'pending') {
        toast.success(
          t(
            'scope.edge.pending',
            '{address} waits for an exclusion approver before scans leave it out',
            { address }
          )
        )
      } else {
        toast.success(
          t('scope.edge.done', '{address} is out of scope: no scan will reach it', { address })
        )
      }
      onOpenChange(false)
      onExcluded?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('scope.edge.failed', 'Could not add it to out of scope')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size="md" onClick={(e) => e.stopPropagation()}>
        <DialogHeader>
          <DialogTitle>
            {t('scope.edge.title', 'Add {address} to out of scope?', { address })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'scope.edge.why',
              '{address} belongs to {provider} and serves many organizations. Scanning it tests {provider}, not your systems, and can break their terms of service.',
              { address, provider }
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-3 text-sm">
          <p>
            {t(
              'scope.edge.effect',
              'From now on no scan, retest or coverage run reaches this address. It stays in the inventory with its history, and you can re-include it on Scoping, Out of scope.'
            )}
          </p>
          <p className="text-muted-foreground" data-testid="edge-exclude-names">
            {t(
              'scope.edge.alsoNames',
              'Names that resolve to this address are left out of scans as well while they resolve to it: a scan of the name would reach the address. Re-include the address to scan them again.'
            )}
          </p>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={busy}>
            {t('scope.edge.confirm', 'Add to out of scope')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
