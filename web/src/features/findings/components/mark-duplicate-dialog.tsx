'use client'

/**
 * Mark a finding as a duplicate of another finding on the same asset
 * (RFC-043). The finding is folded into the one picked here: that one keeps
 * the stronger status and inherits the comments, retests, evidence, tickets
 * and fingerprints; this one stays as a "duplicate" record that links to it.
 *
 * Only findings on the same asset are offered (the API refuses anything else,
 * as well as findings outside the caller's data scope). Merging with a false
 * positive or a risk acceptance also needs findings:approve; the API decides.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { mutate } from 'swr'
import { Loader2, Search } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useFindingsApi, useMarkDuplicateApi } from '../api/use-findings-api'
import type { ApiFinding } from '../api/finding-api.types'
import { FindingStatusBadge } from './finding-status-badge'
import type { FindingStatus } from '../types'

interface MarkDuplicateDialogProps {
  findingId: string
  assetId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Called with the canonical finding's id after a successful merge. */
  onMarked?: (canonicalId: string) => void
}

/** The page size of the candidate list; a search narrows it. */
const CANDIDATE_PAGE = 50

function candidateTitle(f: ApiFinding): string {
  return f.title || f.rule_name || f.message || f.id
}

export function MarkDuplicateDialog({
  findingId,
  assetId,
  open,
  onOpenChange,
  onMarked,
}: MarkDuplicateDialogProps) {
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState('')

  const { data, isLoading } = useFindingsApi(
    {
      asset_id: assetId,
      exclude_statuses: ['duplicate'],
      search: search.trim() || undefined,
      per_page: CANDIDATE_PAGE,
    },
    { enabled: open && !!assetId }
  )
  const candidates = useMemo(
    () => (data?.data ?? []).filter((f) => f.id !== findingId && f.status !== 'duplicate'),
    [data, findingId]
  )

  const { trigger, isMutating } = useMarkDuplicateApi(findingId)

  const close = (next: boolean) => {
    if (!next) {
      setSearch('')
      setSelected('')
    }
    onOpenChange(next)
  }

  async function handleConfirm() {
    if (!selected) return
    try {
      await trigger({ duplicate_of_id: selected })
      toast.success('Marked as duplicate', {
        description: 'Its comments, retests, evidence and tickets moved to the original finding.',
      })
      await mutate((key) => typeof key === 'string' && key.startsWith('/api/v1/findings'))
      close(false)
      onMarked?.(selected)
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to mark the finding as a duplicate'))
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Mark as duplicate</DialogTitle>
          <DialogDescription>
            Pick the original finding on the same asset. This finding is closed as a duplicate of
            it; its comments, retests, evidence and tickets move to the original, which keeps the
            stronger status.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="relative">
            <Search
              className="text-muted-foreground absolute top-1/2 left-2.5 h-4 w-4 -translate-y-1/2"
              aria-hidden
            />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search findings on this asset"
              aria-label="Search findings on this asset"
              className="pl-8"
            />
          </div>

          <div className="max-h-72 overflow-y-auto rounded-md border">
            {isLoading ? (
              <div className="text-muted-foreground flex items-center gap-2 p-4 text-sm">
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                Loading findings
              </div>
            ) : candidates.length === 0 ? (
              <p className="text-muted-foreground p-4 text-sm">
                No other finding on this asset matches.
              </p>
            ) : (
              <RadioGroup
                value={selected}
                onValueChange={setSelected}
                aria-label="Original finding"
                className="gap-0"
              >
                {candidates.map((f) => (
                  <Label
                    key={f.id}
                    htmlFor={`dup-${f.id}`}
                    className="hover:bg-muted/50 flex cursor-pointer items-start gap-3 border-b p-3 font-normal last:border-b-0"
                  >
                    <RadioGroupItem id={`dup-${f.id}`} value={f.id} className="mt-0.5" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">
                        {candidateTitle(f)}
                      </span>
                      <span className="text-muted-foreground mt-0.5 flex flex-wrap items-center gap-2 text-xs">
                        <FindingStatusBadge status={f.status as FindingStatus} />
                        <span>{f.tool_name}</span>
                        {f.file_path && <span className="truncate font-mono">{f.file_path}</span>}
                      </span>
                    </span>
                  </Label>
                ))}
              </RadioGroup>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => close(false)} disabled={isMutating}>
            Cancel
          </Button>
          <Button onClick={() => void handleConfirm()} disabled={!selected || isMutating}>
            {isMutating && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
            Mark as duplicate
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
