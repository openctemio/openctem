'use client'

/**
 * Replace a scope entry's pattern (server/docs/architecture/scope-entry-replace.md).
 *
 * The pattern of an entry never changes in place: a new entry with the new
 * pattern takes its place, through the same checks and approvals as adding
 * an entry, and the old one is kept as replaced. The change (added and
 * removed coverage, whether it needs approval, the scan zones that name the
 * old range) is shown before the click. A scan zone is updated only when the
 * caller ticks it and may change scan zones; the server checks that again.
 */

import { useEffect, useId, useState } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { invalidateScanZonesCache, updateScanZone } from '@/lib/api/scan-zone-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  invalidateScopeCache,
  previewReplaceScopeTarget,
  replaceScopeTarget,
} from '../api/use-scope-api'
import type { ApiScopeReplace, ApiScopeTarget } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'

/** Whether an entry's pattern can be replaced: in effect, not a program or CI trust entry. */
export function canReplacePattern(entry: ApiScopeTarget): boolean {
  return (
    entry.status === 'active' &&
    entry.in_effect === true &&
    entry.authorization_source !== 'program' &&
    !(entry.managed_by && entry.managed_by.length > 0)
  )
}

interface ScopeReplacePatternProps {
  entry: ApiScopeTarget
  /** Called after a replacement was saved. */
  onReplaced: () => void
  /** Whether another save of the dialog is running. */
  disabled?: boolean
}

function CoverageList({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <ul className="space-y-0.5">
        {items.map((it) => (
          <li key={it}>
            <code className="break-all text-xs">{it}</code>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function ScopeReplacePattern({ entry, onReplaced, disabled }: ScopeReplacePatternProps) {
  const { t } = useTranslation()
  const id = useId()
  const canWriteZones = useHasPermission(Permission.ScanZonesWrite)
  const [pattern, setPattern] = useState('')
  const [reason, setReason] = useState('')
  const [preview, setPreview] = useState<ApiScopeReplace | null>(null)
  const [zonePicks, setZonePicks] = useState<Record<string, boolean>>({})
  const [busy, setBusy] = useState<'preview' | 'replace' | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setPattern('')
    setReason('')
    setPreview(null)
    setZonePicks({})
    setError(null)
  }, [entry.id])

  const entryId = entry.id ?? ''
  const input = { pattern: pattern.trim(), reason: reason.trim() }
  const ready = input.pattern !== '' && input.reason !== ''

  const showChange = async () => {
    setBusy('preview')
    setError(null)
    try {
      setPreview(await previewReplaceScopeTarget(entryId, input))
      setZonePicks({})
    } catch (err) {
      setPreview(null)
      setError(
        scopeErrorMessage(t, err, t('scope.replace.errPreview', 'Could not check the new pattern.'))
      )
    } finally {
      setBusy(null)
    }
  }

  const replace = async () => {
    setBusy('replace')
    setError(null)
    try {
      const res = await replaceScopeTarget(entryId, input)
      // A zone changes only when the new entry is in effect, the caller
      // ticked it and may change scan zones (the server checks again).
      const picked = res.old_retired
        ? (res.zones ?? []).filter((z) => zonePicks[z.id ?? ''] && (z.suggested?.length ?? 0) > 0)
        : []
      let zoneFailed = false
      for (const z of picked) {
        try {
          await updateScanZone(z.id ?? '', { ranges: z.suggested ?? [] })
        } catch {
          zoneFailed = true
        }
      }
      await invalidateScopeCache()
      if (picked.length > 0) await invalidateScanZonesCache()
      toast.success(
        res.old_retired
          ? t('scope.replace.done', '{old} replaced by {new}', {
              old: res.old?.pattern ?? '',
              new: res.new?.pattern ?? '',
            })
          : t(
              'scope.replace.donePending',
              '{new} is waiting for approval; {old} stays in effect until then',
              { old: res.old?.pattern ?? '', new: res.new?.pattern ?? '' }
            )
      )
      if (zoneFailed) {
        toast.error(
          t(
            'scope.replace.zoneFailed',
            'The scope entry was replaced, but a scan zone was not updated. Update it in Scan zones.'
          )
        )
      }
      onReplaced()
    } catch (err) {
      setError(
        scopeErrorMessage(t, err, t('scope.replace.errSave', 'The pattern was not replaced.'))
      )
    } finally {
      setBusy(null)
    }
  }

  const change = preview?.change
  const pending = preview?.new?.status === 'pending'
  const zones = preview?.zones ?? []
  const hiddenZones = preview?.zones_hidden ?? 0

  return (
    <section aria-labelledby={`${id}-title`} className="space-y-3 rounded-md border p-3">
      <div className="space-y-1">
        <h3 id={`${id}-title`} className="text-sm font-medium">
          {t('scope.replace.title', 'Replace pattern')}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t(
            'scope.replace.intro',
            'A new entry with the new pattern takes this one’s place, with the same checks and approvals as adding an entry. This entry is kept as replaced, with its history.'
          )}
        </p>
      </div>
      {error && (
        <Alert variant="destructive">
          <AlertTriangle />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="space-y-2">
        <Label htmlFor={`${id}-pattern`}>{t('scope.replace.pattern', 'New pattern')}</Label>
        <Input
          id={`${id}-pattern`}
          className="font-mono"
          maxLength={500}
          value={pattern}
          placeholder={entry.pattern}
          onChange={(e) => {
            setPattern(e.target.value)
            setPreview(null)
          }}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor={`${id}-reason`}>
          {t('scope.replace.reason', 'Why the pattern changes')}
        </Label>
        <Textarea
          id={`${id}-reason`}
          rows={2}
          maxLength={1000}
          value={reason}
          onChange={(e) => {
            setReason(e.target.value)
            setPreview(null)
          }}
        />
      </div>

      {preview && change && (
        <div className="space-y-3 rounded-md bg-muted/50 p-3 text-sm" aria-live="polite">
          <div className="grid gap-3 sm:grid-cols-2">
            <CoverageList
              label={
                change.addresses
                  ? t('scope.replace.addedN', 'Added ({n} addresses)', {
                      n: change.added_addresses ?? 0,
                    })
                  : t('scope.replace.added', 'Added')
              }
              items={change.added?.length ? change.added : [t('scope.replace.nothing', 'Nothing')]}
            />
            <CoverageList
              label={
                change.addresses
                  ? t('scope.replace.removedN', 'Removed ({n} addresses)', {
                      n: change.removed_addresses ?? 0,
                    })
                  : t('scope.replace.removed', 'Removed')
              }
              items={
                change.removed?.length ? change.removed : [t('scope.replace.nothing', 'Nothing')]
              }
            />
          </div>
          <p>
            {pending
              ? t(
                  'scope.replace.needsApproval',
                  'Needs approval: the new entry waits for {n} approval(s), and this entry stays in effect until it is approved.',
                  { n: preview.new?.approvals_required ?? 1 }
                )
              : t(
                  'scope.replace.atOnce',
                  'No approval needed: the new entry takes effect at once and this entry stops authorizing probes.'
                )}{' '}
            {preview.step_up_required &&
              t('scope.replace.stepUp', 'You may be asked to confirm your identity.')}
          </p>
          {zones.map((z) => {
            const canUpdate = canWriteZones && !pending && (z.suggested?.length ?? 0) > 0
            const zid = z.id ?? ''
            return (
              <div key={zid} className="space-y-1">
                <p>
                  {t('scope.replace.zoneUses', 'Scan zone {name} names the old range.', {
                    name: z.name ?? '',
                  })}{' '}
                  {pending
                    ? t(
                        'scope.replace.zoneLater',
                        'Update the zone once the new entry is approved.'
                      )
                    : !canWriteZones
                      ? t(
                          'scope.replace.zoneAsk',
                          'Ask someone who manages scan zones to update it.'
                        )
                      : null}
                </p>
                {canUpdate && (
                  <div className="flex items-start gap-2">
                    <Checkbox
                      id={`${id}-zone-${zid}`}
                      checked={!!zonePicks[zid]}
                      onCheckedChange={(v) => setZonePicks((p) => ({ ...p, [zid]: v === true }))}
                    />
                    <Label htmlFor={`${id}-zone-${zid}`} className="font-normal leading-snug">
                      {t('scope.replace.zoneUpdate', 'Also update the zone to {ranges}', {
                        ranges: (z.suggested ?? []).join(', '),
                      })}
                    </Label>
                  </div>
                )}
              </div>
            )
          })}
          {hiddenZones > 0 && (
            <p>
              {t(
                'scope.replace.zonesHidden',
                '{n} scan zone(s) name the old range. Ask someone who manages scan zones to update them.',
                { n: hiddenZones }
              )}
            </p>
          )}
        </div>
      )}

      <div className="flex flex-wrap justify-end gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={() => void showChange()}
          disabled={!ready || busy !== null || disabled}
        >
          {busy === 'preview' && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
          {t('scope.replace.check', 'Show the change')}
        </Button>
        <Button
          type="button"
          onClick={() => void replace()}
          disabled={!preview || !ready || busy !== null || disabled}
        >
          {busy === 'replace' && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
          {t('scope.replace.confirm', 'Replace pattern')}
        </Button>
      </div>
    </section>
  )
}
