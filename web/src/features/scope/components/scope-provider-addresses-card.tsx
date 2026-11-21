'use client'

/**
 * Scope entries on provider shared addresses (server
 * docs/architecture/provider-shared-addresses.md): addresses, CIDRs and
 * ranges that lie inside a range a provider publishes for infrastructure
 * many organizations share. Shown above the entries list only while there is
 * something to decide: one row per provider with one main action, "Move to
 * out of scope" (previewed, then each entry becomes an exclusion and is
 * turned off; names that point at the addresses stay in scope), and "Keep
 * scanning" (the client asks the person to confirm their identity). Addresses
 * a person confirmed as the organization's are listed under their provider to
 * keep or move one by one. The API decides who may act; without scope:write
 * the actions are hidden.
 */

import { useState } from 'react'
import { Pause, Server } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { ConfirmDialog, type ConfirmPreview } from '@/components/confirm-dialog'
import { RelativeTime } from '@/features/shared'
import { assetDetailHref, isLinkableAssetId } from '@/features/findings/lib/asset-link'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  invalidateScopeCache,
  keepScopeProviderAddresses,
  moveScopeProviderAddresses,
  useScopeProviderAddresses,
} from '../api/use-scope-api'
import type { ApiScopeProviderGroup } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'

/** Entries listed under "Show entries" before "and N more". */
const SHOWN_ENTRIES = 50

export function ScopeProviderAddressesCard() {
  const { t } = useTranslation()
  const { data, mutate } = useScopeProviderAddresses()
  const groups = (data?.groups ?? []).filter((g) => g.entry_count > 0 || g.confirmed.length > 0)
  if (groups.length === 0) return null
  const refresh = async () => {
    await mutate()
    await invalidateScopeCache()
  }
  return (
    <section
      aria-label={t('scope.providers.aria', 'Shared provider addresses')}
      className="rounded-lg border bg-card p-4 text-sm"
      data-testid="scope-provider-addresses"
    >
      <div className="flex gap-3">
        <Server className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        <div className="min-w-0 flex-1 space-y-1">
          <h2 className="font-medium">
            {t('scope.providers.title', 'Shared provider addresses in your scope')}
          </h2>
          <p className="text-muted-foreground">
            {t(
              'scope.providers.description',
              'These scope entries are addresses a provider shares with its other customers. They are not yours to scan, so move them out of scope. The names that point at them stay in scope.'
            )}
          </p>
        </div>
      </div>
      {data?.holding && groups.some((g) => g.entry_count > 0) && (
        <div
          role="status"
          className="mt-3 flex gap-2 rounded-md border bg-muted/40 p-3"
          data-testid="scope-provider-holding"
        >
          <Pause className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
          <div className="min-w-0 space-y-0.5">
            <p className="font-medium">
              {t('scope.providers.holdingTitle', 'Scanning of these addresses is paused')}
            </p>
            <p className="text-muted-foreground">
              {t(
                'scope.providers.holding',
                "These scope entries are a provider's shared addresses, so scans skip them until you answer. Move them out of scope, or choose Keep scanning to resume active scanning in one step. Nothing is deleted either way."
              )}
            </p>
          </div>
        </div>
      )}
      <ul className="mt-3 divide-y border-t">
        {groups.map((g) => (
          <ProviderRow key={g.provider} group={g} onChanged={refresh} />
        ))}
      </ul>
    </section>
  )
}

function ProviderRow({
  group,
  onChanged,
}: {
  group: ApiScopeProviderGroup
  onChanged: () => Promise<void>
}) {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.ScopeWrite)
  const [showEntries, setShowEntries] = useState(false)
  const [moveOpen, setMoveOpen] = useState(false)
  const [keepOpen, setKeepOpen] = useState(false)
  const [preview, setPreview] = useState<ConfirmPreview | undefined>(undefined)
  const [previewing, setPreviewing] = useState(false)
  const provider = group.provider
  const count = group.entry_count

  const openMove = async () => {
    setPreviewing(true)
    try {
      const p = await moveScopeProviderAddresses(provider, true)
      const summary =
        p.entries === 1
          ? t('scope.providers.moveSummaryOne', '1 entry becomes an exclusion')
          : t('scope.providers.moveSummaryMany', '{count} entries become exclusions', {
              count: p.entries,
            })
      setPreview({
        summary:
          p.existing > 0
            ? `${summary}. ${t('scope.providers.moveExisting', '{count} of them already have an exclusion; only the entry is turned off.', { count: p.existing })}`
            : summary,
        names: group.entries.map((e) => e.pattern),
        total: p.entries,
      })
      setMoveOpen(true)
    } catch (err) {
      toast.error(
        scopeErrorMessage(
          t,
          err,
          t('scope.providers.previewFailed', 'Could not count the entries. Try again.')
        )
      )
    } finally {
      setPreviewing(false)
    }
  }

  const move = async () => {
    try {
      const res = await moveScopeProviderAddresses(provider)
      toast.success(
        t('scope.providers.moved', '{count} entries moved out of scope', { count: res.entries })
      )
      setMoveOpen(false)
      await onChanged()
    } catch (err) {
      toast.error(
        scopeErrorMessage(
          t,
          err,
          t('scope.providers.failed', 'Could not save the answer. Try again.')
        )
      )
    }
  }

  const keep = async () => {
    try {
      await keepScopeProviderAddresses(provider)
      toast.success(t('scope.providers.kept', '{provider} addresses kept in scope', { provider }))
      setKeepOpen(false)
      await onChanged()
    } catch (err) {
      toast.error(
        scopeErrorMessage(
          t,
          err,
          t('scope.providers.failed', 'Could not save the answer. Try again.')
        )
      )
    }
  }

  return (
    <li className="space-y-2 py-3" data-testid="scope-provider-row">
      {count > 0 && (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <p className="min-w-0 font-medium">
            {count === 1
              ? t('scope.providers.rowOne', '1 scope entry is a {provider} shared address', {
                  provider,
                })
              : t(
                  'scope.providers.rowMany',
                  '{count} scope entries are {provider} shared addresses',
                  {
                    count,
                    provider,
                  }
                )}
          </p>
          {canWrite && (
            <div className="flex shrink-0 flex-wrap gap-2">
              <Button size="sm" onClick={() => void openMove()} disabled={previewing}>
                {t('scope.providers.move', 'Move to out of scope')}
              </Button>
              <Button size="sm" variant="outline" onClick={() => setKeepOpen(true)}>
                {t('scope.providers.keep', 'Keep scanning')}
              </Button>
            </div>
          )}
        </div>
      )}
      {count > 0 && (
        <Button
          variant="link"
          size="sm"
          className="h-auto px-0"
          aria-expanded={showEntries}
          onClick={() => setShowEntries((v) => !v)}
        >
          {showEntries
            ? t('scope.providers.hideEntries', 'Hide entries')
            : t('scope.providers.showEntries', 'Show entries')}
        </Button>
      )}
      {showEntries && (
        <ul
          aria-label={t('scope.providers.entriesLabel', 'Scope entries of {provider}', {
            provider,
          })}
          className="space-y-1"
        >
          {group.entries.slice(0, SHOWN_ENTRIES).map((e) => (
            <li key={e.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
              <span className="font-mono text-xs break-all">{e.pattern}</span>
              <span className="text-xs text-muted-foreground">
                <RelativeTime date={e.created_at} />
              </span>
            </li>
          ))}
          {group.entries.length > SHOWN_ENTRIES && (
            <li className="text-xs text-muted-foreground">
              {t('scope.bulk.more', 'and {count} more', {
                count: group.entries.length - SHOWN_ENTRIES,
              })}
            </li>
          )}
        </ul>
      )}
      {group.confirmed.length > 0 && (
        <div className="space-y-1" data-testid="scope-provider-confirmed">
          <p className="font-medium">
            {t('scope.providers.confirmedTitle', 'Confirmed by a person: keep or move')}
          </p>
          <p className="text-xs text-muted-foreground">
            {t(
              'scope.providers.confirmedHint',
              'Someone confirmed these {provider} addresses as yours. Open each one to keep or change that decision.',
              { provider }
            )}
          </p>
          <ul className="flex flex-wrap gap-x-3 gap-y-1">
            {group.confirmed.map((c) => (
              <li key={c.asset_id} className="font-mono text-xs">
                {isLinkableAssetId(c.asset_id) ? (
                  <Link href={assetDetailHref(c.asset_id)} className="hover:underline">
                    {c.name}
                  </Link>
                ) : (
                  c.name
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      <ConfirmDialog
        open={moveOpen}
        onOpenChange={setMoveOpen}
        title={t('scope.providers.moveTitle', 'Move {provider} addresses out of scope?', {
          provider,
        })}
        desc={t(
          'scope.providers.moveDesc',
          'Each entry becomes an exclusion of the same address and is turned off. Scans stop touching these addresses. Names that point at them stay in scope.'
        )}
        confirmText={t('scope.providers.move', 'Move to out of scope')}
        preview={preview}
        handleConfirm={move}
      />
      <ConfirmDialog
        open={keepOpen}
        onOpenChange={setKeepOpen}
        title={t('scope.providers.keepTitle', 'Keep scanning {provider} addresses?', { provider })}
        desc={t(
          'scope.providers.keepDesc',
          "Active scanning of these addresses resumes at once. They serve the provider's other customers too, and testing them follows the provider's rules. The entries stay in scope and leave this list. You will be asked to confirm your identity."
        )}
        confirmText={t('scope.providers.keep', 'Keep scanning')}
        handleConfirm={keep}
      />
    </li>
  )
}
