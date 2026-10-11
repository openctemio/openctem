'use client'

/**
 * Scoping › Networks (RFC-082): AS numbers and organization names the
 * organization asserts are its own. Each is looked up in public routing data
 * (RIPEstat): an AS number lists the prefixes it announces, offered as CIDR
 * scope entries through the normal scope flow (approvals, step-up, platform
 * guardrails); an organization name lists the AS numbers registered to it.
 * A seed never authorizes a probe by itself. The review queue offers the
 * range around an address in a seeded network.
 */

import { useState } from 'react'
import { Loader2, Network, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
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
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState, RelativeTime } from '@/features/shared'
import { ScopeFixButtons } from '@/features/scope/components/scope-check-results'
import type { EASMNetworkSeed } from '@/lib/api/generated'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import {
  addNetworkSeed,
  deleteNetworkSeed,
  refreshNetworkSeed,
  useEASMNetworkSeeds,
} from '../hooks/use-easm-network-seeds'
import { useEASMSettings } from '../hooks/use-easm-settings'

type SeedKind = 'asn' | 'org_name'

/** When to read again after a lookup started in the background. */
const LOOKUP_SETTLE_MS = 6_000

/** How many prefixes a seed lists before "show all". */
const PREFIXES_SHOWN = 10

function SeedCard({
  seed,
  canWrite,
  canDelete,
  onRemove,
  onChanged,
  onAddSeed,
}: {
  seed: EASMNetworkSeed
  canWrite: boolean
  canDelete: boolean
  onRemove: (s: EASMNetworkSeed) => void
  onChanged: () => void
  onAddSeed: (asn: string) => void
}) {
  const { t } = useTranslation()
  const [all, setAll] = useState(false)
  const [busy, setBusy] = useState(false)
  const expanding = !seed.last_expanded_at
  const prefixes = seed.prefix_suggestions ?? []
  const shown = all ? prefixes : prefixes.slice(0, PREFIXES_SHOWN)

  const refresh = async () => {
    if (!seed.id) return
    setBusy(true)
    try {
      await refreshNetworkSeed(seed.id)
      toast.success(t('networkSeeds.refreshStarted', 'Refresh started'))
      onChanged()
      setTimeout(onChanged, LOOKUP_SETTLE_MS)
    } catch (e) {
      toast.error(getErrorMessage(e, t('networkSeeds.refreshFailed', 'Could not refresh the seed')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <article className="space-y-3 rounded-md border p-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline">
          {seed.kind === 'asn'
            ? t('networkSeeds.kindAsn', 'AS number')
            : t('networkSeeds.kindOrg', 'Organization')}
        </Badge>
        <span className="break-all font-medium">{seed.value}</span>
        {seed.holder && (
          <span className="break-all text-sm text-muted-foreground">{seed.holder}</span>
        )}
        {seed.label && <span className="text-xs text-muted-foreground">({seed.label})</span>}
        <span className="ms-auto flex items-center gap-1">
          {canWrite && (
            <Button
              size="sm"
              variant="ghost"
              disabled={busy || expanding}
              onClick={() => void refresh()}
              aria-label={t('networkSeeds.refresh', 'Look up again')}
            >
              <RefreshCw className="h-4 w-4" aria-hidden />
            </Button>
          )}
          {canDelete && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => onRemove(seed)}
              aria-label={t('networkSeeds.remove', 'Remove {value}', { value: seed.value ?? '' })}
            >
              <Trash2 className="h-4 w-4" aria-hidden />
            </Button>
          )}
        </span>
      </div>

      <p className="text-xs text-muted-foreground">
        {expanding ? (
          <span className="inline-flex items-center gap-1">
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
            {t('networkSeeds.expanding', 'Looking it up in public routing data…')}
          </span>
        ) : (
          <>
            {t('networkSeeds.lastLookup', 'Looked up')}{' '}
            <RelativeTime date={seed.last_expanded_at} />
          </>
        )}
        {seed.expand_error && (
          <span className="ms-2 text-destructive">
            {t('networkSeeds.lookupFailed', 'The last lookup failed; it is retried later.')}
          </span>
        )}
      </p>

      {seed.kind === 'asn' && seed.shared && (
        <p className="text-sm text-muted-foreground">
          {t(
            'networkSeeds.shared',
            'This network belongs to a cloud or CDN provider that serves many organizations. Its prefixes are not offered as scope entries; add your own addresses one by one.'
          )}
        </p>
      )}

      {seed.kind === 'asn' && !seed.shared && !expanding && (
        <div className="space-y-2">
          <p className="text-sm">
            {t('networkSeeds.prefixesTitle', '{count} announced prefixes', {
              count: prefixes.length,
            })}
          </p>
          {prefixes.length > 0 && (
            <ul className="divide-y rounded border">
              {shown.map((p) => (
                <li key={p.prefix} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                  <span className="font-mono">{p.prefix}</span>
                  {p.allowed ? (
                    canWrite && (
                      <span className="ms-auto">
                        <ScopeFixButtons
                          fixes={[{ action: 'add_entry', target_type: 'cidr', pattern: p.prefix }]}
                          onApplied={onChanged}
                        />
                      </span>
                    )
                  ) : (
                    <Badge variant="secondary" className="ms-auto">
                      {p.refusal === 'CIDR_TOO_LARGE'
                        ? t('networkSeeds.tooLarge', 'Larger than the platform allows')
                        : t('networkSeeds.refused', 'Not allowed by the platform')}
                    </Badge>
                  )}
                </li>
              ))}
            </ul>
          )}
          {prefixes.length > PREFIXES_SHOWN && (
            <Button size="sm" variant="link" className="px-0" onClick={() => setAll(!all)}>
              {all
                ? t('networkSeeds.showFewer', 'Show fewer')
                : t('networkSeeds.showAll', 'Show all {count}', { count: prefixes.length })}
            </Button>
          )}
        </div>
      )}

      {seed.kind === 'org_name' && !expanding && (
        <div className="space-y-2">
          <p className="text-sm">
            {(seed.suggestions ?? []).length > 0
              ? t('networkSeeds.asnsTitle', 'AS numbers registered to this name')
              : t('networkSeeds.noAsns', 'No AS number is registered to this name.')}
          </p>
          <ul className="space-y-1">
            {(seed.suggestions ?? []).map((s) => (
              <li key={s.asn} className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-mono">{s.asn}</span>
                <span className="break-all text-muted-foreground">{s.description}</span>
                {canWrite && s.asn && (
                  <Button
                    size="sm"
                    variant="outline"
                    className="ms-auto h-7 px-2 text-xs"
                    onClick={() => onAddSeed(s.asn!)}
                  >
                    {t('networkSeeds.addAsn', 'Add as AS seed')}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </article>
  )
}

export function EASMNetworkSeedsPanel() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canWrite = can(Permission.ScopeWrite)
  const canDelete = can(Permission.ScopeDelete)
  const { seeds, max, error, isLoading, mutate } = useEASMNetworkSeeds()
  const { settings } = useEASMSettings()
  const lookupsOff = settings?.network_lookups_enabled === false
  const [kind, setKind] = useState<SeedKind>('asn')
  const [value, setValue] = useState('')
  const [saving, setSaving] = useState(false)
  const [removing, setRemoving] = useState<EASMNetworkSeed | null>(null)

  if (error) {
    return (
      <ErrorState
        title={t('networkSeeds.errorTitle', 'network seeds')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  const add = async (k: SeedKind, v: string) => {
    if (!v.trim()) return
    setSaving(true)
    try {
      await addNetworkSeed(k, v.trim())
      toast.success(t('networkSeeds.added', 'Seed added; looking it up'))
      setValue('')
      void mutate()
      // The lookup runs in the background: read once more when it is likely done.
      setTimeout(() => void mutate(), LOOKUP_SETTLE_MS)
    } catch (e) {
      toast.error(getErrorMessage(e, t('networkSeeds.addFailed', 'Could not add the seed')))
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    if (!removing?.id) return
    try {
      await deleteNetworkSeed(removing.id)
      toast.success(t('networkSeeds.removed', 'Seed removed'))
      setRemoving(null)
      void mutate()
    } catch (e) {
      toast.error(getErrorMessage(e, t('networkSeeds.removeFailed', 'Could not remove the seed')))
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        {t(
          'networkSeeds.intro',
          'AS numbers and organization names that are yours. Each is looked up in public routing data (RIPEstat; the value is sent there): an AS number lists the address ranges it announces, which you can add as scope entries; an organization name lists the AS numbers registered to it. A seed never lets a scan reach anything by itself, scope entries do.'
        )}
      </p>
      {lookupsOff && (
        <p className="rounded-md border p-3 text-sm">
          {t(
            'networkSeeds.lookupsOff',
            'Lookups in public routing data are turned off for your organization (Attack surface › Monitoring). Seeds are kept but not looked up.'
          )}
        </p>
      )}
      {canWrite && (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            void add(kind, value)
          }}
        >
          <div className="space-y-1">
            <Label htmlFor="network-seed-kind">{t('networkSeeds.kind', 'Kind')}</Label>
            <Select value={kind} onValueChange={(v) => setKind(v as SeedKind)}>
              <SelectTrigger id="network-seed-kind" className="w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="asn">{t('networkSeeds.kindAsn', 'AS number')}</SelectItem>
                <SelectItem value="org_name">
                  {t('networkSeeds.kindOrg', 'Organization')}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="min-w-56 flex-1 space-y-1">
            <Label htmlFor="network-seed-value">{t('networkSeeds.value', 'Value')}</Label>
            <Input
              id="network-seed-value"
              value={value}
              maxLength={200}
              placeholder={
                kind === 'asn'
                  ? t('networkSeeds.asnPlaceholder', 'AS64500')
                  : t('networkSeeds.orgPlaceholder', 'Example Corporation')
              }
              onChange={(e) => setValue(e.target.value)}
            />
          </div>
          <Button type="submit" disabled={saving || !value.trim() || seeds.length >= max}>
            <Plus className="me-1 h-4 w-4" aria-hidden />
            {t('networkSeeds.add', 'Add seed')}
          </Button>
        </form>
      )}
      {!isLoading && seeds.length === 0 ? (
        <EmptyState
          icon={Network}
          title={t('networkSeeds.emptyTitle', 'No network seeds')}
          description={t(
            'networkSeeds.empty',
            'Add your AS numbers or your organization name to find the address ranges that are yours.'
          )}
        />
      ) : (
        <div className="space-y-3">
          {seeds.map((s) => (
            <SeedCard
              key={s.id}
              seed={s}
              canWrite={canWrite}
              canDelete={canDelete}
              onRemove={setRemoving}
              onChanged={() => void mutate()}
              onAddSeed={(asn) => void add('asn', asn)}
            />
          ))}
        </div>
      )}
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={t('networkSeeds.removeTitle', 'Remove the seed {value}?', {
          value: removing?.value ?? '',
        })}
        desc={t(
          'networkSeeds.removeDesc',
          'Scope entries you added from it stay. Addresses in this network no longer get the range offered in the review queue.'
        )}
        confirmText={t('confirm.remove', 'Remove')}
        destructive
        handleConfirm={() => void remove()}
      />
    </div>
  )
}
