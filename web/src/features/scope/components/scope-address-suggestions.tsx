'use client'

/**
 * Addresses behind in-scope names (RFC-054 §14.7). A name in scope does not
 * put the addresses it resolves to in scope (a stale DNS record can point at
 * someone else's server), so they are offered here instead: the server lists
 * the public addresses in-scope names resolve to, without shared edge, CDN or
 * hosting addresses, narrowed to what the viewer may see; the person picks
 * and adds them in one request.
 */

import { useMemo, useState } from 'react'
import { Network } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  createScopeTargetsBulk,
  invalidateScopeCache,
  useScopeAddressSuggestions,
} from '../api/use-scope-api'
import { reportBulkResult } from './add-to-scope-action'

const MAX_ITEMS = 200

export function ScopeAddressSuggestions() {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.ScopeWrite)
  const { data, mutate } = useScopeAddressSuggestions(canWrite)
  const [open, setOpen] = useState(false)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const rows = useMemo(() => data?.data ?? [], [data])

  if (!canWrite || rows.length === 0) return null

  const openReview = () => {
    setPicked(new Set(rows.slice(0, MAX_ITEMS).map((r) => r.address ?? '')))
    setOpen(true)
  }
  const toggle = (address: string, on: boolean) => {
    const next = new Set(picked)
    if (on) next.add(address)
    else next.delete(address)
    setPicked(next)
  }
  const submit = async () => {
    setBusy(true)
    try {
      const res = await createScopeTargetsBulk({
        items: [...picked]
          .slice(0, MAX_ITEMS)
          .map((p) => ({ target_type: 'ip_address', pattern: p })),
      })
      reportBulkResult(t, res)
      await invalidateScopeCache()
      await mutate()
      setOpen(false)
    } catch (err) {
      toast.error(getErrorMessage(err, t('scope.bulk.failed', 'Could not add to scope')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Alert className="mt-5">
        <Network className="h-4 w-4" aria-hidden />
        <AlertDescription className="flex flex-wrap items-center justify-between gap-2">
          <span>
            {t(
              'scope.addresses.banner',
              '{count} addresses your in-scope names resolve to are not in scope.',
              { count: rows.length }
            )}
          </span>
          <Button size="sm" variant="outline" onClick={openReview}>
            {t('scope.addresses.review', 'Review')}
          </Button>
        </AlertDescription>
      </Alert>
      <Dialog open={open} onOpenChange={(o) => !busy && setOpen(o)}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>
              {t('scope.addresses.title', 'Addresses behind your in-scope names')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'scope.addresses.description',
                'A name in scope does not put its addresses in scope: a stale DNS record can point at someone else. Check each address is yours, then add it. Shared CDN and hosting addresses are not listed.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-2 text-sm">
            <ul className="space-y-2" data-testid="scope-address-list">
              {rows.map((r) => {
                const address = r.address ?? ''
                const id = `addr-${address}`
                return (
                  <li key={address} className="flex items-start gap-2">
                    <Checkbox
                      id={id}
                      checked={picked.has(address)}
                      onCheckedChange={(v) => toggle(address, v === true)}
                    />
                    <label htmlFor={id} className="min-w-0">
                      <span className="font-mono text-xs">{address}</span>
                      <span className="block text-muted-foreground">
                        {t('scope.addresses.from', 'from {names}', {
                          names: (r.names ?? []).slice(0, 3).join(', '),
                        })}
                        {r.provider ? ` · ${r.provider}` : ''}
                      </span>
                    </label>
                  </li>
                )
              })}
            </ul>
            {(data?.skipped_shared ?? 0) > 0 && (
              <p className="text-muted-foreground">
                {t('scope.addresses.skipped', '{count} shared addresses are not listed.', {
                  count: data?.skipped_shared ?? 0,
                })}
              </p>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={() => void submit()} disabled={busy || picked.size === 0}>
              {busy
                ? t('scope.bulk.adding', 'Adding…')
                : t('scope.addresses.add', 'Add {count} to scope', {
                    count: Math.min(picked.size, MAX_ITEMS),
                  })}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
