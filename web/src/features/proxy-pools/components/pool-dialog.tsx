'use client'

import { useEffect, useState } from 'react'
import { ChevronDown, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'

import {
  createProxyPool,
  invalidateProxyPools,
  saveProxyEndpoints,
  updateProxyPool,
} from '../api/use-proxy-pools'
import { describeProxyError, isInvalidEndpointError } from '../lib/errors'
import { maskPasteText } from '../lib/mask'
import type { ProxyPool, ProxyStrategy } from '../types'
import { PasteListField } from './paste-list-field'

interface PoolDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The pool to edit; null creates one. */
  pool: ProxyPool | null
}

/** New pool / edit pool: name, description, enabled, the paste list, and strategy under Advanced. */
export function PoolDialog({ open, onOpenChange, pool }: PoolDialogProps) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [strategy, setStrategy] = useState<ProxyStrategy>('sticky')
  const [text, setText] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setName(pool?.name ?? '')
    setDescription(pool?.description ?? '')
    setEnabled(pool?.enabled ?? true)
    setStrategy(pool?.strategy ?? 'sticky')
    setText(maskPasteText(pool?.endpoints_text ?? ''))
    setError(null)
  }, [open, pool])

  async function submit() {
    setSaving(true)
    setError(null)
    try {
      if (!pool) {
        await createProxyPool({
          name: name.trim(),
          description: description.trim(),
          strategy,
          enabled,
          endpoints_text: text,
        })
      } else {
        // The list first: it is the request most likely to be rejected.
        if (text !== maskPasteText(pool.endpoints_text)) await saveProxyEndpoints(pool.id, text)
        await updateProxyPool(pool.id, {
          name: name.trim(),
          description: description.trim(),
          strategy,
          enabled,
        })
      }
      await invalidateProxyPools()
      toast.success(t('proxyPools.toast.poolSaved', 'Pool saved'))
      onOpenChange(false)
    } catch (e) {
      const msg = describeProxyError(
        e,
        t,
        t('proxyPools.toast.saveFailed', 'Could not save the proxies')
      )
      if (isInvalidEndpointError(e)) setError(msg)
      else toast.error(msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {pool
              ? t('proxyPools.dialog.editTitle', 'Edit pool')
              : t('proxyPools.dialog.newTitle', 'New pool')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'proxyPools.dialog.description',
              'A pool is a list of proxies. Assign it to sensors on their pages: a sensor assigned a pool sends all its scan traffic through it, private targets included.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogForm
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <DialogBody className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="pool-name">{t('proxyPools.field.name', 'Name')}</Label>
              <Input
                id="pool-name"
                value={name}
                maxLength={100}
                onChange={(e) => setName(e.target.value)}
                disabled={saving}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pool-description">
                {t('proxyPools.field.description', 'Description')}
              </Label>
              <Textarea
                id="pool-description"
                value={description}
                rows={2}
                onChange={(e) => setDescription(e.target.value)}
                disabled={saving}
              />
            </div>
            <div className="flex items-center gap-3">
              <Switch
                id="pool-enabled"
                checked={enabled}
                onCheckedChange={setEnabled}
                disabled={saving}
              />
              <Label htmlFor="pool-enabled">{t('proxyPools.field.enabled', 'Enabled')}</Label>
            </div>
            <PasteListField value={text} onChange={setText} error={error} />
            <Collapsible>
              <CollapsibleTrigger asChild>
                <Button type="button" variant="ghost" size="sm" className="-ml-2">
                  <ChevronDown className="size-4" aria-hidden />
                  {t('proxyPools.advanced', 'Advanced')}
                </Button>
              </CollapsibleTrigger>
              <CollapsibleContent className="space-y-1.5 pt-2">
                <Label htmlFor="pool-strategy">{t('proxyPools.field.strategy', 'Strategy')}</Label>
                <select
                  id="pool-strategy"
                  value={strategy}
                  onChange={(e) => setStrategy(e.target.value as ProxyStrategy)}
                  disabled={saving}
                  className="border-input bg-background h-9 w-full rounded-md border px-3 text-sm"
                >
                  <option value="sticky">
                    {t(
                      'proxyPools.strategy.sticky',
                      'Sticky: spread by health, keep a target on one proxy'
                    )}
                  </option>
                  <option value="priority">
                    {t(
                      'proxyPools.strategy.priority',
                      'Priority: use the first healthy proxy in list order'
                    )}
                  </option>
                </select>
              </CollapsibleContent>
            </Collapsible>
          </DialogBody>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={saving}
            >
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={saving || name.trim() === ''}>
              {saving && <Loader2 className="size-4 animate-spin" aria-hidden />}
              {t('proxyPools.save', 'Save')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
