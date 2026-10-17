'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  createLifecycle,
  type Lifecycle,
  type LifecycleCondition,
} from '../../api/use-finding-lifecycles'
import { LIFECYCLE_KEY_PATTERN, isPlanLimitError, slugKey } from '../../lib/lifecycle'
import { ConditionEditor } from './condition-editor'

interface LifecycleCreateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** A default lifecycle exists: a new one needs a context. */
  hasDefault: boolean
  onCreated: (l: Lifecycle) => void
}

/**
 * A new lifecycle with an empty first draft. The first one is the default;
 * further ones apply to the findings their context selects (lowest priority
 * number first).
 */
export function LifecycleCreateDialog({
  open,
  onOpenChange,
  hasDefault,
  onCreated,
}: LifecycleCreateDialogProps) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [key, setKey] = useState('')
  const [keyTouched, setKeyTouched] = useState(false)
  const [description, setDescription] = useState('')
  const [priority, setPriority] = useState(10)
  const [context, setContext] = useState<LifecycleCondition[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setName('')
    setKey('')
    setKeyTouched(false)
    setDescription('')
    setPriority(10)
    setContext([])
    setError(null)
  }, [open])

  const effectiveKey = keyTouched ? key : slugKey(name)
  const canSave =
    name.trim() !== '' &&
    LIFECYCLE_KEY_PATTERN.test(effectiveKey) &&
    (!hasDefault || context.length > 0) &&
    !busy

  const submit = async () => {
    if (!canSave) return
    setBusy(true)
    setError(null)
    try {
      const l = await createLifecycle({
        key: effectiveKey,
        name: name.trim(),
        description: description.trim(),
        ...(hasDefault ? { context, priority } : {}),
      })
      onCreated(l)
      onOpenChange(false)
    } catch (err) {
      setError(
        isPlanLimitError(err)
          ? t(
              'findingLifecycle.plan.schemesReached',
              'Your plan allows no more lifecycles. Archive one, or ask your administrator for more.'
            )
          : getErrorMessage(
              err,
              t('findingLifecycle.scheme.createFailed', 'Could not create the lifecycle')
            )
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('findingLifecycle.scheme.createTitle', 'New lifecycle')}</DialogTitle>
          <DialogDescription>
            {hasDefault
              ? t(
                  'findingLifecycle.scheme.createContextHint',
                  'Applies to the findings its conditions select; the default lifecycle covers the rest.'
                )
              : t(
                  'findingLifecycle.scheme.createDefaultHint',
                  'Your first lifecycle is the default: it applies to every finding.'
                )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="lifecycle-name">{t('findingLifecycle.scheme.name', 'Name')}</Label>
              <Input
                id="lifecycle-name"
                value={name}
                maxLength={64}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="lifecycle-key">{t('findingLifecycle.scheme.key', 'Key')}</Label>
              <Input
                id="lifecycle-key"
                className="font-mono"
                value={effectiveKey}
                onChange={(e) => {
                  setKeyTouched(true)
                  setKey(e.target.value)
                }}
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="lifecycle-description">
              {t('findingLifecycle.scheme.description', 'Description (optional)')}
            </Label>
            <Textarea
              id="lifecycle-description"
              rows={2}
              maxLength={500}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          {hasDefault && (
            <>
              <div className="space-y-2">
                <h3 className="text-sm font-medium">
                  {t('findingLifecycle.scheme.context', 'Applies to findings where')}
                </h3>
                <ConditionEditor
                  conditions={context}
                  onChange={setContext}
                  idPrefix="lifecycle-context"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="lifecycle-priority">
                  {t('findingLifecycle.scheme.priority', 'Order (lower is tried first)')}
                </Label>
                <Input
                  id="lifecycle-priority"
                  type="number"
                  min={0}
                  className="w-28"
                  value={priority}
                  onChange={(e) => setPriority(Number(e.target.value))}
                />
              </div>
            </>
          )}
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={!canSave}>
            {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t('findingLifecycle.scheme.create', 'Create lifecycle')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
