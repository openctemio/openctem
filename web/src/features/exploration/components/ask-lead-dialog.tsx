'use client'

/**
 * Ask a catalog question about one asset (POST /api/v1/exploration/leads,
 * scans:execute). Every lead type is offered; the API refuses one that does
 * not apply to the asset's type (400) or that is already open or at its cap
 * (409), and the dialog says so in plain words. A passive step starts at
 * once; an active one may wait for approval.
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
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { useRevalidateLeads, askLead } from '../hooks/use-leads'
import { LEAD_TYPE_IDS } from '../lib/lead-types.generated'
import { askErrorMessage, leadQuestion, leadTitle, stateLabel } from '../lib/leads'

const MAX_RATIONALE = 1000

export function AskLeadDialog({
  assetId,
  open,
  onOpenChange,
  onAsked,
}: {
  assetId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  onAsked?: () => void
}) {
  const { t } = useTranslation()
  const revalidate = useRevalidateLeads()
  const [type, setType] = useState<string>(LEAD_TYPE_IDS[0])
  const [rationale, setRationale] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const close = (next: boolean) => {
    if (!next) {
      setRationale('')
      setError(null)
    }
    onOpenChange(next)
  }

  const submit = async () => {
    setSaving(true)
    setError(null)
    try {
      const lead = await askLead({
        lead_type: type,
        asset_id: assetId,
        rationale: rationale.trim(),
      })
      toast.success(
        t('exploration.ask.done', 'Question asked: {state}', {
          state: stateLabel(t, lead.state).toLowerCase(),
        })
      )
      close(false)
      onAsked?.()
      void revalidate()
    } catch (e) {
      setError(askErrorMessage(t, e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('exploration.ask.title', 'Ask a question about this asset')}</DialogTitle>
          <DialogDescription>
            {t(
              'exploration.ask.desc',
              'The platform plans a step to answer it. A passive step starts at once; an active step may wait for approval.'
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
            <div className="space-y-2">
              <Label htmlFor="exploration-ask-type">{t('exploration.ask.type', 'Question')}</Label>
              <Select value={type} onValueChange={setType}>
                <SelectTrigger id="exploration-ask-type" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {LEAD_TYPE_IDS.map((id) => (
                    <SelectItem key={id} value={id}>
                      {leadTitle(t, id)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-sm text-muted-foreground">{leadQuestion(t, type)}</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="exploration-ask-rationale">
                {t('exploration.ask.rationale', 'Why (optional)')}
              </Label>
              <Textarea
                id="exploration-ask-rationale"
                value={rationale}
                maxLength={MAX_RATIONALE}
                onChange={(e) => setRationale(e.target.value)}
              />
            </div>
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => close(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={saving}>
              {t('exploration.ask.submit', 'Ask')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
