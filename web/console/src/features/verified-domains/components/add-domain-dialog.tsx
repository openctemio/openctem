'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useState } from 'react'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useAddVerifiedDomain } from '../api/use-verified-domains'
import type { VerifiedDomain } from '../types/verified-domain.types'
import { DnsInstructions } from './dns-instructions'

/**
 * Add-domain dialog. Phase 1 collects the domain; on a successful create it
 * switches to phase 2 and shows the DNS TXT record to publish. Closing the
 * dialog triggers `onAdded` so the parent can revalidate the list.
 */
export function AddDomainDialog({ tenantId, onAdded }: { tenantId: string; onAdded: () => void }) {
  const { t } = useTranslation()

  const [open, setOpen] = useState(false)
  const [domain, setDomain] = useState('')
  const [created, setCreated] = useState<VerifiedDomain | null>(null)
  const { trigger: add, isMutating } = useAddVerifiedDomain(tenantId)

  const reset = () => {
    setDomain('')
    setCreated(null)
  }

  const handleOpenChange = (next: boolean) => {
    setOpen(next)
    if (!next) {
      // If a domain was created during this session, refresh the list on close.
      if (created) onAdded()
      reset()
    }
  }

  const handleSubmit = async () => {
    const trimmed = domain.trim().toLowerCase()
    if (!trimmed) return
    try {
      const result = await add({ domain: trimmed })
      setCreated(result)
      onAdded()
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('admin.addDomainDialog.failedToAddDomain', 'Failed to add domain'))
      )
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="me-2 h-4 w-4" />
          {t('admin.addDomainDialog.addDomain', 'Add domain')}
        </Button>
      </DialogTrigger>
      <DialogContent>
        {created ? (
          <>
            <DialogHeader>
              <DialogTitle>
                {t('admin.addDomainDialog.verify', 'Verify {domain}', { domain: created.domain })}
              </DialogTitle>
              <DialogDescription>
                {t(
                  'admin.addDomainDialog.publishThisDnsTxtRecord',
                  'Publish this DNS TXT record to prove you own the domain, then verify it.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              {created.instructions ? (
                <DnsInstructions instructions={created.instructions} />
              ) : (
                <p className="text-muted-foreground text-sm">
                  {t(
                    'admin.addDomainDialog.noVerificationRecordWasReturned',
                    'No verification record was returned. Reopen the domain from the list to retry.'
                  )}
                </p>
              )}
            </DialogBody>
            <DialogFooter>
              <Button onClick={() => handleOpenChange(false)}>
                {t('admin.addDomainDialog.done', 'Done')}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>
                {t('admin.addDomainDialog.addAVerifiedDomain', 'Add a verified domain')}
              </DialogTitle>
              <DialogDescription>
                {t(
                  'admin.addDomainDialog.enterADomainYouOwn',
                  'Enter a domain you own. Shared/consumer domains (like gmail.com) cannot be verified.'
                )}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  void handleSubmit()
                }}
                className="space-y-2"
              >
                <Label htmlFor="verified-domain-input">
                  {t('admin.addDomainDialog.domain', 'Domain')}
                </Label>
                <Input
                  id="verified-domain-input"
                  value={domain}
                  autoFocus
                  placeholder="acme.com"
                  onChange={(e) => setDomain(e.target.value)}
                />
              </form>
            </DialogBody>
            <DialogFooter>
              <Button variant="outline" onClick={() => handleOpenChange(false)}>
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button onClick={handleSubmit} disabled={isMutating || !domain.trim()}>
                {isMutating
                  ? t('admin.addDomainDialog.adding', 'Adding…')
                  : t('admin.addDomainDialog.add', 'Add')}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
