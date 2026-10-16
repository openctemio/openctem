'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { fetcher, fetcherWithOptions } from '@/lib/api/client'

interface DeletionStatus {
  scheduled: boolean
  erase_after?: string
}

interface SoleOwnerDetails {
  organizations?: string[]
}

/**
 * My account › Security: delete the account (api RFC-104). Every session
 * ends and the account's API keys are revoked at once; signing in again
 * within 14 days cancels; afterwards the account leaves every organization and
 * its personal data is erased. The only owner of an organization transfers
 * ownership or deletes it first (the API names those organizations).
 */
export function DeleteAccountCard({ email }: { email?: string }) {
  const { t } = useTranslation()
  const { data } = useSWR<DeletionStatus>('/api/v1/me/account/deletion', fetcher, {
    revalidateOnFocus: false,
  })
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [soleOwnerOf, setSoleOwnerOf] = useState<string[] | null>(null)

  const handleDelete = async () => {
    setBusy(true)
    try {
      await fetcherWithOptions<DeletionStatus>('/api/v1/me/account', { method: 'DELETE' })
    } catch (error) {
      setBusy(false)
      setOpen(false)
      const details = (error as { details?: SoleOwnerDetails } | null)?.details
      if (details?.organizations?.length) {
        setSoleOwnerOf(details.organizations)
        return
      }
      toast.error(error instanceof Error ? error.message : t('settings.accountDelete.failed'))
      return
    }
    toast.success(t('settings.accountDelete.scheduled'))
    // Every session ended: back to sign-in.
    window.location.replace('/login')
  }

  return (
    <Card className="border-destructive/40">
      <CardHeader>
        <CardTitle>{t('settings.accountDelete.title')}</CardTitle>
        <CardDescription>{t('settings.accountDelete.desc')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {data?.scheduled && data.erase_after && (
          <p className="text-sm text-destructive">
            {t('settings.accountDelete.pending', undefined, {
              date: new Date(data.erase_after).toLocaleDateString(),
            })}
          </p>
        )}
        {soleOwnerOf && (
          <p className="text-sm text-destructive" role="alert">
            {t('settings.accountDelete.soleOwner', undefined, { orgs: soleOwnerOf.join(', ') })}
          </p>
        )}
        <Button variant="destructive" size="sm" onClick={() => setOpen(true)}>
          <Trash2 className="h-4 w-4" />
          {t('settings.accountDelete.button')}
        </Button>
      </CardContent>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        destructive
        title={t('settings.accountDelete.confirmTitle')}
        desc={t('settings.accountDelete.confirmDesc')}
        typeToConfirm={email}
        confirmText={t('settings.accountDelete.button')}
        isLoading={busy}
        handleConfirm={handleDelete}
      />
    </Card>
  )
}
