'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { DangerZone, DangerZoneItem } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { fetcher, fetcherWithOptions } from '@/lib/api/client'
import { formatDate } from '@/lib/app-locale'

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
    <DangerZone id="delete-account">
      <DangerZoneItem
        title={t('settings.accountDelete.title')}
        description={
          <>
            {t('settings.accountDelete.desc')}
            {data?.scheduled && data.erase_after && (
              <span className="mt-1 block text-destructive">
                {t('settings.accountDelete.pending', undefined, {
                  date: formatDate(new Date(data.erase_after)),
                })}
              </span>
            )}
            {soleOwnerOf && (
              <span className="mt-1 block text-destructive" role="alert">
                {t('settings.accountDelete.soleOwner', undefined, { orgs: soleOwnerOf.join(', ') })}
              </span>
            )}
          </>
        }
        action={
          <Button variant="destructive" onClick={() => setOpen(true)}>
            <Trash2 aria-hidden />
            {t('settings.accountDelete.button')}
          </Button>
        }
      />
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
    </DangerZone>
  )
}
