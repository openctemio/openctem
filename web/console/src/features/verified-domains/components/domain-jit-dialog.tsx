'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useState } from 'react'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { getErrorMessage } from '@/lib/api/error-handler'

import { isPendingChange, useUpdateDomainJIT } from '../api/use-verified-domains'
import type { DomainJITRole, VerifiedDomain } from '../types/verified-domain.types'

const ROLE_LABEL: Record<DomainJITRole, string> = { viewer: 'Viewer', member: 'Member' }
const DEFAULT_ROLE = 'default'

/** How SSO treats newcomers on a verified domain, in words. */
export function jitLabel(d: Pick<VerifiedDomain, 'jit_enabled' | 'jit_role'>): string {
  if (d.jit_enabled === false) return 'Not admitted'
  return d.jit_role ? `Join as ${ROLE_LABEL[d.jit_role]}` : 'Join with the IdP default'
}

/**
 * Per-domain just-in-time provisioning (RFC-058): whether SSO admits people
 * who are not members yet on this domain, and with which role. Administrators
 * are never provisioned.
 */
export function DomainJITDialog({
  tenantId,
  domain,
  onOpenChange,
  onSaved,
}: {
  tenantId: string
  domain: VerifiedDomain | null
  onOpenChange: (open: boolean) => void
  onSaved: () => void
}) {
  const { t } = useTranslation()

  const { trigger, isMutating } = useUpdateDomainJIT(tenantId)
  const [enabled, setEnabled] = useState(true)
  const [role, setRole] = useState<string>(DEFAULT_ROLE)
  const [loadedFor, setLoadedFor] = useState<string | null>(null)
  if (domain && loadedFor !== domain.id) {
    setLoadedFor(domain.id)
    setEnabled(domain.jit_enabled !== false)
    setRole(domain.jit_role ?? DEFAULT_ROLE)
  }

  const save = async () => {
    if (!domain) return
    try {
      const res = await trigger({
        id: domain.id,
        jit_enabled: enabled,
        jit_role: role === DEFAULT_ROLE ? '' : (role as DomainJITRole),
      })
      if (isPendingChange(res)) {
        toast.info(
          t(
            'admin.domainJitDialog.admittingMorePeopleWaitsFor',
            '{domain}: admitting more people waits for an owner of the organization to approve it',
            { domain: domain.domain }
          )
        )
      } else {
        toast.success(
          t('admin.domainJitDialog.provisioningUpdated', '{domain}: provisioning updated', {
            domain: domain.domain,
          })
        )
      }
      onSaved()
      onOpenChange(false)
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t('admin.domainJitDialog.couldNotUpdateProvisioning', 'Could not update provisioning')
        )
      )
    }
  }

  return (
    <Dialog
      open={!!domain}
      onOpenChange={(next) => {
        if (!next) setLoadedFor(null)
        onOpenChange(next)
      }}
    >
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>
            {t('admin.domainJitDialog.newPeopleOn', 'New people on {domain}', {
              domain: domain?.domain ?? '',
            })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'admin.domainJitDialog.whetherTheOrganizationSSso',
              "Whether the organization's SSO lets people with an address on this domain join on their first sign-in, and with which role. Administrators are never added this way. Admitting more people, or with a higher role, waits for an owner's approval."
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-4 py-4">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="domain-jit-enabled">
                {t('admin.domainJitDialog.admitNewPeople', 'Admit new people')}
              </Label>
              <Switch
                id="domain-jit-enabled"
                checked={enabled}
                onCheckedChange={setEnabled}
                disabled={isMutating}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="domain-jit-role">{t('admin.domainJitDialog.role', 'Role')}</Label>
              <Select value={role} onValueChange={setRole} disabled={!enabled || isMutating}>
                <SelectTrigger id="domain-jit-role" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={DEFAULT_ROLE}>
                    {t(
                      'admin.domainJitDialog.identityProviderDefault',
                      'Identity provider default'
                    )}
                  </SelectItem>
                  <SelectItem value="viewer">
                    {t('admin.domainJitDialog.viewer', 'Viewer')}
                  </SelectItem>
                  <SelectItem value="member">
                    {t('admin.domainJitDialog.member', 'Member')}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={save} disabled={isMutating}>
            {isMutating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('common.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
