'use client'

/**
 * A role created from a template never changes when the template does
 * (api RFC-095 §2.4). When the catalog has a newer version this panel shows
 * what it adds and removes, and an editor applies it explicitly.
 */
import { useState } from 'react'
import { Loader2, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { useSWRConfig } from 'swr'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Can, Permission } from '@/lib/permissions'

import { applyRoleTemplateUpdate } from '../api/use-roles'
import type { Role } from '../types/role.types'

export function RoleTemplateUpdate({
  role,
  onApplied,
}: {
  role: Role
  onApplied?: (r: Role) => void
}) {
  const { t } = useTranslation()
  const { mutate } = useSWRConfig()
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const tpl = role.template
  if (!tpl || role.is_system) return null
  const name = tpl.template_name || tpl.template_id

  if (!tpl.update_available || !tpl.current_version) {
    return (
      <p className="text-xs text-muted-foreground" data-testid="role-template-origin">
        {t('org.roleTemplate.fromTemplate', undefined, { template: name })}
      </p>
    )
  }

  const apply = async () => {
    setBusy(true)
    try {
      const updated = await applyRoleTemplateUpdate(role.id, tpl.current_version ?? 0)
      toast.success(t('org.roleTemplate.applied'))
      await mutate((key) => typeof key === 'string' && key.startsWith('/api/v1/roles'), undefined, {
        revalidate: true,
      })
      onApplied?.(updated)
    } catch {
      toast.error(t('org.roleTemplate.applyFailed'))
    } finally {
      setBusy(false)
      setConfirming(false)
    }
  }

  return (
    <Alert data-testid="role-template-update">
      <RefreshCw className="size-4" />
      <AlertTitle>{t('org.roleTemplate.updateTitle')}</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>
          {t('org.roleTemplate.updateBody', undefined, {
            template: name,
            from: tpl.version_taken,
            to: tpl.current_version,
          })}
        </p>
        {tpl.diff.added.length > 0 && (
          <div className="flex flex-wrap items-center gap-1">
            <span className="text-xs font-medium">{t('org.roleTemplate.added')}</span>
            {tpl.diff.added.map((p) => (
              <Badge // label-ok: a permission id
                key={p}
                variant="outline"
                className="font-mono text-xs"
              >
                + {p}
              </Badge>
            ))}
          </div>
        )}
        {tpl.diff.removed.length > 0 && (
          <div className="flex flex-wrap items-center gap-1">
            <span className="text-xs font-medium">{t('org.roleTemplate.removed')}</span>
            {tpl.diff.removed.map((p) => (
              <Badge // label-ok: a permission id
                key={p}
                variant="outline"
                className="font-mono text-xs text-muted-foreground"
              >
                − {p}
              </Badge>
            ))}
          </div>
        )}
        <p className="text-xs text-muted-foreground">{t('org.roleTemplate.keepsEdits')}</p>
        <Can permission={Permission.RolesWrite} mode="disable">
          <Button size="sm" onClick={() => setConfirming(true)} disabled={busy}>
            {busy && <Loader2 className="me-2 size-4 animate-spin" />}
            {t('org.roleTemplate.apply')}
          </Button>
        </Can>
        <ConfirmDialog
          open={confirming}
          onOpenChange={setConfirming}
          title={t('org.roleTemplate.confirmTitle', 'Apply the template update to {role}?', {
            role: role.name,
          })}
          desc={t(
            'org.roleTemplate.confirmDesc',
            'It adds {added} permissions and removes {removed} for everyone who holds this role. Your own changes to the role are kept. Applying it cannot be reversed here; you can edit the role afterwards.',
            {
              added: tpl.diff.added.length,
              removed: tpl.diff.removed.length,
            }
          )}
          confirmText={t('org.roleTemplate.confirmApply', 'Apply update')}
          handleConfirm={apply}
        />
      </AlertDescription>
    </Alert>
  )
}
