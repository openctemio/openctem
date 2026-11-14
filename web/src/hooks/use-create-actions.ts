'use client'

import { useMemo } from 'react'
import {
  FileUp,
  Package,
  Radar,
  ShieldAlert,
  UserPlus,
  Wrench,
  type LucideIcon,
} from 'lucide-react'
import { usePermissions } from '@/context/permission-provider'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { useCanMutate } from '@/lib/permissions'
import { Permission } from '@/lib/permissions'
import { openFormHref, type OpenForm } from '@/lib/open-form'

/**
 * Every "new" verb of the app: the header's Create menu, its "n" chords and
 * the palette's commands list exactly these. Each opens a page's own create
 * form (`?new=<form>`, src/hooks/use-open-form.ts); the write itself stays on
 * that page, behind its confirmation and step-up, and the API is the only
 * authority. An action the caller may not take is not listed.
 */
export interface CreateAction {
  id: OpenForm
  /** The second key of the "n" chord (none for Invite people). */
  chord?: string
  /** i18n key and English text. */
  labelKey: string
  label: string
  icon: LucideIcon
  href: string
}

/** The actions in menu order, with the page each form lives on. */
export const CREATE_ACTION_DEFS: readonly (Omit<CreateAction, 'href'> & { path: string })[] = [
  {
    id: 'scan',
    chord: 's',
    labelKey: 'nav.create.scan',
    label: 'New scan',
    icon: Radar,
    path: '/scans',
  },
  {
    id: 'import',
    chord: 'i',
    labelKey: 'nav.create.import',
    label: 'Import results',
    icon: FileUp,
    path: '/findings',
  },
  {
    id: 'asset',
    chord: 'a',
    labelKey: 'nav.create.asset',
    label: 'Add asset',
    icon: Package,
    path: '/assets',
  },
  {
    id: 'finding',
    chord: 'f',
    labelKey: 'nav.create.finding',
    label: 'New finding',
    icon: ShieldAlert,
    path: '/findings',
  },
  {
    id: 'task',
    chord: 't',
    labelKey: 'nav.create.task',
    label: 'Remediation task',
    icon: Wrench,
    path: '/remediation/tasks',
  },
  {
    id: 'invite',
    labelKey: 'nav.create.invite',
    label: 'Invite people',
    icon: UserPlus,
    path: '/settings/members',
  },
]

/**
 * The create actions this caller may take now. Each gate is the one the
 * target page applies before it opens the form, so a listed action always
 * opens its form.
 */
export function useCreateActions(): CreateAction[] {
  const { hasPermission } = usePermissions()
  const scansOn = useModuleEnabled('scans')
  const remediationOn = useModuleEnabled('remediation')
  const canInvite = useCanMutate('POST /api/v1/tenants/{tenant}/invitations')
  const allowed: Record<OpenForm, boolean> = {
    // scans-section-tabs.tsx
    scan: scansOn && hasPermission(Permission.ScansWrite),
    // findings/page.tsx canImport (the gate of POST /findings/imports)
    import:
      hasPermission(Permission.FindingsWrite) &&
      hasPermission(Permission.AssetsWrite) &&
      hasPermission(Permission.AssetsImport),
    // all-assets-inventory.tsx canWrite
    asset: hasPermission(Permission.AssetsWrite),
    // findings/page.tsx "Add finding"
    finding: hasPermission(Permission.FindingsWrite),
    // tasks-view.tsx canQueryCreate
    task:
      remediationOn &&
      hasPermission(Permission.RemediationWrite) &&
      hasPermission(Permission.FindingsRead),
    // settings/members/page.tsx "Invite user"
    invite: canInvite,
  }
  const key = (Object.keys(allowed) as OpenForm[]).filter((k) => allowed[k]).join(',')
  return useMemo(() => {
    const on = new Set(key.split(','))
    return CREATE_ACTION_DEFS.filter((d) => on.has(d.id)).map(({ path, ...d }) => ({
      ...d,
      href: openFormHref(path, d.id),
    }))
  }, [key])
}
