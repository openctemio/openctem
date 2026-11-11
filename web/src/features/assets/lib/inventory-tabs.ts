/**
 * The type tabs of the External surface lens: Domains, Subdomains, IP
 * addresses, Services, Web endpoints, Certificates. A tab is a locked `type`
 * condition: it shows as a locked chip, is not part of the editable query text,
 * and narrows the list (and its counts) to one stored type (a web endpoint is
 * the service sub-type `discovered_url`, so the Services tab leaves it out).
 * Other lenses keep the type facet.
 */
import type { InventoryFilters } from './inventory-url'

/** The lens whose list is split into tabs. */
export const TABS_LENS = 'external_surface'

export interface InventoryTab {
  /** The `?tab=` value. */
  id: string
  /** The stored type the tab lists. */
  type: string
  /** Narrows the type to one stored sub-type. */
  subType?: string
  /** Leaves one stored sub-type out. */
  notSubType?: string
  /** i18n key of the tab label (the English fallback follows). */
  labelKey: string
  label: string
  /** Registry fields of this type, listed first by the search box. */
  fields: string[]
}

export const INVENTORY_TABS: readonly InventoryTab[] = [
  {
    id: 'domain',
    type: 'domain',
    labelKey: 'assets.tabs.type.domain',
    label: 'Domains',
    fields: ['name', 'domain', 'expires', 'scope_status'],
  },
  {
    id: 'subdomain',
    type: 'subdomain',
    labelKey: 'assets.tabs.type.subdomain',
    label: 'Subdomains',
    fields: ['name', 'under', 'resolution', 'technology', 'liveness'],
  },
  {
    id: 'ip_address',
    type: 'ip_address',
    labelKey: 'assets.tabs.type.ip_address',
    label: 'IP addresses',
    fields: ['ip', 'network', 'port', 'service', 'domain', 'exposure'],
  },
  {
    id: 'service',
    type: 'service',
    notSubType: 'discovered_url',
    labelKey: 'assets.tabs.type.service',
    label: 'Services',
    fields: ['name', 'port', 'service', 'technology', 'domain'],
  },
  {
    id: 'web_endpoint',
    type: 'service',
    subType: 'discovered_url',
    labelKey: 'assets.tabs.type.web_endpoint',
    label: 'Web endpoints',
    fields: ['name', 'domain', 'technology', 'technology_category'],
  },
  {
    id: 'certificate',
    type: 'certificate',
    labelKey: 'assets.tabs.type.certificate',
    label: 'Certificates',
    fields: ['name', 'domain', 'expires'],
  },
]

export function tabById(id: string | null | undefined): InventoryTab | undefined {
  return INVENTORY_TABS.find((t) => t.id === id)
}

/**
 * The tab an old `types=<one type>` link (with an optional `sub_type`) opens.
 * `discovered_url` is the registry's name for the web endpoint alias.
 */
export function tabFromTypes(
  types: readonly string[] | undefined,
  subType: string | undefined
): InventoryTab | undefined {
  if (types?.length !== 1) return undefined
  const type = types[0]
  if (type === 'discovered_url') return tabById('web_endpoint')
  if (type === 'service') return tabById(subType === 'discovered_url' ? 'web_endpoint' : 'service')
  return INVENTORY_TABS.find((t) => t.type === type && !t.subType && !t.notSubType && !subType)
}

/** The open tab of a filter: only inside the External surface lens. */
export function openTab(f: Pick<InventoryFilters, 'lens' | 'tab'>): InventoryTab | undefined {
  return f.lens === TABS_LENS ? tabById(f.tab) : undefined
}

/**
 * The filter the list runs: the tab's locked type condition on top of the
 * viewer's own. Chips, the query text and saved views use the filter without it.
 */
export function withTab(f: InventoryFilters): InventoryFilters {
  const tab = openTab(f)
  if (!tab) return f
  const extra = { ...(f.extra ?? {}) }
  if (tab.notSubType) extra.sub_type_not = tab.notSubType
  return {
    ...f,
    types: [tab.type] as InventoryFilters['types'],
    subType: tab.subType,
    extra: Object.keys(extra).length > 0 ? extra : undefined,
  }
}

/**
 * Tab counts from the lens's stats (`by_type_sub_type`, keyed "type" or
 * "type/sub_type"): every tab counts its own stored rows only.
 */
export function tabCounts(
  byTypeSubType: Record<string, number> | undefined
): Record<string, number> {
  const out: Record<string, number> = {}
  for (const tab of INVENTORY_TABS) {
    let n = 0
    for (const [key, count] of Object.entries(byTypeSubType ?? {})) {
      const [type, sub] = key.split('/', 2)
      if (type !== tab.type) continue
      if (tab.subType ? sub !== tab.subType : tab.notSubType && sub === tab.notSubType) continue
      n += count
    }
    out[tab.id] = n
  }
  return out
}
