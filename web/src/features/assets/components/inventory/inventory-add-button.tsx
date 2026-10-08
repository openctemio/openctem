'use client'

/**
 * "Add" on the inventory. On a one-type list it adds that type; otherwise it
 * offers every type of the registry, grouped by lens, so a new registry type
 * can be added by hand with no page of its own.
 */
import { Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import type { AssetTypeRegistry } from '@/features/asset-types/lib/asset-registry'
import { lensLabel } from '@/features/asset-types/lib/asset-registry'
import { inSentence, typeViewOf, type TypeView } from '@/features/asset-types/lib/type-view'
import type { AssetLens } from '@/features/asset-types/registry.generated'

interface Choice {
  key: string
  label: string
  type: string
  subType?: string
}

function choicesByLens(registry: AssetTypeRegistry): { lens: string; choices: Choice[] }[] {
  const groups = new Map<string, Choice[]>()
  for (const t of registry.types ?? []) {
    if (!t.type) continue
    const lens = t.lens ?? ''
    const choice: Choice = t.alias_of
      ? {
          key: t.type,
          label: t.label ?? t.type,
          type: t.alias_of.type ?? t.type,
          subType: t.alias_of.sub_type,
        }
      : { key: t.type, label: t.label ?? t.type, type: t.type }
    // An alias without a sub-type is just another name of its core type.
    if (t.alias_of && !t.alias_of.sub_type) continue
    const list = groups.get(lens) ?? []
    list.push(choice)
    groups.set(lens, list)
  }
  const order: string[] = (registry.lenses ?? []).map((l) => l.id ?? '')
  return [...groups.entries()]
    .sort(([a], [b]) => {
      const ia = order.indexOf(a)
      const ib = order.indexOf(b)
      return (ia < 0 ? order.length : ia) - (ib < 0 ? order.length : ib)
    })
    .map(([lens, choices]) => ({ lens, choices }))
}

export function InventoryAddButton({
  registry,
  view,
  onAdd,
}: {
  registry: AssetTypeRegistry | undefined
  view: TypeView | null
  onAdd: (view: TypeView) => void
}) {
  if (view) {
    return (
      <Button size="sm" onClick={() => onAdd(view)}>
        <Plus className="me-2 h-4 w-4" />
        Add {inSentence(view.label)}
      </Button>
    )
  }
  if (!registry?.types?.length) return null
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="sm">
          <Plus className="me-2 h-4 w-4" />
          Add asset
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="max-h-[60vh] w-56 overflow-y-auto">
        {choicesByLens(registry).map(({ lens, choices }, i) => (
          <DropdownMenuGroup key={lens || 'other'}>
            {i > 0 && <DropdownMenuSeparator />}
            <DropdownMenuLabel className="text-xs text-muted-foreground">
              {lens ? lensLabel(registry, lens as AssetLens) : 'Other'}
            </DropdownMenuLabel>
            {choices.map((c) => (
              <DropdownMenuItem
                key={c.key}
                onClick={() => {
                  const v = typeViewOf(registry, [c.type], c.subType)
                  if (v) onAdd(v)
                }}
              >
                {c.label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuGroup>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
