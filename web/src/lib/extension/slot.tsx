/**
 * Renders what the extension registered for a named place in a core page;
 * renders nothing in the default build. Slot ids and their props are listed
 * in ./types.ts (ExtensionSlotProps).
 */
import type { ComponentType } from 'react'

import { webExtension } from './index'
import type { ExtensionSlotId, ExtensionSlotProps } from './types'

type SlotProps<K extends ExtensionSlotId> = { id: K } & ExtensionSlotProps[K]

export function ExtensionSlot<K extends ExtensionSlotId>({ id, ...props }: SlotProps<K>) {
  const Slot = webExtension.slots[id] as ComponentType<ExtensionSlotProps[K]> | undefined
  if (!Slot) return null
  return <Slot {...(props as unknown as ExtensionSlotProps[K])} />
}
