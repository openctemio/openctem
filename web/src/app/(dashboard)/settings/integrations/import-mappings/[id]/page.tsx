'use client'

import { useParams } from 'next/navigation'
import { ImportMappingEditor } from '@/features/import-mappings/components/import-mapping-editor'

/** One import mapping: its editor and versions. */
export default function ImportMappingEditorPage() {
  const params = useParams<{ id: string }>()
  return <ImportMappingEditor id={params.id} />
}
