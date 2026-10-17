'use client'

import { useParams } from 'next/navigation'
import { MappingEditor } from '@/features/ticket-mapping/components/mapping-editor'

/** The field and status mapping editor of one destination (RFC-097). */
export default function TicketMappingEditorPage() {
  const params = useParams<{ id: string }>()
  return <MappingEditor id={params.id} />
}
