import { redirect } from 'next/navigation'

// Crawled URLs are web endpoints under their origin now (RFC-056).
export default function Page() {
  redirect('/assets/web?tab=endpoints')
}
