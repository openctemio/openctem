/** Date and time of an ISO timestamp in the console locale (the raw value when unparseable). */
export function formatDateTime(iso: string, locale?: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleString(locale, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
}
