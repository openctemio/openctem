/**
 * Whether the web API proxy must pass a response body through as bytes.
 * Only JSON and text/* are decoded; everything else (Word, Excel, PDF,
 * images, archives, CSV served as octet-stream...) is streamed untouched.
 * An allow-list of binary types missed DOCX/XLSX and corrupted every Word
 * report and template download.
 */
export function isBinaryContentType(contentType: string): boolean {
  const ct = contentType.split(';')[0].trim().toLowerCase()
  if (!ct) return false
  if (ct.startsWith('text/')) return false
  if (ct === 'application/json' || ct.endsWith('+json')) return false
  return true
}
