/**
 * Drop the query string and fragment of every http(s) URL in a piece of
 * text, keeping scheme://host/path. Errors that sensors report often quote
 * signed download URLs (GitHub release assets, S3, GCS) whose query string
 * carries a token; this keeps them readable without showing the token.
 *
 *   redactUrlQueries('Get "https://h.example/a/b?sig=secret&se=1": EOF')
 *   // 'Get "https://h.example/a/b?…": EOF'
 */
export function redactUrlQueries(text: string): string
export function redactUrlQueries(text: string | null | undefined): string | null | undefined
export function redactUrlQueries(text: string | null | undefined): string | null | undefined {
  if (!text) return text
  return text.replace(/\bhttps?:\/\/[^\s"'<>]+/gi, (url) => {
    const cut = url.search(/[?#]/)
    return cut === -1 ? url : `${url.slice(0, cut)}?…`
  })
}

// scheme://userinfo@ : the userinfo runs to the last "@" before the path.
const URL_USERINFO = /\b([a-z][a-z0-9+.-]{0,31}:\/\/)[^\s/?#"'<>]{1,256}@/gi

/**
 * Replace the credentials of every URL in a piece of text
 * (`scheme://user:pass@host`, any scheme) with `mask`, keeping the scheme and
 * everything from the host on. Idempotent; every quantifier is bounded.
 *
 *   redactUrlCredentials('clone https://ci:s3cret@git.example.com/a.git')
 *   // 'clone https://…@git.example.com/a.git'
 */
export function redactUrlCredentials(text: string, mask = '…'): string {
  if (!text || !text.includes('://')) return text
  return text.replace(URL_USERINFO, (_all, scheme: string) => `${scheme}${mask}@`)
}
