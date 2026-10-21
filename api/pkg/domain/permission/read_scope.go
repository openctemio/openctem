package permission

import "strings"

// IsReadScope reports whether p is a read-only permission (its last segment is
// "read" or "view"). API keys cannot write on the REST API, so a key may carry
// only such scopes; a write scope would make the key look more powerful than
// it is.
func IsReadScope(p string) bool {
	return strings.HasSuffix(p, ":read") || strings.HasSuffix(p, ":view")
}
