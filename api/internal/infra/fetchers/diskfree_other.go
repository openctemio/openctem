//go:build !unix

package fetchers

import "errors"

// diskFree is not available on this platform: a fetch is refused (the API
// server runs on Linux).
func diskFree(string) (uint64, error) {
	return 0, errors.New("free disk space is not available on this platform")
}
