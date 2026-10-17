//go:build !(linux || darwin)

package systemstatus

import "errors"

func diskUsage(string) (uint64, uint64, error) {
	return 0, 0, errors.New("statfs is not supported on this platform")
}
