//go:build unix

package fetchers

import "syscall"

// diskFree is the bytes an unprivileged process may still write under dir.
func diskFree(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil //nolint:gosec // Bsize is positive
}
