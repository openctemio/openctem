//go:build linux || darwin

package systemstatus

import "syscall"

// diskUsage returns the total and available bytes (available to an
// unprivileged process, as the API runs) of the file system holding path.
func diskUsage(path string) (total, avail uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize) //nolint:gosec // block size is positive
	return st.Blocks * bs, st.Bavail * bs, nil
}
