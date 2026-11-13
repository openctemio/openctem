package pgsql

// The scans entity reads the scans table; every path is a plain column.
func init() { bindings["scans"] = binding{table: "scans", exprs: map[string]string{}} }
