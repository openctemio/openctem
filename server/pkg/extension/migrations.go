package extension

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

var migrationFile = regexp.MustCompile(`^(\d{14})_([a-z0-9_]+)\.(up|down)\.sql$`)

// ValidateMigrations checks an extension's migration set: at least one
// migration, only VERSION_name.up.sql / .down.sql files at the root with
// VERSION a 14-digit UTC timestamp, every up with its down, and no version
// used twice.
func ValidateMigrations(m fs.FS) error {
	entries, err := fs.ReadDir(m, ".")
	if err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	type pair struct {
		name     string
		up, down bool
	}
	byVersion := map[string]*pair{}
	for _, e := range entries {
		if e.IsDir() {
			return fmt.Errorf("migrations: unexpected directory %q", e.Name())
		}
		g := migrationFile.FindStringSubmatch(e.Name())
		if g == nil {
			return fmt.Errorf("migrations: %q is not VERSION_name.up.sql or .down.sql", e.Name())
		}
		p := byVersion[g[1]]
		if p == nil {
			p = &pair{name: g[2]}
			byVersion[g[1]] = p
		}
		if p.name != g[2] {
			return fmt.Errorf("migrations: version %s used by %q and %q", g[1], p.name, g[2])
		}
		if g[3] == "up" {
			p.up = true
		} else {
			p.down = true
		}
	}
	if len(byVersion) == 0 {
		return fmt.Errorf("migrations: none")
	}
	versions := make([]string, 0, len(byVersion))
	for v := range byVersion {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	var missing []string
	for _, v := range versions {
		if p := byVersion[v]; !p.up || !p.down {
			missing = append(missing, v+"_"+p.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("migrations: up and down both needed for %s", strings.Join(missing, ", "))
	}
	return nil
}
