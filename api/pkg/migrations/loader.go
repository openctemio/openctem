// Package migrations provides edition-aware database migration loading.
package migrations

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Edition represents the product edition.
type Edition string

const (
	EditionCore       Edition = "core"
	EditionEnterprise Edition = "enterprise"
	EditionSaaS       Edition = "saas"
)

// IsValid checks if the edition is valid.
func (e Edition) IsValid() bool {
	switch e {
	case EditionCore, EditionEnterprise, EditionSaaS:
		return true
	default:
		return false
	}
}

// ParseEdition parses an edition string.
func ParseEdition(s string) (Edition, error) {
	e := Edition(strings.ToLower(s))
	if !e.IsValid() {
		return "", fmt.Errorf("invalid edition: %s (valid: core, enterprise, saas)", s)
	}
	return e, nil
}

// Migration represents a database migration file.
type Migration struct {
	Version   string
	Name      string
	Edition   Edition
	Direction string // "up" or "down"
	FilePath  string
}

// String returns the migration identifier.
func (m Migration) String() string {
	return fmt.Sprintf("%s_%s.%s.sql", m.Version, m.Name, m.Direction)
}

// LoadMigrationsFromDir loads migrations from a directory, filtered by edition.
// - EditionCore: only core migrations
// - EditionEnterprise: core + enterprise migrations
// - EditionSaaS: core + enterprise + saas migrations
func LoadMigrationsFromDir(dir string, edition Edition, direction string) ([]Migration, error) {
	var migrations []Migration

	suffix := fmt.Sprintf(".%s.sql", direction)

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, suffix) {
			return nil
		}

		filename := filepath.Base(path)
		// Parse filename: 000001_extensions.up.sql -> version=000001, name=extensions
		baseName := strings.TrimSuffix(filename, suffix)
		parts := strings.SplitN(baseName, "_", 2)
		if len(parts) != 2 {
			return nil // Skip invalid filenames
		}

		version := parts[0]
		name := parts[1]

		// Get edition for this migration
		migEdition := GetMigrationEdition(version)

		// Filter by target edition
		if !ShouldRunMigration(version, edition) {
			return nil
		}

		migrations = append(migrations, Migration{
			Version:   version,
			Name:      name,
			Edition:   migEdition,
			Direction: direction,
			FilePath:  path,
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Sort by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// ReadMigrationContent reads the content of a migration file.
func ReadMigrationContent(m Migration) ([]byte, error) {
	return os.ReadFile(m.FilePath)
}

// GetMigrationVersions returns all migration versions from a list.
func GetMigrationVersions(migrations []Migration) []string {
	versions := make([]string, len(migrations))
	for i, m := range migrations {
		versions[i] = m.Version
	}
	return versions
}

// GroupByEdition groups migrations by their edition.
func GroupByEdition(migrations []Migration) map[Edition][]Migration {
	groups := make(map[Edition][]Migration)
	for _, m := range migrations {
		groups[m.Edition] = append(groups[m.Edition], m)
	}
	return groups
}

// CountByEdition counts migrations by edition.
func CountByEdition(migrations []Migration) map[Edition]int {
	counts := make(map[Edition]int)
	for _, m := range migrations {
		counts[m.Edition]++
	}
	return counts
}
