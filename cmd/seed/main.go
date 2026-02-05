package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/lib/pq"
)

func main() {
	// Parse flags
	dbURL := flag.String("db", "", "Database URL (or set DATABASE_URL env)")
	seedFile := flag.String("file", "migrations/seed/seed_data.sql", "Path to seed SQL file")
	clean := flag.Bool("clean", false, "Clean existing data before seeding")
	flag.Parse()

	// Get database URL
	databaseURL := *dbURL
	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	if databaseURL == "" {
		fmt.Println("Error: Database URL required. Use -db flag or set DATABASE_URL env")
		os.Exit(1)
	}

	// Connect to database
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Test connection
	if err := db.PingContext(ctx); err != nil {
		fmt.Printf("Error pinging database: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Connected to database")

	// Clean existing data if requested
	if *clean {
		if err := cleanDatabase(ctx, db); err != nil {
			fmt.Printf("Error cleaning database: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Cleaned existing seed data")
	}

	// Read seed file
	seedPath, err := filepath.Abs(*seedFile)
	if err != nil {
		fmt.Printf("Error resolving seed file path: %v\n", err)
		os.Exit(1)
	}

	seedSQL, err := os.ReadFile(seedPath)
	if err != nil {
		fmt.Printf("Error reading seed file %s: %v\n", seedPath, err)
		os.Exit(1)
	}

	// Execute seed SQL
	fmt.Printf("Executing seed file: %s\n", seedPath)
	if _, err := db.ExecContext(ctx, string(seedSQL)); err != nil {
		fmt.Printf("Error executing seed SQL: %v\n", err)
		os.Exit(1)
	}

	// Print summary
	printSummary(ctx, db)
	fmt.Println("\nSeed completed successfully!")
}

func cleanDatabase(ctx context.Context, db *sql.DB) error {
	// Order matters due to foreign key constraints
	tables := []string{
		"findings",
		"exposures",
		"attack_path_nodes",
		"attack_paths",
		"components",
		"assets",
		"tenant_invitations",
		"tenant_members",
		"tenants",
		"vulnerabilities",
		// Don't delete users as they might be linked to sessions
	}

	// Only delete seeded data (with specific UUIDs)
	cleanQueries := []string{
		// Delete findings with seed IDs
		`DELETE FROM findings WHERE id::text LIKE 'f%000000-0000-0000-0000-00000000%'`,
		// Delete exposures with seed IDs
		`DELETE FROM exposures WHERE id::text LIKE 'e%000000-0000-0000-0000-00000000%'`,
		// Delete components with seed IDs
		`DELETE FROM components WHERE id::text LIKE 'c%000000-0000-0000-0000-00000000%'`,
		// Delete assets with seed IDs
		`DELETE FROM assets WHERE id::text LIKE 'a%000000-0000-0000-0000-00000000%'`,
		// Delete tenant_members for seed tenants
		`DELETE FROM tenant_members WHERE tenant_id IN (
			'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
			'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
			'cccccccc-cccc-cccc-cccc-cccccccccccc'
		)`,
		// Delete tenants with seed IDs
		`DELETE FROM tenants WHERE id IN (
			'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
			'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
			'cccccccc-cccc-cccc-cccc-cccccccccccc'
		)`,
		// Delete vulnerabilities with seed IDs
		`DELETE FROM vulnerabilities WHERE id::text LIKE 'v0000000-0000-0000-0000-00000000%'`,
		// Delete users with seed IDs (be careful with this)
		`DELETE FROM users WHERE id IN (
			'11111111-1111-1111-1111-111111111111',
			'22222222-2222-2222-2222-222222222222',
			'33333333-3333-3333-3333-333333333333',
			'44444444-4444-4444-4444-444444444444',
			'55555555-5555-5555-5555-555555555555',
			'66666666-6666-6666-6666-666666666666'
		)`,
	}

	for _, query := range cleanQueries {
		if _, err := db.ExecContext(ctx, query); err != nil {
			// Log but continue - some tables might not exist
			fmt.Printf("Warning: %v\n", err)
		}
	}

	// Alternative: truncate all tables (more aggressive)
	_ = tables

	return nil
}

func printSummary(ctx context.Context, db *sql.DB) {
	fmt.Println("\n=== Seed Data Summary ===")

	counts := []struct {
		table string
		query string
	}{
		{"Users", "SELECT COUNT(*) FROM users"},
		{"Tenants", "SELECT COUNT(*) FROM tenants"},
		{"Tenant Members", "SELECT COUNT(*) FROM tenant_members"},
		{"Assets", "SELECT COUNT(*) FROM assets"},
		{"Repositories", "SELECT COUNT(*) FROM assets WHERE asset_type = 'repository'"},
		{"Components", "SELECT COUNT(*) FROM components"},
		{"Vulnerabilities", "SELECT COUNT(*) FROM vulnerabilities"},
		{"Findings", "SELECT COUNT(*) FROM findings"},
		{"Exposures", "SELECT COUNT(*) FROM exposures"},
	}

	for _, c := range counts {
		var count int
		if err := db.QueryRowContext(ctx, c.query).Scan(&count); err != nil {
			fmt.Printf("  %s: (error: %v)\n", c.table, err)
		} else {
			fmt.Printf("  %s: %d\n", c.table, count)
		}
	}
}
