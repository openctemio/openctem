// Package main provides a CLI tool to create the first tenant with an owner user.
// This is used during initial deployment when registration is disabled.
//
// Usage:
//
//	./bootstrap-tenant -email=admin@company.com -password=SecureP@ss! -team="My Company" -slug=my-company
//
//	# Or via environment variables
//	TENANT_EMAIL=admin@company.com TENANT_PASSWORD=SecureP@ss! TENANT_TEAM_NAME="My Company" TENANT_TEAM_SLUG=my-company ./bootstrap-tenant
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func main() {
	// Parse flags
	dbURL := flag.String("db", "", "Database URL (or set DATABASE_URL env)")
	email := flag.String("email", "", "User email (or set TENANT_EMAIL env)")
	password := flag.String("password", "", "User password (or set TENANT_PASSWORD env)")
	name := flag.String("name", "", "User display name (defaults to email prefix)")
	teamName := flag.String("team", "", "Team/organization name (or set TENANT_TEAM_NAME env)")
	teamSlug := flag.String("slug", "", "Team URL slug (or set TENANT_TEAM_SLUG env)")
	force := flag.Bool("force", false, "Overwrite existing user/tenant with same email/slug")
	flag.Parse()

	// Get values from env if not provided
	databaseURL := resolveDBURL(*dbURL)
	if databaseURL == "" {
		fatal("Database URL required. Use -db flag, set DATABASE_URL, or set DB_HOST/DB_USER/DB_PASSWORD/DB_NAME env vars")
	}

	userEmail := firstNonEmpty(*email, os.Getenv("TENANT_EMAIL"))
	if userEmail == "" {
		fatal("Email required. Use -email flag or set TENANT_EMAIL env")
	}

	userPassword := firstNonEmpty(*password, os.Getenv("TENANT_PASSWORD"))
	if userPassword == "" {
		fatal("Password required. Use -password flag or set TENANT_PASSWORD env")
	}
	if len(userPassword) < 8 {
		fatal("Password must be at least 8 characters")
	}

	tName := firstNonEmpty(*teamName, os.Getenv("TENANT_TEAM_NAME"))
	if tName == "" {
		fatal("Team name required. Use -team flag or set TENANT_TEAM_NAME env")
	}

	tSlug := firstNonEmpty(*teamSlug, os.Getenv("TENANT_TEAM_SLUG"))
	if tSlug == "" {
		// Auto-generate slug from team name
		tSlug = strings.ToLower(strings.ReplaceAll(tName, " ", "-"))
		tSlug = regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(tSlug, "")
	}
	if !slugRegex.MatchString(tSlug) {
		fatal("Invalid slug format. Use lowercase letters, numbers, and hyphens only (e.g., 'my-company')")
	}

	userName := firstNonEmpty(*name, os.Getenv("TENANT_USER_NAME"))
	if userName == "" {
		parts := strings.Split(userEmail, "@")
		userName = parts[0]
	}

	// Connect to database
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		fatal("Error connecting to database: %v", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		fatal("Error pinging database: %v", err)
	}

	// Start transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		fatal("Error starting transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// =========================================================================
	// Step 1: Create or find user
	// =========================================================================

	var userID string
	err = tx.QueryRowContext(ctx, "SELECT id FROM users WHERE email = $1", userEmail).Scan(&userID)
	if err == nil {
		if !*force {
			fatal("User with email %s already exists (ID: %s). Use -force to continue with existing user.", userEmail, userID)
		}
		fmt.Printf("Using existing user: %s\n", userID)
	} else if errors.Is(err, sql.ErrNoRows) {
		// Create new user
		userID = uuid.New().String()
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(userPassword), 12)
		if err != nil {
			fatal("Error hashing password: %v", err)
		}

		now := time.Now()
		_, err = tx.ExecContext(ctx, `
			INSERT INTO users (id, email, name, password_hash, auth_provider, status, email_verified_at, created_at, updated_at)
			VALUES ($1, $2, $3, $4, 'local', 'active', $5, $5, $5)
		`, userID, userEmail, userName, string(passwordHash), now)
		if err != nil {
			fatal("Error creating user: %v", err)
		}
		fmt.Printf("Created user: %s\n", userID)
	} else {
		fatal("Error checking user: %v", err)
	}

	// =========================================================================
	// Step 2: Create or find tenant
	// =========================================================================

	var tenantID string
	err = tx.QueryRowContext(ctx, "SELECT id FROM tenants WHERE slug = $1", tSlug).Scan(&tenantID)
	if err == nil {
		if !*force {
			fatal("Tenant with slug '%s' already exists (ID: %s). Use -force to continue.", tSlug, tenantID)
		}
		fmt.Printf("Using existing tenant: %s\n", tenantID)
	} else if errors.Is(err, sql.ErrNoRows) {
		// Create new tenant
		tenantID = uuid.New().String()
		now := time.Now()
		_, err = tx.ExecContext(ctx, `
			INSERT INTO tenants (id, name, slug, plan_id, created_at, updated_at)
			VALUES ($1, $2, $3, (SELECT id FROM plans WHERE slug = 'free' LIMIT 1), $4, $4)
		`, tenantID, tName, tSlug, now)
		if err != nil {
			// Try without plan_id if plans table doesn't exist
			_, err = tx.ExecContext(ctx, `
				INSERT INTO tenants (id, name, slug, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $4)
			`, tenantID, tName, tSlug, now)
			if err != nil {
				fatal("Error creating tenant: %v", err)
			}
		}
		fmt.Printf("Created tenant: %s (slug: %s)\n", tenantID, tSlug)
	} else {
		fatal("Error checking tenant: %v", err)
	}

	// =========================================================================
	// Step 3: Create owner membership
	// =========================================================================

	var existingMembership string
	err = tx.QueryRowContext(ctx,
		"SELECT id FROM tenant_members WHERE user_id = $1 AND tenant_id = $2",
		userID, tenantID,
	).Scan(&existingMembership)
	if err == nil {
		fmt.Printf("Membership already exists: %s\n", existingMembership)
	} else if errors.Is(err, sql.ErrNoRows) {
		membershipID := uuid.New().String()
		now := time.Now()
		_, err = tx.ExecContext(ctx, `
			INSERT INTO tenant_members (id, user_id, tenant_id, role, joined_at, created_at, updated_at)
			VALUES ($1, $2, $3, 'owner', $4, $4, $4)
		`, membershipID, userID, tenantID, now)
		if err != nil {
			fatal("Error creating membership: %v", err)
		}
		fmt.Printf("Created owner membership\n")
	} else {
		fatal("Error checking membership: %v", err)
	}

	// =========================================================================
	// Step 4: Assign owner role (if user_roles table exists)
	// =========================================================================

	ownerRoleID := "00000000-0000-0000-0000-000000000001" // System owner role

	// Verify the owner role exists in the database
	var roleExists bool
	err = tx.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1)",
		ownerRoleID,
	).Scan(&roleExists)
	if err != nil || !roleExists {
		// Roles table may not exist or role not seeded - try to continue
		fmt.Printf("Warning: could not verify owner role exists (table may not be seeded yet)\n")
	}

	var existingRole string
	err = tx.QueryRowContext(ctx,
		"SELECT role_id FROM user_roles WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3",
		userID, tenantID, ownerRoleID,
	).Scan(&existingRole)
	if errors.Is(err, sql.ErrNoRows) {
		now := time.Now()
		_, err = tx.ExecContext(ctx, `
			INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING
		`, userID, tenantID, ownerRoleID, now)
		if err != nil {
			fatal("Error assigning owner role: %v. The user was created but has no role. Re-run with -force after fixing the issue.", err)
		}
		fmt.Printf("Assigned owner role\n")
	} else if err == nil {
		fmt.Printf("Owner role already assigned\n")
	} else {
		fatal("Error checking role assignment: %v", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		fatal("Error committing transaction: %v", err)
	}

	// Print success
	fmt.Println()
	fmt.Println("=== Tenant Bootstrap Complete ===")
	fmt.Printf("  User:     %s (%s)\n", userName, userEmail)
	fmt.Printf("  Team:     %s\n", tName)
	fmt.Printf("  Slug:     %s\n", tSlug)
	fmt.Printf("  Tenant:   %s\n", tenantID)
	fmt.Printf("  Role:     owner\n")
	fmt.Println()
	fmt.Println("You can now login at your OpenCTEM UI with:")
	fmt.Printf("  Email:    %s\n", userEmail)
	fmt.Printf("  Password: (the password you provided)\n")
	fmt.Println()
	fmt.Printf("  Registration can remain disabled (AUTH_ALLOW_REGISTRATION=false)\n")
	fmt.Printf("  Invite users via: Settings → Users → Invite\n")
}

// resolveDBURL builds database URL from flag or env vars
func resolveDBURL(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if url := os.Getenv("DATABASE_URL"); url != "" {
		return url
	}

	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASSWORD")
	name := os.Getenv("DB_NAME")
	sslmode := os.Getenv("DB_SSLMODE")

	if host != "" && user != "" && pass != "" && name != "" {
		if port == "" {
			port = "5432"
		}
		if sslmode == "" {
			sslmode = "disable"
		}
		return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, pass, host, port, name, sslmode)
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(os.Stderr, "Error: "+msg)
	os.Exit(1)
}
