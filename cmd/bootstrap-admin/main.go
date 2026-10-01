// Package main provides a CLI tool to create the first platform administrator.
// This is used during initial deployment to bootstrap the admin system.
//
// A platform administrator (RFC-022) is a normal sign-in account (users table)
// that belongs to no organization, linked to an admin_users row that holds the
// role, the authenticator and the API key. The administrator signs in on the
// normal /login page and opens the admin console with a TOTP code. This tool
// creates both and links them; when no account exists for the email it creates
// one with a temporary password, printed once.
//
// Usage:
//
//	# Generate a new admin with random API key
//	./bootstrap-admin -db=$DATABASE_URL -email=admin@example.com
//
//	# Link an existing administrator (created before sign-in accounts were
//	# linked) to a sign-in account, keeping its role, key and authenticator
//	./bootstrap-admin -db=$DATABASE_URL -email=admin@example.com -link
//
//	# Use a specific API key (e.g., from environment)
//	./bootstrap-admin -db=$DATABASE_URL -email=admin@example.com -api-key=$BOOTSTRAP_ADMIN_KEY
//
//	# Or via environment variables
//	DATABASE_URL=postgres://... ADMIN_EMAIL=admin@example.com ./bootstrap-admin
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"github.com/openctemio/api/pkg/password"
)

func main() {
	// Parse flags
	dbURL := flag.String("db", "", "Database URL (or set DATABASE_URL env)")
	email := flag.String("email", "", "Admin email (or set ADMIN_EMAIL env)")
	name := flag.String("name", "", "Admin name (defaults to email prefix)")
	apiKey := flag.String("api-key", "", "API key to use (or set BOOTSTRAP_ADMIN_KEY env, generates random if not set)")
	role := flag.String("role", "super_admin", "Admin role: super_admin, ops_admin, readonly")
	force := flag.Bool("force", false, "Overwrite existing admin with same email")
	linkOnly := flag.Bool("link", false, "Only link the existing admin with this email to a sign-in account (keeps role, API key and authenticator)")
	flag.Parse()

	// Get values from env if not provided
	databaseURL := *dbURL
	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	// Fallback: build DATABASE_URL from individual DB_* environment variables
	// This allows running inside containers that use separate DB_* vars
	if databaseURL == "" {
		dbHost := os.Getenv("DB_HOST")
		dbPort := os.Getenv("DB_PORT")
		dbUser := os.Getenv("DB_USER")
		dbPassword := os.Getenv("DB_PASSWORD")
		dbName := os.Getenv("DB_NAME")
		dbSSLMode := os.Getenv("DB_SSLMODE")

		if dbHost != "" && dbUser != "" && dbPassword != "" && dbName != "" {
			if dbPort == "" {
				dbPort = "5432"
			}
			if dbSSLMode == "" {
				dbSSLMode = "disable"
			}
			databaseURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
				dbUser, dbPassword, dbHost, dbPort, dbName, dbSSLMode)
		}
	}
	if databaseURL == "" {
		fatal("Database URL required. Use -db flag, set DATABASE_URL, or set DB_HOST/DB_USER/DB_PASSWORD/DB_NAME env vars")
	}

	adminEmail := *email
	if adminEmail == "" {
		adminEmail = os.Getenv("ADMIN_EMAIL")
	}
	if adminEmail == "" {
		fatal("Admin email required. Use -email flag or set ADMIN_EMAIL env")
	}

	adminAPIKey := *apiKey
	if adminAPIKey == "" {
		adminAPIKey = os.Getenv("BOOTSTRAP_ADMIN_KEY")
	}

	adminRole := *role
	if adminRole == "viewer" { // accepted for older scripts; the role is readonly
		adminRole = "readonly"
	}
	if adminRole != "super_admin" && adminRole != "ops_admin" && adminRole != "readonly" {
		fatal("Invalid role. Must be one of: super_admin, ops_admin, readonly")
	}

	// Set admin name (default to email prefix if not provided)
	adminName := *name
	if adminName == "" {
		adminName = os.Getenv("ADMIN_NAME")
	}
	if adminName == "" {
		// Extract name from email (e.g., "admin@example.com" -> "admin")
		parts := strings.Split(adminEmail, "@")
		adminName = parts[0]
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

	// Check if admin_users table exists
	var tableExists bool
	err = db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_name = 'admin_users'
		)
	`).Scan(&tableExists)
	if err != nil {
		fatal("Error checking table: %v", err)
	}
	if !tableExists {
		fatal("admin_users table does not exist. Run migrations first.")
	}
	var linkable bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'admin_users' AND column_name = 'user_id')
	`).Scan(&linkable); err != nil {
		fatal("Error checking schema: %v", err)
	}
	if !linkable {
		fatal("admin_users.user_id is missing. Run migrations first (000226).")
	}

	if *linkOnly {
		var adminID string
		if err := db.QueryRowContext(ctx, `SELECT id FROM admin_users WHERE email = $1`, adminEmail).Scan(&adminID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				fatal("No admin with email %s. Run without -link to create one.", adminEmail)
			}
			fatal("Error looking up admin: %v", err)
		}
		temp := linkAccount(ctx, db, adminID, adminEmail, adminName)
		fmt.Println()
		fmt.Println("=== Administrator linked to a sign-in account ===")
		fmt.Printf("  Admin ID: %s\n", adminID)
		fmt.Printf("  Email:    %s\n", adminEmail)
		printSignIn(adminEmail, temp)
		return
	}

	// Check if admin with this email already exists
	var existingID string
	err = db.QueryRowContext(ctx, `
		SELECT id FROM admin_users WHERE email = $1
	`, adminEmail).Scan(&existingID)
	if err == nil {
		if !*force {
			fatal("Admin with email %s already exists (ID: %s). Use -force to overwrite.", adminEmail, existingID)
		}
		// Delete existing admin
		_, err = db.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, existingID)
		if err != nil {
			fatal("Error deleting existing admin: %v", err)
		}
		fmt.Printf("Deleted existing admin: %s\n", existingID)
	} else if !errors.Is(err, sql.ErrNoRows) {
		fatal("Error checking existing admin: %v", err)
	}

	// Generate API key if not provided
	if adminAPIKey == "" {
		adminAPIKey = generateAPIKey()
		fmt.Println("Generated new API key (no existing key provided)")
	}

	// Hash the API key
	hashedKey, err := bcrypt.GenerateFromPassword([]byte(adminAPIKey), bcrypt.DefaultCost)
	if err != nil {
		fatal("Error hashing API key: %v", err)
	}

	// Create admin user
	adminID := uuid.New().String()
	now := time.Now()

	_, err = db.ExecContext(ctx, `
		INSERT INTO admin_users (id, email, name, role, api_key_hash, api_key_prefix, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, adminID, adminEmail, adminName, adminRole, string(hashedKey), extractPrefix(adminAPIKey), true, now, now)
	if err != nil {
		fatal("Error creating admin: %v", err)
	}
	temp := linkAccount(ctx, db, adminID, adminEmail, adminName)

	// Print success message
	fmt.Println()
	fmt.Println("=== Bootstrap Admin Created ===")
	fmt.Printf("  ID:    %s\n", adminID)
	fmt.Printf("  Name:  %s\n", adminName)
	fmt.Printf("  Email: %s\n", adminEmail)
	fmt.Printf("  Role:  %s\n", adminRole)
	fmt.Println()
	fmt.Println("API Key (save this, it won't be shown again):")
	fmt.Printf("  %s\n", adminAPIKey)
	fmt.Println()
	fmt.Println("Configure the CLI:")
	fmt.Println("  export OPENCTEM_API_KEY=" + adminAPIKey)
	fmt.Println("  export OPENCTEM_API_URL=https://your-api-url")
	fmt.Println()
	fmt.Println("  # Or save to config file:")
	fmt.Println("  openctem-admin config set-context prod --api-url=https://your-api-url --api-key=" + adminAPIKey)
	fmt.Println("  openctem-admin config use-context prod")
	fmt.Println()
	fmt.Println("Test the connection:")
	fmt.Println("  openctem-admin cluster-info")
	fmt.Println()
	printSignIn(adminEmail, temp)
}

// linkAccount links the admin to the users-table account with its email,
// creating a local account with a temporary password when none exists (the
// password is returned; empty when an existing account was linked). An
// account that belongs to an organization is refused: administrators belong
// to none, so they need a separate account.
func linkAccount(ctx context.Context, db *sql.DB, adminID, email, name string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	var userID, temp string
	err := db.QueryRowContext(ctx, `SELECT id FROM users WHERE lower(email) = $1`, email).Scan(&userID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		temp = temporaryPassword()
		hash, herr := password.New().Hash(temp)
		if herr != nil {
			fatal("Error hashing password: %v", herr)
		}
		userID = uuid.New().String()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO users (id, email, name, password_hash, auth_provider, status, email_verified, created_at, updated_at)
			VALUES ($1, $2, $3, $4, 'local', 'active', true, NOW(), NOW())
		`, userID, email, name, hash); err != nil {
			fatal("Error creating sign-in account: %v", err)
		}
	case err != nil:
		fatal("Error looking up sign-in account: %v", err)
	default:
		var orgs int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_members WHERE user_id = $1`, userID).Scan(&orgs); err != nil {
			fatal("Error checking memberships: %v", err)
		}
		if orgs > 0 {
			fatal("The account %s belongs to %d organization(s). A platform administrator belongs to none; use a separate email.", email, orgs)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE admin_users SET user_id = $2, updated_at = NOW() WHERE id = $1`, adminID, userID); err != nil {
		fatal("Error linking the account: %v", err)
	}
	return temp
}

func printSignIn(email, temp string) {
	fmt.Println()
	fmt.Println("Admin console (browser): sign in at <ui-url>/login, then open the console")
	fmt.Println("and enroll an authenticator app on first use.")
	fmt.Printf("  Email:    %s\n", email)
	if temp != "" {
		fmt.Printf("  Password: %s   (temporary, shown once; change it after signing in)\n", temp)
	} else {
		fmt.Println("  Password: the existing account's password")
	}
}

// temporaryPassword returns a random password meeting the default policy.
func temporaryPassword() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		fatal("Error generating password: %v", err)
	}
	out := make([]byte, len(buf))
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return "Oc" + string(out) + "7!"
}

// extractPrefix extracts the lookup prefix from an API key.
// Must match the prefix format used by admin.ExtractAPIKeyPrefix:
// "oc-admin-" (9 chars) + first 8 hex chars = 17 chars total.
func extractPrefix(apiKey string) string {
	const prefix = "oc-admin-"
	prefixLen := len(prefix) + 8
	if len(apiKey) >= prefixLen {
		return apiKey[:prefixLen]
	}
	return apiKey
}

// generateAPIKey generates a secure random API key
func generateAPIKey() string {
	// Format: oc-admin-<32 random hex chars>
	// Total: 41 chars
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		fatal("Error generating random key: %v", err)
	}
	return "oc-admin-" + hex.EncodeToString(bytes)
}

func fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(os.Stderr, "Error: "+msg)
	os.Exit(1)
}
