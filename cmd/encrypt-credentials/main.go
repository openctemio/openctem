// Command encrypt-credentials encrypts existing plaintext credentials in the database.
//
// Usage:
//
//	go run ./cmd/encrypt-credentials -db "postgres://..." -key "your-hex-key"
//
// Or using environment variables:
//
//	DATABASE_URL="postgres://..." APP_ENCRYPTION_KEY="your-hex-key" go run ./cmd/encrypt-credentials
package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/crypto"
)

func main() {
	// Parse flags
	dbURL := flag.String("db", "", "Database URL (or set DATABASE_URL env)")
	encryptionKey := flag.String("key", "", "Encryption key in hex (or set APP_ENCRYPTION_KEY env)")
	keyFormat := flag.String("key-format", "", "Key format: hex, base64, raw (auto-detected if not specified)")
	dryRun := flag.Bool("dry-run", false, "Show what would be encrypted without making changes")
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

	// Get encryption key
	keyStr := *encryptionKey
	if keyStr == "" {
		keyStr = os.Getenv("APP_ENCRYPTION_KEY")
	}
	if keyStr == "" {
		fmt.Println("Error: Encryption key required. Use -key flag or set APP_ENCRYPTION_KEY env")
		fmt.Println("Generate a key with: openssl rand -hex 32")
		os.Exit(1)
	}

	// Create cipher
	cipher, err := createCipher(keyStr, *keyFormat)
	if err != nil {
		fmt.Printf("Error creating cipher: %v\n", err)
		os.Exit(1)
	}

	// Connect to database
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		fmt.Printf("Error pinging database: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Connected to database")

	if *dryRun {
		fmt.Println("\n=== DRY RUN MODE - No changes will be made ===")
		fmt.Println()
	}

	// Encrypt integrations table
	integrationsCount, err := encryptIntegrations(ctx, db, cipher, *dryRun)
	if err != nil {
		fmt.Printf("Error encrypting integrations: %v\n", err)
		os.Exit(1)
	}

	// Encrypt scm_connections table
	scmCount, err := encryptSCMConnections(ctx, db, cipher, *dryRun)
	if err != nil {
		fmt.Printf("Error encrypting SCM connections: %v\n", err)
		os.Exit(1)
	}

	// Print summary
	fmt.Println("\n=== Summary ===")
	fmt.Printf("Integrations encrypted: %d\n", integrationsCount)
	fmt.Printf("SCM Connections encrypted: %d\n", scmCount)

	if *dryRun {
		fmt.Println("\nDry run complete. Run without -dry-run to apply changes.")
	} else {
		fmt.Println("\nEncryption complete!")
	}
}

func createCipher(keyStr, format string) (*crypto.Cipher, error) {
	// Auto-detect format if not specified
	if format == "" {
		switch len(keyStr) {
		case 32:
			format = "raw"
		case 64:
			format = "hex"
		case 44:
			format = "base64"
		default:
			return nil, fmt.Errorf("cannot auto-detect key format for length %d", len(keyStr))
		}
	}

	switch format {
	case "hex":
		return crypto.NewCipherFromHex(keyStr)
	case "base64":
		return crypto.NewCipherFromBase64(keyStr)
	case "raw":
		return crypto.NewCipher([]byte(keyStr))
	default:
		return nil, fmt.Errorf("unknown key format: %s", format)
	}
}

// isEncrypted checks if a string looks like it's already encrypted (base64 with reasonable length)
func isEncrypted(value string) bool {
	if value == "" {
		return true // Empty is "encrypted" (nothing to do)
	}

	// Encrypted values are base64 encoded and include nonce (12 bytes) + ciphertext + tag (16 bytes)
	// Minimum length: base64((12 + 1 + 16)) = base64(29) = 40 chars
	// Typical token like "ghp_xxxx" (40 chars) would be: base64((12 + 40 + 16)) = base64(68) = 92 chars

	// Check if it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return false // Not base64, so not encrypted
	}

	// Encrypted data should be at least 29 bytes (nonce + 1 byte + tag)
	if len(decoded) < 29 {
		return false
	}

	// Common plaintext patterns that indicate NOT encrypted
	plaintextPatterns := []string{
		"ghp_",   // GitHub personal access token
		"gho_",   // GitHub OAuth token
		"ghs_",   // GitHub server-to-server token
		"ghr_",   // GitHub refresh token
		"glpat-", // GitLab personal access token
		"Bearer ",
		"Basic ",
	}

	for _, pattern := range plaintextPatterns {
		if strings.HasPrefix(value, pattern) {
			return false
		}
	}

	// If it looks like base64 with reasonable length, assume encrypted
	return true
}

func encryptIntegrations(ctx context.Context, db *sql.DB, cipher *crypto.Cipher, dryRun bool) (int, error) {
	fmt.Println("Processing integrations table...")

	// Check if table exists
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_name = 'integrations'
		)
	`).Scan(&exists)
	if err != nil {
		return 0, fmt.Errorf("check table exists: %w", err)
	}
	if !exists {
		fmt.Println("  Table 'integrations' does not exist, skipping")
		return 0, nil
	}

	// Get all integrations with credentials
	rows, err := db.QueryContext(ctx, `
		SELECT id, credentials_encrypted
		FROM integrations
		WHERE credentials_encrypted IS NOT NULL AND credentials_encrypted != ''
	`)
	if err != nil {
		return 0, fmt.Errorf("query integrations: %w", err)
	}
	defer rows.Close()

	var toEncrypt []struct {
		id          string
		credentials string
	}

	for rows.Next() {
		var id, creds string
		if err := rows.Scan(&id, &creds); err != nil {
			return 0, fmt.Errorf("scan row: %w", err)
		}

		if !isEncrypted(creds) {
			toEncrypt = append(toEncrypt, struct {
				id          string
				credentials string
			}{id, creds})
		}
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate rows: %w", err)
	}

	fmt.Printf("  Found %d integrations with plaintext credentials\n", len(toEncrypt))

	if dryRun || len(toEncrypt) == 0 {
		return len(toEncrypt), nil
	}

	// Encrypt and update
	for _, item := range toEncrypt {
		encrypted, err := cipher.EncryptString(item.credentials)
		if err != nil {
			return 0, fmt.Errorf("encrypt credentials for %s: %w", item.id, err)
		}

		_, err = db.ExecContext(ctx, `
			UPDATE integrations
			SET credentials_encrypted = $1, updated_at = NOW()
			WHERE id = $2
		`, encrypted, item.id)
		if err != nil {
			return 0, fmt.Errorf("update integration %s: %w", item.id, err)
		}

		fmt.Printf("  Encrypted integration: %s\n", item.id)
	}

	return len(toEncrypt), nil
}

func encryptSCMConnections(ctx context.Context, db *sql.DB, cipher *crypto.Cipher, dryRun bool) (int, error) {
	fmt.Println("Processing scm_connections table...")

	// Check if table exists
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_name = 'scm_connections'
		)
	`).Scan(&exists)
	if err != nil {
		return 0, fmt.Errorf("check table exists: %w", err)
	}
	if !exists {
		fmt.Println("  Table 'scm_connections' does not exist, skipping")
		return 0, nil
	}

	// Get all SCM connections with credentials
	rows, err := db.QueryContext(ctx, `
		SELECT id, access_token
		FROM scm_connections
		WHERE access_token IS NOT NULL AND access_token != ''
	`)
	if err != nil {
		return 0, fmt.Errorf("query scm_connections: %w", err)
	}
	defer rows.Close()

	var toEncrypt []struct {
		id          string
		accessToken string
	}

	for rows.Next() {
		var id, token string
		if err := rows.Scan(&id, &token); err != nil {
			return 0, fmt.Errorf("scan row: %w", err)
		}

		if !isEncrypted(token) {
			toEncrypt = append(toEncrypt, struct {
				id          string
				accessToken string
			}{id, token})
		}
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate rows: %w", err)
	}

	fmt.Printf("  Found %d SCM connections with plaintext credentials\n", len(toEncrypt))

	if dryRun || len(toEncrypt) == 0 {
		return len(toEncrypt), nil
	}

	// Encrypt and update
	for _, item := range toEncrypt {
		encrypted, err := cipher.EncryptString(item.accessToken)
		if err != nil {
			return 0, fmt.Errorf("encrypt token for %s: %w", item.id, err)
		}

		_, err = db.ExecContext(ctx, `
			UPDATE scm_connections
			SET access_token = $1, updated_at = NOW()
			WHERE id = $2
		`, encrypted, item.id)
		if err != nil {
			return 0, fmt.Errorf("update scm_connection %s: %w", item.id, err)
		}

		fmt.Printf("  Encrypted SCM connection: %s\n", item.id)
	}

	return len(toEncrypt), nil
}
