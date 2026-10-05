package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type failingEncryptor struct{ crypto.Encryptor }

func (failingEncryptor) EncryptString(string) (string, error) { return "", errors.New("no key") }

// Evidence storage keys are never stored in plaintext when encryption fails,
// and a key that does not decrypt is an error, not the ciphertext used as the
// key (23b T-M5).
func TestSettingsStorageResolver_FailsClosed(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()
	tenantID := shared.NewID().String()
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1,'Storage',$2)`, tenantID, "storage-fc-"+tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM settings WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	cfg := attachment.StorageConfig{Provider: "s3", Bucket: "b", Region: "eu-west-1", AccessKey: "AKIAPLAIN", SecretKey: "PLAINSECRET"}
	bad := NewSettingsStorageResolver(db, failingEncryptor{}, logger.NewNop())
	if err := bad.SaveTenantStorageConfig(ctx, tenantID, cfg); err == nil {
		t.Fatal("save with a failing encryptor succeeded")
	}
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM settings WHERE tenant_id=$1 AND key='storage_config'`, tenantID).Scan(&n)
	if n != 0 {
		t.Fatal("storage config stored although encryption failed")
	}

	// Stored with one key, read with another: the read is an error.
	k1, _ := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	k2, _ := crypto.NewCipher([]byte("fedcba9876543210fedcba9876543210"))
	if err := NewSettingsStorageResolver(db, k1, logger.NewNop()).SaveTenantStorageConfig(ctx, tenantID, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got, err := NewSettingsStorageResolver(db, k2, logger.NewNop()).GetTenantStorageConfig(ctx, tenantID); err == nil {
		t.Fatalf("undecryptable keys returned without error: %+v", got)
	}
	got, err := NewSettingsStorageResolver(db, k1, logger.NewNop()).GetTenantStorageConfig(ctx, tenantID)
	if err != nil || got.SecretKey != "PLAINSECRET" {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
}
