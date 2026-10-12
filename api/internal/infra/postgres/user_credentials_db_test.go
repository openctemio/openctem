package postgres

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Settings audit A-M5: UserRepository.Update rewrote the whole row, so
// parallel failed sign-ins lost increments (each wrote its snapshot + 1) and a
// profile save racing a password change could put the old password hash back.
// Credential fields now change only through targeted, atomic updates.
func TestUserRepository_CredentialFieldsAreAtomic(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewUserRepository(&DB{DB: db})
	id := seedGroupsUser(ctx, t, db, "creds.test")
	if _, err := db.ExecContext(ctx, `UPDATE users SET auth_provider = 'local', password_hash = 'old-hash' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}

	t.Run("parallel failed sign-ins all count and lock at the limit", func(t *testing.T) {
		const n = 8
		var wg sync.WaitGroup
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := repo.RecordFailedLogin(ctx, id, 5, 15*time.Minute); err != nil {
					t.Errorf("record failed login: %v", err)
				}
			}()
		}
		wg.Wait()
		var attempts int
		var locked bool
		if err := db.QueryRowContext(ctx, `SELECT failed_login_attempts, locked_until > NOW() FROM users WHERE id = $1`,
			id.String()).Scan(&attempts, &locked); err != nil {
			t.Fatal(err)
		}
		if attempts != n || !locked {
			t.Fatalf("after %d parallel failures: attempts=%d locked=%v, want %d and locked", n, attempts, locked, n)
		}
		if err := repo.RecordSuccessfulLogin(ctx, id); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT failed_login_attempts, locked_until IS NOT NULL FROM users WHERE id = $1`,
			id.String()).Scan(&attempts, &locked); err != nil {
			t.Fatal(err)
		}
		if attempts != 0 || locked {
			t.Fatalf("after a successful sign-in: attempts=%d locked=%v", attempts, locked)
		}
	})

	t.Run("a stale profile save does not put back an old password hash", func(t *testing.T) {
		stale, err := repo.GetByID(ctx, id) // snapshot before the password change
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.UpdatePasswordHash(ctx, id, "new-hash"); err != nil {
			t.Fatal(err)
		}
		stale.UpdateProfile("Renamed", "", "")
		if err := repo.Update(ctx, stale); err != nil {
			t.Fatal(err)
		}
		var hash, name string
		if err := db.QueryRowContext(ctx, `SELECT password_hash, name FROM users WHERE id = $1`, id.String()).Scan(&hash, &name); err != nil {
			t.Fatal(err)
		}
		if hash != "new-hash" || name != "Renamed" {
			t.Fatalf("after a stale profile save: hash=%q name=%q, want new-hash and Renamed", hash, name)
		}
	})
}
