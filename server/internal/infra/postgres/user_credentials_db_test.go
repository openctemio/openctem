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

	// research/189 B1a-1: failures while locked still count, each further run
	// of maxAttempts failures doubles the lock (capped), and a run in between
	// keeps the current lock.
	t.Run("lockout backs off and caps", func(t *testing.T) {
		lockFor := func(t *testing.T, before int) (attempts int, secs float64, locked bool) {
			t.Helper()
			if _, err := db.ExecContext(ctx, `UPDATE users SET failed_login_attempts = $2, locked_until = NULL WHERE id = $1`, id.String(), before); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.RecordFailedLogin(ctx, id, 5, 15*time.Minute); err != nil {
				t.Fatal(err)
			}
			var until *time.Time
			if err := db.QueryRowContext(ctx, `SELECT failed_login_attempts, locked_until FROM users WHERE id = $1`, id.String()).Scan(&attempts, &until); err != nil {
				t.Fatal(err)
			}
			if until == nil {
				return attempts, 0, false
			}
			return attempts, time.Until(*until).Seconds(), true
		}
		if n, _, locked := lockFor(t, 6); n != 7 || locked {
			t.Fatalf("7th failure: attempts=%d locked=%v, want 7 and no new lock", n, locked)
		}
		if n, secs, locked := lockFor(t, 9); n != 10 || !locked || secs < 29*60 || secs > 31*60 {
			t.Fatalf("10th failure: attempts=%d locked=%v for %.0fs, want 10 and about 30m", n, locked, secs)
		}
		if _, secs, locked := lockFor(t, 5+5*40-1); !locked || secs < 23.9*3600 || secs > 24.1*3600 {
			t.Fatalf("long run: locked=%v for %.0fs, want the 24h cap", locked, secs)
		}
	})

	t.Run("a new password clears the lockout", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE users SET failed_login_attempts = 12, locked_until = NOW() + interval '1 hour' WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
		if err := repo.UpdatePasswordHash(ctx, id, "reset-hash"); err != nil {
			t.Fatal(err)
		}
		var attempts int
		var locked bool
		if err := db.QueryRowContext(ctx, `SELECT failed_login_attempts, locked_until IS NOT NULL FROM users WHERE id = $1`, id.String()).Scan(&attempts, &locked); err != nil {
			t.Fatal(err)
		}
		if attempts != 0 || locked {
			t.Fatalf("after a password reset: attempts=%d locked=%v, want 0 and unlocked", attempts, locked)
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
