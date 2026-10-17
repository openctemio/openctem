package bootstrapadmin

// `bootstrap-admin storage migrate` copies the server file storage between
// the local driver and an S3-compatible bucket (the admin-cli image's
// entrypoint is this binary). Design and procedure:
// api/docs/architecture/file-storage.md, "Moving between local and S3".
//
//	# 1. Dry run: what would be copied
//	STORAGE_BUCKET=openctem-attachments STORAGE_REGION=eu-west-1 \
//	STORAGE_ACCESS_KEY=... STORAGE_SECRET_KEY=... \
//	  bootstrap-admin storage migrate -from local -to s3 -local-path /app/data/attachments -dry-run
//	# 2. Copy (repeatable: objects already copied are skipped)
//	  bootstrap-admin storage migrate -from local -to s3 -local-path /app/data/attachments
//	# 3. Stop the API, run the copy once more, set STORAGE_PROVIDER=s3, start the API.
//
// Nothing in the database changes: a file keeps its namespace and key, and
// rows record "local" for the server storage whatever its driver. The source
// is never modified. Organizations' own buckets are not touched.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
)

// Drivers the copy moves between.
const (
	driverLocal = "local"
	driverS3    = "s3"
)

// runStorage dispatches `storage <command>`; it returns the exit code.
func runStorage(args []string) int {
	if len(args) == 0 || args[0] != "migrate" {
		fmt.Fprintln(os.Stderr, "usage: bootstrap-admin storage migrate -from local|s3 -to local|s3 [-local-path DIR] [-tenant ID] [-dry-run] [-verify]")
		return 2
	}
	fsFlags := flag.NewFlagSet("storage migrate", flag.ContinueOnError)
	from := fsFlags.String("from", "", "source driver: local or s3")
	to := fsFlags.String("to", "", "destination driver: local or s3")
	localPath := fsFlags.String("local-path", firstNonEmpty(os.Getenv("STORAGE_LOCAL_PATH"), "./data/attachments"), "local storage directory (STORAGE_LOCAL_PATH)")
	tenant := fsFlags.String("tenant", "", "copy only this organization's namespace (its id)")
	dryRun := fsFlags.Bool("dry-run", false, "list what would be copied, write nothing")
	verify := fsFlags.Bool("verify", false, "also compare SHA-256 of objects already at the destination")
	if err := fsFlags.Parse(args[1:]); err != nil {
		return 2
	}
	if *tenant != "" {
		if err := attachment.ValidateTenantNamespace(*tenant); err != nil {
			fmt.Fprintln(os.Stderr, "storage migrate: -tenant must be an organization id")
			return 2
		}
	}
	if !((*from == driverLocal && *to == driverS3) || (*from == driverS3 && *to == driverLocal)) {
		fmt.Fprintln(os.Stderr, "storage migrate: copy from local to s3, or from s3 to local")
		return 2
	}
	open := func(kind string) (storage.ObjectStore, error) {
		if kind == driverLocal {
			if st, err := os.Stat(*localPath); err != nil || !st.IsDir() {
				if kind == *from {
					return nil, fmt.Errorf("local storage directory %q not found", *localPath)
				}
			}
			return storage.NewLocalStorage(*localPath), nil
		}
		s3s, err := storage.NewOperatorS3Storage(os.Getenv("STORAGE_BUCKET"), os.Getenv("STORAGE_REGION"),
			os.Getenv("STORAGE_ENDPOINT"), os.Getenv("STORAGE_ACCESS_KEY"), os.Getenv("STORAGE_SECRET_KEY"))
		if err != nil {
			return nil, err
		}
		if err := s3s.SetServerSideEncryption(os.Getenv("STORAGE_SSE"), os.Getenv("STORAGE_SSE_KMS_KEY_ID")); err != nil {
			return nil, err
		}
		return s3s, nil
	}
	src, err := open(*from)
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage migrate:", err)
		return 1
	}
	dst, err := open(*to)
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage migrate:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := storage.Migrate(ctx, src, dst, storage.MigrateOptions{
		Namespace: *tenant, DryRun: *dryRun, Verify: *verify, Progress: os.Stdout,
	})
	verb := "copied"
	if *dryRun {
		verb = "to copy"
	}
	fmt.Printf("storage migrate %s -> %s: %d %s (%d bytes), %d already there, %d failed\n",
		*from, *to, res.Copied, verb, res.Bytes, res.Skipped, res.Failed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage migrate:", strings.TrimSpace(err.Error()))
		return 1
	}
	if res.Failed > 0 {
		return 1
	}
	return 0
}
