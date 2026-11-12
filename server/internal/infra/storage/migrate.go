package storage

// Copying the server file storage between drivers, local ↔ s3
// (api/docs/architecture/file-storage.md, "Moving between local and S3").
// Rows record "local" for the server storage whatever its driver, and a file
// keeps the same namespace and key in either driver, so a copy needs no
// database change: copy, verify, then switch STORAGE_PROVIDER.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
)

// ObjectStore is a driver seen object by object: what the copy needs.
type ObjectStore interface {
	// ListObjects calls fn for every object, as namespace and key.
	ListObjects(ctx context.Context, fn func(namespace, key string, size int64) error) error
	// StatObject returns an object's size, and false when it does not exist.
	StatObject(ctx context.Context, namespace, key string) (int64, bool, error)
	// PutObject writes an object at exactly this namespace and key.
	PutObject(ctx context.Context, namespace, key string, r io.Reader) error
	Download(ctx context.Context, namespace, key string) (io.ReadCloser, string, error)
}

var (
	_ ObjectStore = (*LocalStorage)(nil)
	_ ObjectStore = (*S3Storage)(nil)
)

// tempUploadPrefix names the local driver's temporary upload files.
const tempUploadPrefix = ".upload-"

// checkObjectKey refuses a key that could leave its namespace or that is a
// temporary upload file.
func checkObjectKey(key string) error {
	if key == "" || key == "." || key == ".." || strings.ContainsAny(key, "/\\\x00") || strings.HasPrefix(key, tempUploadPrefix) {
		return fmt.Errorf("invalid object key %q", key)
	}
	return nil
}

// ListObjects walks {base}/{namespace}/{key}. Symlinks, deeper directories
// and temporary upload files are skipped, never followed.
func (s *LocalStorage) ListObjects(ctx context.Context, fn func(namespace, key string, size int64) error) error {
	nss, err := os.ReadDir(s.basePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read storage dir: %w", err)
	}
	for _, ns := range nss {
		if !ns.IsDir() || checkNamespace(ns.Name()) != nil {
			continue // a symlink or stray file is not a namespace
		}
		files, err := os.ReadDir(filepath.Join(s.basePath, ns.Name()))
		if err != nil {
			return fmt.Errorf("read namespace %s: %w", ns.Name(), err)
		}
		for _, f := range files {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !f.Type().IsRegular() || checkObjectKey(f.Name()) != nil {
				continue
			}
			info, err := f.Info()
			if err != nil {
				return err
			}
			if err := fn(ns.Name(), f.Name(), info.Size()); err != nil {
				return err
			}
		}
	}
	return nil
}

// StatObject returns the size of a regular file.
func (s *LocalStorage) StatObject(_ context.Context, namespace, key string) (int64, bool, error) {
	if err := checkNamespace(namespace); err != nil {
		return 0, false, err
	}
	if err := checkObjectKey(key); err != nil {
		return 0, false, err
	}
	p, err := s.safePath(namespace, key)
	if err != nil {
		return 0, false, err
	}
	st, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !st.Mode().IsRegular() {
		return 0, false, fmt.Errorf("%s/%s is not a regular file", namespace, key)
	}
	return st.Size(), true, nil
}

// PutObject writes key atomically (temporary file, sync, rename), private.
func (s *LocalStorage) PutObject(_ context.Context, namespace, key string, r io.Reader) error {
	if err := checkNamespace(namespace); err != nil {
		return err
	}
	if err := checkObjectKey(key); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(s.basePath, namespace), 0o700); err != nil {
		return fmt.Errorf("create namespace dir: %w", err)
	}
	p, err := s.safePath(namespace, key)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), tempUploadPrefix+"*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once renamed
	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, p)
}

// ListObjects lists the bucket; an object is {namespace}/{key}, anything
// else in the bucket is skipped.
func (s *S3Storage) ListObjects(ctx context.Context, fn func(namespace, key string, size int64) error) error {
	pages := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list bucket: %w", err)
		}
		for _, obj := range page.Contents {
			ns, key, ok := strings.Cut(aws.ToString(obj.Key), "/")
			if !ok || checkNamespace(ns) != nil || checkObjectKey(key) != nil {
				continue
			}
			if err := fn(ns, key, aws.ToInt64(obj.Size)); err != nil {
				return err
			}
		}
	}
	return nil
}

// StatObject returns an object's size.
func (s *S3Storage) StatObject(ctx context.Context, namespace, key string) (int64, bool, error) {
	if err := checkNamespace(namespace); err != nil {
		return 0, false, err
	}
	if err := checkObjectKey(key); err != nil {
		return 0, false, err
	}
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(path.Join(namespace, key)),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && (apiErr.ErrorCode() == "NotFound" || apiErr.ErrorCode() == "NoSuchKey") {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("head object: %w", err)
	}
	return aws.ToInt64(out.ContentLength), true, nil
}

// PutObject writes an object at exactly namespace/key (with the configured
// server-side encryption).
func (s *S3Storage) PutObject(ctx context.Context, namespace, key string, r io.Reader) error {
	if err := checkNamespace(namespace); err != nil {
		return err
	}
	if err := checkObjectKey(key); err != nil {
		return err
	}
	body, size, cleanup, err := seekableBody(r)
	if err != nil {
		return err
	}
	defer cleanup()
	return s.putObject(ctx, path.Join(namespace, key), "application/octet-stream", body, size)
}

// MigrateOptions control a copy.
type MigrateOptions struct {
	// Namespace limits the copy to one namespace (a tenant id); empty = all.
	Namespace string
	// DryRun lists what would be copied without writing.
	DryRun bool
	// Verify also hashes objects already at the destination with the same
	// size, instead of taking them as copied.
	Verify bool
	// Progress, when set, gets one line per copied or failed object.
	Progress io.Writer
}

// MigrateResult counts what a copy did.
type MigrateResult struct {
	Copied, Skipped, Failed int
	Bytes                   int64
}

// Migrate copies every object of src to dst under the same namespace and
// key. An object already at the destination with the same size is skipped
// (with Verify: and the same SHA-256), so a run can be repeated after an
// interruption. Each copy is read back from dst and compared by SHA-256; a
// mismatch is a failure. src is never changed.
func Migrate(ctx context.Context, src, dst ObjectStore, opts MigrateOptions) (MigrateResult, error) {
	var res MigrateResult
	logf := func(format string, args ...any) {
		if opts.Progress != nil {
			_, _ = fmt.Fprintf(opts.Progress, format+"\n", args...)
		}
	}
	err := src.ListObjects(ctx, func(ns, key string, size int64) error {
		if opts.Namespace != "" && ns != opts.Namespace {
			return nil
		}
		dsize, found, err := dst.StatObject(ctx, ns, key)
		if err != nil {
			res.Failed++
			logf("FAIL %s/%s: %v", ns, key, err)
			return nil
		}
		if found && dsize == size {
			if !opts.Verify {
				res.Skipped++
				return nil
			}
			same, err := sameObject(ctx, src, dst, ns, key)
			if err == nil && same {
				res.Skipped++
				return nil
			}
		}
		if opts.DryRun {
			res.Copied++
			res.Bytes += size
			logf("would copy %s/%s (%d bytes)", ns, key, size)
			return nil
		}
		if err := copyObject(ctx, src, dst, ns, key); err != nil {
			res.Failed++
			logf("FAIL %s/%s: %v", ns, key, err)
			return nil
		}
		res.Copied++
		res.Bytes += size
		logf("copied %s/%s (%d bytes)", ns, key, size)
		return nil
	})
	return res, err
}

func hashObject(ctx context.Context, s ObjectStore, ns, key string) ([]byte, error) {
	rc, _, err := s.Download(ctx, ns, key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func sameObject(ctx context.Context, src, dst ObjectStore, ns, key string) (bool, error) {
	a, err := hashObject(ctx, src, ns, key)
	if err != nil {
		return false, err
	}
	b, err := hashObject(ctx, dst, ns, key)
	if err != nil {
		return false, err
	}
	return bytes.Equal(a, b), nil
}

func copyObject(ctx context.Context, src, dst ObjectStore, ns, key string) error {
	rc, _, err := src.Download(ctx, ns, key)
	if err != nil {
		return fmt.Errorf("read source: %w", err)
	}
	defer func() { _ = rc.Close() }()
	h := sha256.New()
	if err := dst.PutObject(ctx, ns, key, io.TeeReader(rc, h)); err != nil {
		return fmt.Errorf("write destination: %w", err)
	}
	want := h.Sum(nil)
	got, err := hashObject(ctx, dst, ns, key)
	if err != nil {
		return fmt.Errorf("read back: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("the copy does not match the source (SHA-256)")
	}
	return nil
}

// ErrNotObjectStore: a storage that cannot be copied object by object.
var ErrNotObjectStore = errors.New("storage cannot be copied object by object")

// AsObjectStore returns fs as an ObjectStore.
func AsObjectStore(fs attachment.FileStorage) (ObjectStore, error) {
	if o, ok := fs.(ObjectStore); ok {
		return o, nil
	}
	return nil, ErrNotObjectStore
}
