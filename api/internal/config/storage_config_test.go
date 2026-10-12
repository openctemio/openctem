package config

import (
	"strings"
	"testing"
)

func TestLoad_StorageProvider(t *testing.T) {
	cases := []struct {
		name                     string
		provider, bucket, ak, sk string
		wantErr                  string
	}{
		{"default local", "", "", "", "", ""},
		{"local", "local", "", "", "", ""},
		{"s3 complete", "s3", "attachments", "AKIA", "secret", ""},
		{"minio complete", "minio", "attachments", "AKIA", "secret", ""},
		{"s3 without bucket", "s3", "", "AKIA", "secret", "STORAGE_BUCKET"},
		{"s3 without keys", "s3", "attachments", "", "", "STORAGE_ACCESS_KEY"},
		// Used to fall back to local storage with only a log warning.
		{"unknown provider", "gcs", "", "", "", "invalid STORAGE_PROVIDER"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("STORAGE_PROVIDER", tc.provider)
			t.Setenv("STORAGE_BUCKET", tc.bucket)
			t.Setenv("STORAGE_ACCESS_KEY", tc.ak)
			t.Setenv("STORAGE_SECRET_KEY", tc.sk)
			_, err := Load()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
