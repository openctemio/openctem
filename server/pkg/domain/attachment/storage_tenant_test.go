package attachment

import "testing"

func TestStorageConfig_ValidateTenantChoice(t *testing.T) {
	s3 := StorageConfig{Provider: ProviderS3, Bucket: "evidence", Region: "us-east-1", AccessKey: "AK", SecretKey: "SK"}

	bad := map[string]StorageConfig{
		"local with base_path":   {Provider: ProviderLocal, BasePath: "/etc/cron.d"},
		"relative base_path":     {Provider: ProviderLocal, BasePath: "../../tmp"},
		"unknown provider":       {Provider: "gcs"},
		"s3 without keys":        {Provider: ProviderS3, Bucket: "evidence"},
		"s3 with base_path":      func() StorageConfig { c := s3; c.BasePath = "/x"; return c }(),
		"minio without endpoint": func() StorageConfig { c := s3; c.Provider = ProviderMinIO; return c }(),
		"endpoint scheme":        func() StorageConfig { c := s3; c.Endpoint = "gopher://x"; return c }(),
		"endpoint userinfo":      func() StorageConfig { c := s3; c.Endpoint = "http://u:p@minio:9000"; return c }(),
		"bad region":             func() StorageConfig { c := s3; c.Region = "x.evil.com"; return c }(),
		"bad bucket":             func() StorageConfig { c := s3; c.Bucket = "../x"; return c }(),
	}
	for name, c := range bad {
		if err := c.ValidateTenantChoice(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}

	good := []StorageConfig{
		{Provider: ProviderLocal},
		s3,
		func() StorageConfig {
			c := s3
			c.Provider = ProviderMinIO
			c.Endpoint = "https://minio.corp.example:9000"
			return c
		}(),
	}
	for _, c := range good {
		if err := c.ValidateTenantChoice(); err != nil {
			t.Errorf("%+v: unexpected error %v", c, err)
		}
	}
}
