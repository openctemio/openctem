package attachment

import "testing"

func TestIsR2Endpoint(t *testing.T) {
	yes := []string{"https://a.r2.cloudflarestorage.com", "https://a.eu.r2.cloudflarestorage.com:443/", "a.fedramp.r2.cloudflarestorage.com", "https://A.R2.CloudflareStorage.com."}
	no := []string{"", "https://s3.amazonaws.com", "http://minio:9000", "https://r2.cloudflarestorage.com.evil.example", "https://evilr2.cloudflarestorage.com.example.com"}
	for _, e := range yes {
		if !IsR2Endpoint(e) {
			t.Errorf("%q should be R2", e)
		}
	}
	for _, e := range no {
		if IsR2Endpoint(e) {
			t.Errorf("%q should not be R2", e)
		}
	}
}
