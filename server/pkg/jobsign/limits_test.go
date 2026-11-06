package jobsign

import "testing"

func TestLimitHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://API.example.com:8443/x": "api.example.com", "api.example.com:8443": "api.example.com",
		"api.example.com:8443/tcp": "api.example.com", "Api.Example.com.": "api.example.com", "10.0.0.5": "10.0.0.5",
		"[2001:db8::1]:443": "2001:db8::1", "10.0.0.0/24": "", "": "",
	} {
		if got := LimitHost(in); got != want {
			t.Errorf("LimitHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// The API and the signer accept exactly the limits a sensor accepts
// (sdk-go scopelimit.Validate): anything else would be refused there.
func TestValidateLimits(t *testing.T) {
	targets := []string{"https://shop.example.com/api/", "api.example.com:8443"}
	good := []Limit{
		{Host: "shop.example.com", Ports: "443", Protocol: "tcp", PathPrefix: "/api"},
		{Host: "api.example.com", Ports: "8443,9000-9010", Protocol: "tcp"},
		{Host: "shop.example.com", PathPrefix: "/api/v2/"},
	}
	if err := ValidateLimits(good, targets); err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]Limit{
		"other host":    {Host: "evil.example.org", Ports: "443"},
		"upper host":    {Host: "SHOP.example.com", Ports: "443"},
		"nothing":       {Host: "shop.example.com"},
		"unsorted":      {Host: "shop.example.com", Ports: "443,80"},
		"adjacent":      {Host: "shop.example.com", Ports: "80,81"},
		"overlap":       {Host: "shop.example.com", Ports: "80-90,85"},
		"leading zero":  {Host: "shop.example.com", Ports: "0443"},
		"protocol":      {Host: "shop.example.com", Protocol: "sctp"},
		"udp path":      {Host: "shop.example.com", Protocol: "udp", PathPrefix: "/a"},
		"relative":      {Host: "shop.example.com", PathPrefix: "api"},
		"dot segment":   {Host: "shop.example.com", PathPrefix: "/api/../admin"},
		"dot param":     {Host: "shop.example.com", PathPrefix: "/api/..;/admin"},
		"escape":        {Host: "shop.example.com", PathPrefix: "/api%2fadmin"},
		"backslash":     {Host: "shop.example.com", PathPrefix: `/api\admin`},
		"double slash":  {Host: "shop.example.com", PathPrefix: "/a//b"},
		"query":         {Host: "shop.example.com", PathPrefix: "/a?b"},
		"control":       {Host: "shop.example.com", PathPrefix: "/a\nb"},
		"too many rngs": {Host: "shop.example.com", Ports: "1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63,65"},
	} {
		if err := ValidateLimits([]Limit{l}, targets); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
