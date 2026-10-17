package feedsign_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/contentpkg"
	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/programfeed"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// Each feed's key set has its own maximum validity: the catalog's is a year,
// the program and vulnerability feeds' is 180 days, and a type without one
// refuses every key set.
func TestVerifyKeySet_PerTypeValidity(t *testing.T) {
	now := time.Now().UTC()
	rootPub, root, _ := ed25519.GenerateKey(rand.Reader)
	onlinePub, _, _ := ed25519.GenerateKey(rand.Reader)
	rootID := jobsign.KeyID(rootPub)

	vuln := feedsign.KeySetType{PayloadType: vulnbundle.KeySetPayloadType, Kind: vulnbundle.KeySetKind, MaxValidity: vulnbundle.MaxKeySetValidity}
	cases := []struct {
		name   string
		typ    feedsign.KeySetType
		days   int
		accept bool
	}{
		{"catalog 200d", contentpkg.KeySetType, 200, true},
		{"catalog 365d", contentpkg.KeySetType, 365, true},
		{"catalog 366d", contentpkg.KeySetType, 366, false},
		{"programfeed 180d", programfeed.KeySetType, 180, true},
		{"programfeed 200d", programfeed.KeySetType, 200, false},
		{"vulnbundle 180d", vuln, 180, true},
		{"vulnbundle 200d", vuln, 200, false},
		{"no max validity", feedsign.KeySetType{PayloadType: vuln.PayloadType, Kind: vuln.Kind}, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, err := feedsign.SignKeySet(root, c.typ, 1, now, now.Add(time.Duration(c.days)*24*time.Hour), onlinePub)
			if err != nil {
				t.Fatal(err)
			}
			_, err = feedsign.VerifyKeySet(env, c.typ, rootID, 1, now)
			if c.accept != (err == nil) {
				t.Fatalf("accept=%v, err=%v", c.accept, err)
			}
		})
	}
	if vulnbundle.MaxKeySetValidity != 180*24*time.Hour || programfeed.MaxKeySetValidity != 180*24*time.Hour {
		t.Fatal("programfeed and vulnbundle keep 180 days")
	}
}
