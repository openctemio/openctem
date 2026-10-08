package sensortransport

import (
	"crypto/ed25519"
	"crypto/tls"
	"math/big"
	"net/http"
	"net/url"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
)

// h2Transport speaks HTTP/2 only over TLS with cfg.
func h2Transport(cfg *tls.Config) *http.Transport {
	p := new(http.Protocols)
	p.SetHTTP2(true)
	return &http.Transport{TLSClientConfig: cfg, Protocols: p}
}

type (
	urlT           = url.URL
	bigInt         = big.Int
	sensorIdentity = sensorapp.SensorIdentity
	edPub          = ed25519.PublicKey
)

var parseURL = url.Parse
