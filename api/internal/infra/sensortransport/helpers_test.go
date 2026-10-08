package sensortransport

import (
	"crypto/tls"
	"math/big"
	"net/http"
	"net/url"
)

// h2Transport speaks HTTP/2 only over TLS with cfg.
func h2Transport(cfg *tls.Config) *http.Transport {
	p := new(http.Protocols)
	p.SetHTTP2(true)
	return &http.Transport{TLSClientConfig: cfg, Protocols: p}
}

type (
	urlT   = url.URL
	bigInt = big.Int
)

var parseURL = url.Parse
