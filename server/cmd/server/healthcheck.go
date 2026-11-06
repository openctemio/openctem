package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// healthcheckTimeout bounds one probe; container runtimes give the check
// command its own timeout on top (Dockerfile HEALTHCHECK --timeout=3s).
const healthcheckTimeout = 3 * time.Second

// runHealthcheck is `server -healthcheck`: GET /health on this container's
// own listener and exit 0 when it answers 200, 1 otherwise. It lets a
// container healthcheck run without a shell or wget in the image. The URL is
// fixed to the loopback address and SERVER_PORT, so nothing in the
// environment can point the probe at another host.
func runHealthcheck(stderr io.Writer) int {
	port := 8080
	if v := os.Getenv("SERVER_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			fmt.Fprintf(stderr, "healthcheck: invalid SERVER_PORT %q\n", v)
			return 1
		}
		port = p
	}
	return probeHealth(stderr, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port))+"/health", healthcheckTimeout)
}

// probeHealth returns 0 when url answers 200 within timeout, 1 otherwise.
func probeHealth(stderr io.Writer, url string, timeout time.Duration) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return 1
	}
	// No proxy and no redirects: the probe is about this process only.
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "healthcheck: %s answered %d\n", url, resp.StatusCode)
		return 1
	}
	return 0
}
