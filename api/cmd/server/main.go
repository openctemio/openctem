// Command server is the stock API server binary. All of the server lives in
// the importable package pkg/server so that a custom build can reuse it.
package main

import "github.com/openctemio/openctem/api/pkg/server"

func main() { server.Main() }
