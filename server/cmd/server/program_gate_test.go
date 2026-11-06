package main

import (
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/scan"
)

// The ownership gate the scan service is wired with must answer which
// targets only bug-bounty program entries cover (RFC-065 §8), or program
// targets could reach platform sensors.
var _ scan.ProgramTargetChecker = (*easmapp.ActiveGate)(nil)
