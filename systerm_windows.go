// +build windows
// +build !notty

package main

import (
	"github.com/raz-varren/log"
	"os"
	"syscall"
)

const hasSysTerm = true

var sysTerm = int(syscall.Stdin)

//windows doesn't understand the ANSI color sequences
func init() {
	log.SetDefaultLogger(log.NewLogger(os.Stdout, log.LogLevelDbg))
}
