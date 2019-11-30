// +build !windows
// +build !notty

package main

import (
	"os"
)

const hasSysTerm = true

var sysTerm = int(os.Stdin.Fd())
