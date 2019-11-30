// +build notty

package main

import (
	"os"
)

const hasSysTerm = false

var sysTerm = int(os.Stdin.Fd())
