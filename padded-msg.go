package main

import (
	"fmt"
	"github.com/raz-varren/log"
	"strings"
	"sync"
)

// NewPaddedMsgs allocates a new *PaddedMsgs
func NewPaddedMsgs() *PaddedMsgs {
	return &PaddedMsgs{
		mu:      &sync.Mutex{},
		longest: 0,
	}
}

type PaddedMsgs struct {
	mu      *sync.Mutex
	longest int
}

// Msg dynamically pads the left of each new prefix to line up with the longest prefix previously used.
func (m *PaddedMsgs) Msg(prefix string, msg ...interface{}) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	pLen := len(prefix)

	switch {
	case pLen > m.longest:
		m.longest = pLen
	case pLen < m.longest:
		prefix = strings.Repeat(" ", m.longest-pLen) + prefix
	}

	msgStr := fmt.Sprintln(append([]interface{}{prefix}, msg...)...)
	msgStr = strings.TrimRight(msgStr, "\n\r\t ")

	return msgStr
}

func (m *PaddedMsgs) Info(prefix string, msg ...interface{}) {
	log.Info.Println(m.Msg(prefix, msg...))
}

func (m *PaddedMsgs) Err(prefix string, msg ...interface{}) {
	log.Err.Println(m.Msg(prefix, msg...))
}

func (m *PaddedMsgs) Fatal(prefix string, msg ...interface{}) {
	log.Err.Fatalln(m.Msg(prefix, msg...))
}

func (m *PaddedMsgs) Warn(prefix string, msg ...interface{}) {
	log.Warn.Println(m.Msg(prefix, msg...))
}
