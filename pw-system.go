package main

import (
	"bytes"
	"fmt"
	"github.com/awnumar/memguard"
	"github.com/raz-varren/log"
	"golang.org/x/crypto/ssh/terminal"
	"sync"
)

const (
	minPassLen = 8
)

type errMinPass struct {
	min int
}

func (e errMinPass) Error() string {
	return fmt.Sprintf("password must be at least %d characters long", e.min)
}

// NewPWSystem returns a *PWSystem suitable for managing passwords
func NewPWSystem() *PWSystem {
	return &PWSystem{
		mu:  &sync.Mutex{},
		pws: []*memguard.LockedBuffer{},
		c:   0,
	}
}

type PWSystem struct {
	mu  *sync.Mutex
	pws []*memguard.LockedBuffer
	c   int
}

func (p *PWSystem) Prompt(ask string, allowEmpty bool) []byte {
	fmt.Println(ask)
	pass, err := terminal.ReadPassword(sysTerm)
	if err != nil {
		log.Err.Fatalln(err)
	}

	// we may want to know if the user gave us an empty password
	if len(pass) == 0 && allowEmpty {
		return nil
	}

	p.checkLen(pass)

	return p.AddPass(pass)
}

func (p *PWSystem) PromptConfirm(ask, confirm, fail string) []byte {
	fmt.Println(ask)
	pass, err := terminal.ReadPassword(sysTerm)
	if err != nil {
		log.Err.Fatalln(err)
	}

	p.checkLen(pass)

	fmt.Println(confirm)
	pass2, err := terminal.ReadPassword(sysTerm)
	if err != nil {
		log.Err.Fatalln(err)
	}

	if !bytes.Equal(pass, pass2) {
		log.Err.Fatalln(fail)
	}

	return p.AddPass(pass)
}

func (p *PWSystem) checkLen(pass []byte) {
	if len(pass) < minPassLen {
		log.Err.Fatalln(errMinPass{min: minPassLen})
	}
}

func (p *PWSystem) AddPass(pass []byte) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()

	pw := memguard.NewBufferFromBytes(pass)
	p.pws = append(p.pws, pw)
	return pw.Bytes()
}

func (p *PWSystem) First() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pws[0].Bytes()
}

func (p *PWSystem) Next() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.c >= len(p.pws) {
		return nil
	}
	pw := p.pws[p.c]
	p.c++
	return pw.Bytes()
}

func (p *PWSystem) HasNext() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.c < len(p.pws)
}

func (p *PWSystem) Rewind() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.c = 0
}

func (p *PWSystem) All() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()

	pws := [][]byte{}
	for _, pw := range p.pws {
		pws = append(pws, pw.Bytes())
	}
	return pws
}

func (p *PWSystem) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.pws)
}

func (p *PWSystem) Destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pw := range p.pws {
		pw.Destroy()
	}
}
