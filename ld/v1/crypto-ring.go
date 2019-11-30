package v1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"hash"
	"io"
	"sync"
)

type cryptoRing struct {
	mu                 *sync.Mutex
	hashKey, cipherKey *memguard.LockedBuffer
	ch                 *cryptoHeader
	mac                hash.Hash
	stream             cipher.Stream
}

func newCryptoRing(pass []byte, header *cryptoHeader) *cryptoRing {
	if header == nil {
		header = defaultCryptoHeader()
	}
	cr := &cryptoRing{
		mu: &sync.Mutex{},
		ch: header,
	}

	cr.genCrypto(pass)

	return cr
}

func (cr *cryptoRing) genCrypto(pass []byte) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	keyLen := keyLenCipher + keyLenHash
	key := argon2.IDKey(pass, cr.ch.Salt(), cr.ch.cp.Time(), cr.ch.cp.Memory(), cr.ch.cp.Threads(), uint32(keyLen))

	cr.cipherKey = memguard.NewBufferFromBytes(key[:keyLenCipher])
	cr.hashKey = memguard.NewBufferFromBytes(key[keyLenCipher:keyLen])

	cr.mac = hmac.New(sha512.New, cr.hashKey.Bytes())

	block, err := aes.NewCipher(cr.cipherKey.Bytes())
	if err != nil {
		panic(err)
	}

	cr.stream = cipher.NewCTR(block, cr.ch.IV())
}

func (cr *cryptoRing) Mac() hash.Hash {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	return cr.mac
}

func (cr *cryptoRing) Stream() cipher.Stream {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	return cr.stream
}

func (cr *cryptoRing) HeaderLen() int {
	return cr.ch.Len()
}

func (cr *cryptoRing) SigLen() int {
	return lenSig
}

func (cr *cryptoRing) Destroy() {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	cr.hashKey.Destroy()
	cr.cipherKey.Destroy()
}

func fillRand(buf []byte) {
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		// if we can't use the rand reader then all crypto is in question
		// don't continue
		panic(err)
	}
}
