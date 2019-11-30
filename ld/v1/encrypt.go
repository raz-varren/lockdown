package v1

import (
	"crypto/cipher"
	"errors"
	"hash"
	"io"
	"os"
)

var (
	ErrBadPass = errors.New("password cannot be zero bytes")
)

//NewEnc takes a password, key derivation cost parameters, and an io.Writer and returns
//an io.WriteCloser that encrypts the data written to it.
//
//Close must be called on the returned io.WriteCloser when finished writing
//and before the underlying io.Writer is closed, otherwise the WriteCloser will
//not know when to write the hmac-sha512 signature of the encrypted data
func NewEnc(pass []byte, cp CostParams, w io.Writer) (io.WriteCloser, error) {
	if len(pass) == 0 {
		return nil, ErrBadPass
	}
	ch := newCryptoHeader(&costParams{
		time:    cp.Time,
		memory:  cp.Memory,
		threads: cp.Threads,
	})
	cr := newCryptoRing(pass, ch)

	headerData, _ := ch.MarshalBinary()

	ew := &encWriter{w: w, mac: cr.Mac(), cr: cr}
	sw := &cipher.StreamWriter{S: cr.Stream(), W: ew}

	if _, err := ew.Write(headerData); err != nil {
		return nil, err
	}

	return sw, nil
}

type encWriter struct {
	w   io.Writer
	mac hash.Hash
	cr  *cryptoRing
}

// Write encrypts b and writes it to the underlying writer
func (e *encWriter) Write(b []byte) (int, error) {
	n, err := e.w.Write(b)
	_, macErr := e.mac.Write(b[:n])

	if err != nil {
		return n, err
	}

	return n, macErr
}

// Close must be called once finished writing to e and before closing the underlying writer
func (e *encWriter) Close() error {
	sig := e.mac.Sum(nil)
	e.w.Write(sig)
	e.cr.Destroy()

	if c, ok := e.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// EncryptFile will encrypt fileIn and store the encrypted result at fileOut
func EncryptFile(pass []byte, cp CostParams, fileIn, fileOut string) error {
	encF, err := os.OpenFile(fileOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer encF.Close()

	encW, err := NewEnc(pass, cp, encF)
	if err != nil {
		return err
	}
	defer encW.Close()

	plainFile, err := os.Open(fileIn)
	if err != nil {
		return err
	}
	defer plainFile.Close()

	_, err = io.Copy(encW, plainFile)
	return err
}
