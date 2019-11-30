package ld

import (
	"errors"
	"fmt"
	"github.com/raz-varren/lockdown/ld/ldtools"
	"github.com/raz-varren/lockdown/ld/v1"
	"io"
)

var (
	// supported versions
	Versions = ldtools.NewVersionMap(v1.Version)

	ErrBadVer = errors.New("failed to read encryption version")
)

type ErrVerMissing struct {
	ver uint16
}

func (e ErrVerMissing) Error() string {
	return fmt.Sprintf("version (%d) is not supported. supported versions are (%s)", e.ver, Versions.SupList())
}

//NewEnc takes a password, key derivation cost parameters, and an io.Writer and returns
//an io.WriteCloser that encrypts the data written to it.
//
// Close must be called on the returned io.WriteCloser when finished writing
// and before the underlying io.Writer is closed otherwise the WriteCloser will
// not know when to write signatures of the encrypted data
func NewEnc(pass []byte, cp v1.CostParams, w io.Writer) (io.WriteCloser, error) {
	// ideally we can just replace this with newer versions to
	// always keep users on the latest encryption standards
	return v1.NewEnc(pass, cp, w)
}

// NewDec returns an io.ReadCloser that will decrypt r. If the provided password is incorrect,
// and ErrSigMismatch will be returned. ErrSigMismatch may also indicate the encrypted file was
// tampered with, as there is no way to know if the key was wrong or the file is compromised.
//
// The returned io.ReadCloser, must be closed once it is no longer needed,
// in order to clear the derived key from protected memory.
func NewDec(pass []byte, r io.ReadSeeker) (io.ReadCloser, error) {
	b := make([]byte, 2)
	_, err := r.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	if _, err = io.ReadFull(r, b); err != nil {
		return nil, ErrBadVer
	}

	ver := ldtools.Btou16(b)
	if !Versions.Sup(ver) {
		return nil, ErrVerMissing{ver: ver}
	}

	// rewind back to start
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	// we only have one supported version to return
	return v1.NewDec(pass, r)
}

// EncryptFile will encrypt fileIn and store the encrypted result at fileOut
func EncryptFile(pass []byte, cp v1.CostParams, fileIn, fileOut string) error {
	return v1.EncryptFile(pass, cp, fileIn, fileOut)
}

// DecryptFile will decrypt fileIn and store the plaintext result at fileOut
func DecryptFile(pass []byte, fileIn, fileOut string) error {
	return v1.DecryptFile(pass, fileIn, fileOut)
}
