package v1

import (
	"crypto/cipher"
	"crypto/hmac"
	"errors"
	"github.com/raz-varren/lockdown/ld/ldtools"
	"io"
	"os"
)

var (
	ErrTooSmall    = errors.New("the provided io.ReadSeeker is too small to be an encrypted file")
	ErrSigMismatch = errors.New("the signature did not match the encypted data")
	//ErrBadSalt     = errors.New("could not read salts from file")
	ErrVerMismatch = errors.New("invalid file version, version must be 1")
)

// NewDec returns an io.ReadCloser that will decrypt r. If the provided password is incorrect,
// an ErrSigMismatch will be returned. ErrSigMismatch may also indicate the encrypted file was
// tampered with, as there is no way to know if the key was wrong or the file is compromised.
//
// The returned io.ReadCloser, must be closed once it is no longer needed,
// in order to clear the derived key from protected memory.
func NewDec(pass []byte, r io.ReadSeeker) (io.ReadCloser, error) {
	end, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}

	start, err := r.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	fileSize := end - start
	if fileSize < int64(lenHeader+lenSig) {
		return nil, ErrTooSmall
	}

	headerBytes := make([]byte, lenHeader)
	err = ldtools.GetSlices(r, headerBytes)
	if err != nil {
		return nil, err
	}

	ch := emptyCryptoHeader()
	ch.UnmarshalBinary(headerBytes)

	if ch.Ver() != Version {
		return nil, ErrVerMismatch
	}

	cr := newCryptoRing(pass, ch)

	// reset to start
	if _, err = r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	mac := cr.Mac()
	if _, err = io.CopyN(mac, r, fileSize-lenSig); err != nil {
		return nil, err
	}

	sig := make([]byte, lenSig)
	if _, err = io.ReadFull(r, sig); err != nil {
		return nil, err
	}

	//if this fails then either the password was wrong
	//or the data was tampered with... or I guess it's
	//not an encrypted file. Either way we can't decrypt it.
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrSigMismatch
	}

	if _, err = r.Seek(int64(ch.Len()), io.SeekStart); err != nil {
		return nil, err
	}

	sr := &cipher.StreamReader{
		S: cr.Stream(),
		R: io.LimitReader(r, fileSize-int64(ch.Len())-lenSig),
	}

	cw := &closeWrapper{sr: sr, cr: cr}

	return cw, nil
}

type closeWrapper struct {
	sr *cipher.StreamReader
	cr *cryptoRing
}

func (cw *closeWrapper) Read(p []byte) (n int, err error) {
	return cw.sr.Read(p)
}

func (cw *closeWrapper) Close() error {
	cw.cr.Destroy()
	return nil
}

// DecryptFile will decrypt fileIn and store the plaintext result at fileOut
func DecryptFile(pass []byte, fileIn, fileOut string) error {
	encFile, err := os.Open(fileIn)
	if err != nil {
		return err
	}
	defer encFile.Close()

	decR, err := NewDec(pass, encFile)
	if err != nil {
		return err
	}
	defer decR.Close()

	plainFile, err := os.OpenFile(fileOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer plainFile.Close()

	_, err = io.Copy(plainFile, decR)
	return err
}
