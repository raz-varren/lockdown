package v1

import (
	"bytes"
	"fmt"
	"github.com/raz-varren/lockdown/ld/ldtools"
	"golang.org/x/crypto/argon2"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type fileT struct {
	name string
	size int64
}

var (
	fastCP   = CostParams{Time: 1, Memory: 1024 * 128, Threads: 4}
	testPass = []byte("testpassword")
)

const (
	tmpDirPrefix        = "lockdown_tests_"
	encryptedFilePath   = "../../testdata/encrypted.file.lkd"
	tamperedFilePath    = "../../testdata/tampered.file.lkd"
	decryptableFilePath = "../../testdata/decryptable.file.lkd"
)

func TestV1(t *testing.T) {
	files := []fileT{
		{name: "0-byte_*.file", size: 0},
		{name: "1-byte_*.file", size: 1},
		{name: "2-byte_*.file", size: 2},
		{name: "1-kibibyte_*.file", size: 1024},
		{name: "1-mebibyte_*.file", size: 1024 * 1024},
		{name: "5-mebibyte_*.file", size: 1024 * 1024 * 5},
		{name: "10-mebibyte_*.file", size: 1024 * 1024 * 10},
		{name: "100-mebibyte_*.file", size: 1024 * 1024 * 100},
		{name: "1-gibibyte.file", size: 1024 * 1024 * 1024},
	}

	tmpDir, err := ioutil.TempDir("", tmpDirPrefix)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	for _, f := range files {
		rtf, err := ldtools.NewRandTmpFile(tmpDir, f.name, f.size)
		if err != nil {
			t.Fatal(err)
		}

		cp := fastCP
		fileName := rtf.File().Name()
		encFileName := fileName + ".lkd"
		decFileName := fileName + ".dec"

		err = EncryptFile(testPass, cp, fileName, encFileName)

		if err != nil {
			t.Fatal(err)
		}

		err = DecryptFile(testPass, encFileName, decFileName)
		if err != nil {
			t.Fatal(err)
		}

		sum, err := ldtools.FileSha256(decFileName)
		if err != nil {
			t.Fatal(err)
		}

		if !rtf.Equal(sum) {
			t.Fatal("decrypted file doesn't match original")
		}

		rtf.Close()
		os.Remove(encFileName)
		os.Remove(decFileName)
	}
}

func TestBadPass(t *testing.T) {
	f, err := os.Open(encryptedFilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	dec, err := NewDec(testPass, f)
	if err == nil {
		dec.Close()
		t.Fatalf("expected (ErrSigMismatch) but got (nil)")
	}

	if err != ErrSigMismatch {
		t.Fatal(err)
	}
}

func TestTamperedFile(t *testing.T) {
	f, err := os.Open(tamperedFilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	dec, err := NewDec(testPass, f)
	if err == nil {
		dec.Close()
		t.Fatalf("expected (ErrSigMismatch) but got (nil)")
	}

	if err != ErrSigMismatch {
		t.Fatal(err)
	}
}

const currArgon = 19

func TestArgonVer(t *testing.T) {
	if argon2.Version != currArgon {
		t.Fatalf("argon2 version expected (%d) but got (%d)", currArgon, argon2.Version)
	}
}

func TestNewEncWriteErr(t *testing.T) {
	rmf, err := ldtools.NewRandMemFile(1024)
	if err != nil {
		t.Fatal(err)
	}

	tio := NewTaintedIO(rmf, FailOn{Write: 1})
	_, err = NewEnc(testPass, fastCP, tio)
	if err != tio {
		t.Fatalf("expected %v, but got (%v)", tio, err)
	}
}

func TestNewDecSeekErr(t *testing.T) {
	for i := 1; i <= 4; i++ {
		tio, err := NewTaintedFile(decryptableFilePath, FailOn{Seek: i})
		if err != nil {
			t.Fatal(err)
		}

		dec, err := NewDec(testPass, tio)
		if err == nil {
			dec.Close()
		}
		if err != tio {
			tio.Close()
			t.Fatalf("expected %v, but got (%v)", tio, err)
		}
		tio.Close()
	}
}

func TestNewDecReadErr(t *testing.T) {
	for i := 1; i <= 3; i++ {
		tio, err := NewTaintedFile(decryptableFilePath, FailOn{Read: i})
		if err != nil {
			t.Fatal(err)
		}

		dec, err := NewDec(testPass, tio)
		if err == nil {
			dec.Close()
		}
		if err != tio {
			tio.Close()
			t.Fatalf("expected (%v), but got (%v)", tio, err)
		}
		tio.Close()
	}
}

func TestNewDecTooSmall(t *testing.T) {
	dec, err := NewDec(testPass, bytes.NewReader(nil))
	if err == nil {
		dec.Close()
	}
	if err != ErrTooSmall {
		t.Fatalf("expected (%v), but got (%v)", ErrTooSmall, err)
	}
}

func TestNewDecBadVer(t *testing.T) {
	ch := fastCryptoHeader()
	ch.ver = 2
	chData, _ := ch.MarshalBinary()
	data := append(chData, make([]byte, lenSig)...)

	dec, err := NewDec(testPass, bytes.NewReader(data))
	if err == nil {
		dec.Close()
	}
	if err != ErrVerMismatch {
		t.Fatalf("expected (%v), but got (%v)", ErrVerMismatch, err)
	}
}

func TestDecryptFileNotExists(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", tmpDirPrefix)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	err = DecryptFile(testPass, filepath.Join(tmpDir, "nonexistent.file"), filepath.Join(tmpDir, "decrypted.file"))
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected (file not exists error), but got (%v)", err)
	}
}

func TestDecryptFileTainted(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", tmpDirPrefix)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	err = DecryptFile([]byte("bad pass"), decryptableFilePath, filepath.Join(tmpDir, "decrypted.file"))
	if err != ErrSigMismatch {
		t.Fatalf("expected (%v), but got (%v)", ErrSigMismatch, err)
	}
}

func TestDecryptFileExists(t *testing.T) {
	err := DecryptFile(testPass, decryptableFilePath, encryptedFilePath)
	if err == nil || !os.IsExist(err) {
		t.Fatalf("expected (file exists error), but got (%v)", err)
	}
}

func TestEncryptFileExists(t *testing.T) {
	err := EncryptFile(testPass, fastCP, decryptableFilePath, encryptedFilePath)
	if err == nil || !os.IsExist(err) {
		t.Fatalf("expected (file exists error), but got (%v)", err)
	}
}

func TestEncryptFileNotExists(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", tmpDirPrefix)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	err = EncryptFile(testPass, fastCP, filepath.Join(tmpDir, "nonexistent.file"), filepath.Join(tmpDir, "encrypted.file"))
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected (file exists error), but got (%v)", err)
	}
}

func TestEncryptFileBadPass(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", tmpDirPrefix)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	err = EncryptFile(nil, fastCP, decryptableFilePath, filepath.Join(tmpDir, "encrypted.file"))
	if err != ErrBadPass {
		t.Fatalf("expected (%v), but got (%v)", ErrBadPass, err)
	}
}

type FailOn struct {
	Any, Read, Write, Seek, All int
}

func NewTaintedFile(filePath string, fo FailOn) (*TaintedIO, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	return NewTaintedIO(f, fo), nil
}

func NewTaintedIO(rws io.ReadWriteSeeker, fo FailOn) *TaintedIO {
	return &TaintedIO{
		mu:  &sync.Mutex{},
		rws: rws,
		fo:  fo,
	}
}

type TaintedIO struct {
	mu         *sync.Mutex
	rws        io.ReadWriteSeeker
	fo         FailOn
	readCount  int
	writeCount int
	seekCount  int
}

func (tio *TaintedIO) shouldFail() bool {
	switch {
	case (tio.fo.Read > 0 && tio.readCount >= tio.fo.Read):
		return true
	case (tio.fo.Write > 0 && tio.writeCount >= tio.fo.Write):
		return true
	case (tio.fo.Seek > 0 && tio.seekCount >= tio.fo.Seek):
		return true
	case (tio.fo.Any > 0 && (tio.readCount >= tio.fo.Any || tio.writeCount >= tio.fo.Any || tio.seekCount >= tio.fo.Any)):
		return true
	case (tio.fo.All > 0 && (tio.readCount+tio.writeCount+tio.seekCount) >= tio.fo.All):
		return true
	default:
		return false
	}
}

func (tio *TaintedIO) Error() string {
	tio.mu.Lock()
	defer tio.mu.Unlock()

	return fmt.Sprintf("TaintedIO error: %#v, Read: %d, Write: %d, Seek: %d",
		tio.fo,
		tio.readCount,
		tio.writeCount,
		tio.seekCount)
}

func (tio *TaintedIO) Read(p []byte) (int, error) {
	tio.mu.Lock()
	defer tio.mu.Unlock()

	tio.readCount++

	if tio.shouldFail() {
		return 0, tio
	}

	return tio.rws.Read(p)
}

func (tio *TaintedIO) Write(p []byte) (int, error) {
	tio.mu.Lock()
	defer tio.mu.Unlock()

	tio.writeCount++

	if tio.shouldFail() {
		return 0, tio
	}
	return tio.rws.Write(p)
}

func (tio *TaintedIO) Seek(offset int64, whence int) (int64, error) {
	tio.mu.Lock()
	defer tio.mu.Unlock()

	tio.seekCount++

	if tio.shouldFail() {
		return 0, tio
	}
	return tio.rws.Seek(offset, whence)
}

func (tio *TaintedIO) Close() error {
	if c, ok := tio.rws.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
