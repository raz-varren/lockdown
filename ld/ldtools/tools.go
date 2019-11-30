package ldtools

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/mattetti/filebuffer"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// converts a uint8 number to a byte slice
func U8tob(i uint8) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(i))
	return []byte{b[1]}
}

// converts a byte slice to a uint8 number
func Btou8(b []byte) uint8 {
	return uint8(binary.BigEndian.Uint16([]byte{0, b[0]}))
}

// converts a uint16 number to a byte slice
func U16tob(i uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b
}

// converts a byte slice to a uint16 number
func Btou16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

// converts a uint32 number to a byte slice
func U32tob(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b
}

// converts a byte slice to a uint32 number
func Btou32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

type VersionMap struct {
	mu  *sync.RWMutex
	m   map[uint16]bool
	vl  []int
	vls string
}

func NewVersionMap(vers ...uint16) *VersionMap {
	m := make(map[uint16]bool)
	vl := []int{}
	vls := []string{}
	for _, v := range vers {
		m[v] = true
		vl = append(vl, int(v))
	}
	sort.Ints(vl)

	for _, v := range vl {
		vls = append(vls, strconv.Itoa(v))
	}

	vMap := &VersionMap{
		mu:  &sync.RWMutex{},
		m:   m,
		vl:  vl,
		vls: strings.Join(vls, ", "),
	}

	return vMap
}

// Sup returns true if the provided version is supported
func (vm *VersionMap) Sup(i uint16) bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.m[i]
}

func (vm *VersionMap) SupList() string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.vls
}

func GetSlices(r io.Reader, slices ...[]byte) error {
	for _, s := range slices {
		if _, err := io.ReadFull(r, s); err != nil {
			return err
		}
	}
	return nil
}

func NewRandMemFile(size int64) (io.ReadWriteSeeker, error) {
	fb := filebuffer.New(nil)
	_, err := io.CopyN(fb, rand.Reader, size)
	if err != nil {
		return nil, err
	}

	_, err = fb.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	return fb, nil
}

func NewRandTmpFile(dir, name string, size int64) (*RandTmpFile, error) {
	file, err := ioutil.TempFile(dir, name)
	if err != nil {
		return nil, err
	}

	_, err = io.CopyN(file, rand.Reader, size)
	if err != nil {
		return nil, err
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	sum, err := ReadSeekerSha256(file)
	if err != nil {
		return nil, err
	}

	return &RandTmpFile{
		f:   file,
		sum: sum,
	}, nil
}

type RandTmpFile struct {
	f   *os.File
	sum []byte
}

// Closes the underlying *os.File and deletes it, returning the (*os.File).Close() value
func (rtf *RandTmpFile) Close() error {
	err := rtf.f.Close()
	os.Remove(rtf.File().Name())
	return err
}

// Returns the underlying random file
func (rtf *RandTmpFile) File() *os.File {
	return rtf.f
}

// Returns the underlying file hash sum
func (rtf *RandTmpFile) Sum() []byte {
	return rtf.sum
}

// Returns whether sum is equal to the hash sum of the underlying file
func (rtf *RandTmpFile) Equal(sum []byte) bool {
	return bytes.Equal(rtf.sum, sum)
}

func ReaderSha256(r io.Reader) ([]byte, error) {
	hash := sha256.New()
	_, err := io.Copy(hash, r)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func FileSha256(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ReaderSha256(f)
}

// Reads rs into a sha256 hash then seeks rs to 0 relative to the start
func ReadSeekerSha256(rs io.ReadSeeker) ([]byte, error) {
	sum, err := ReaderSha256(rs)
	if err != nil {
		return nil, err
	}
	if _, err = rs.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	return sum, nil
}
