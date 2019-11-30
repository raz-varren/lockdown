package v1

import (
	"bytes"
	"fmt"
	"github.com/raz-varren/lockdown/ld/ldtools"
	"golang.org/x/crypto/argon2"
)

func emptyCryptoHeader() *cryptoHeader {
	return &cryptoHeader{cp: &costParams{}}
}

// a printable representation of a cryptoHeader
type CryptoHeader struct {
	Ver        uint16
	VerArgon   uint16
	Salt       []byte
	IV         []byte
	CostParams CostParams
}

func (ch CryptoHeader) String() string {
	templ := `
Ver: %d
VerArgon: %d
Salt: %x
IV: %x
CostParams:
    Time: %d
    Memory: %d MB
    Threads: %d

`
	return fmt.Sprintf(templ,
		ch.Ver,
		ch.VerArgon,
		ch.Salt,
		ch.IV,
		ch.CostParams.Time,
		ch.CostParams.Memory/1024,
		ch.CostParams.Threads)
}

func ExtractCryptoHeader(b []byte) CryptoHeader {
	ch := &cryptoHeader{}
	ch.UnmarshalBinary(b)
	return CryptoHeader{
		Ver:      ch.ver,
		VerArgon: ch.verArgon,
		Salt:     ch.salt,
		IV:       ch.iv,
		CostParams: CostParams{
			Time:    ch.cp.time,
			Memory:  ch.cp.memory,
			Threads: ch.cp.threads,
		},
	}
}

func fastCryptoHeader() *cryptoHeader {
	return cpCryptoHeader(CostFast)
}

func defaultCryptoHeader() *cryptoHeader {
	return cpCryptoHeader(CostNormal)
}

func slowCryptoHeader() *cryptoHeader {
	return cpCryptoHeader(CostSlow)
}

func cpCryptoHeader(cp CostParams) *cryptoHeader {
	return newCryptoHeader(&costParams{
		time:    cp.Time,
		memory:  cp.Memory,
		threads: cp.Threads,
	})
}

func newCryptoHeader(cp *costParams) *cryptoHeader {
	ch := &cryptoHeader{
		ver:      Version,
		verArgon: argon2.Version,
		cp:       cp,
	}
	ch.salt = ch.genSalt()
	ch.iv = ch.genIV()
	return ch
}

func parseCryptoHeader(data []byte) *cryptoHeader {
	ch := &cryptoHeader{}
	ch.UnmarshalBinary(data)
	return ch
}

type cryptoHeader struct {
	ver      uint16
	verArgon uint16
	salt     []byte
	iv       []byte
	cp       *costParams
}

func (ch *cryptoHeader) genSalt() []byte {
	salt := make([]byte, ch.LenSalt())
	fillRand(salt)
	return salt
}

func (ch *cryptoHeader) genIV() []byte {
	iv := make([]byte, ch.LenIV())
	fillRand(iv)
	return iv
}

func (ch *cryptoHeader) MarshalBinary() (data []byte, err error) {
	cpb, _ := ch.cp.MarshalBinary()

	buf := bytes.NewBuffer(nil)
	buf.Write(ldtools.U16tob(ch.ver))
	buf.Write(ldtools.U16tob(ch.verArgon))
	buf.Write(cpb)
	buf.Write(ch.salt)
	buf.Write(ch.iv)

	return buf.Bytes(), nil
}

func (ch *cryptoHeader) UnmarshalBinary(data []byte) error {
	if len(data) < ch.Len() {
		panic("data length is too small to be a crypto header")
	}

	lVer := ch.LenVer()
	lVerArgon := lVer + ch.LenVerArgon()
	lCP := lVerArgon + ch.LenCostParams()
	lSalt := lCP + ch.LenSalt()
	lIV := lSalt + ch.LenIV()

	cp := &costParams{}

	ch.ver = ldtools.Btou16(data[:lVer])
	ch.verArgon = ldtools.Btou16(data[lVer:lVerArgon])
	cp.UnmarshalBinary(data[lVerArgon:lCP])
	ch.salt = data[lCP:lSalt]
	ch.iv = data[lSalt:lIV]

	ch.cp = cp
	return nil
}

func (ch *cryptoHeader) Ver() uint16 {
	return ch.ver
}

func (ch *cryptoHeader) VerArgon() uint16 {
	return ch.verArgon
}

func (ch *cryptoHeader) Salt() []byte {
	return ch.salt
}

func (ch *cryptoHeader) IV() []byte {
	return ch.iv
}

func (ch *cryptoHeader) Len() int {
	return ch.LenVer() + ch.LenVerArgon() + ch.LenSalt() + ch.LenIV() + ch.LenCostParams()
}

func (ch *cryptoHeader) LenVer() int {
	return lenVer
}

func (ch *cryptoHeader) LenVerArgon() int {
	return lenVerArgon
}

func (ch *cryptoHeader) LenSalt() int {
	return lenSalt
}

func (ch *cryptoHeader) LenIV() int {
	return lenIV
}

func (ch *cryptoHeader) LenCostParams() int {
	return ch.cp.Len()
}
