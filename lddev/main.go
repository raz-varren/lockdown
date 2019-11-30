package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/raz-varren/lockdown/ld/ldtools"
	"github.com/raz-varren/lockdown/ld/v1"
	"github.com/raz-varren/log"
	"io"
	"io/ioutil"
	"os"
)

const (
	hashSize = sha256.Size
)

var (
	flagHeader      = flag.Bool("head", false, "print out the crypto header of the provided files")
	flagSig         = flag.Bool("sig", false, "print out the hmac signature")
	flagHash        = flag.String("hash", "", "generate a hash file")
	flagHashCompare = flag.String("hashcompare", "", "compare a file's hash to a hash file")
	flagRandFile    = flag.Int64("randfile", 0, "generate files filled with (n) bytes of random data")

	errBadHash = fmt.Errorf("hash file should be exactly %d bytes", hashSize)
)

func main() {
	flag.Parse()

	if *flagHash != "" {
		if len(flag.Args()) > 1 {
			log.Err.Fatalln("you can only hash 1 file at a time")
		}
		if len(flag.Args()) == 0 {
			log.Err.Fatalln("you must provide a file to hash")
		}
	}

	for _, arg := range flag.Args() {
		err := processArg(arg)
		if err != nil {
			log.Err.Fatalln(err)
		}
	}
}

func processArg(arg string) error {
	if *flagHeader {
		if err := processHeader(arg); err != nil {
			return err
		}
	}

	if *flagSig {
		if err := processSig(arg); err != nil {
			return err
		}
	}

	if *flagHash != "" {
		if err := processWriteHash(arg); err != nil {
			return err
		}
	}

	if *flagHashCompare != "" {
		if err := processCompareHash(arg); err != nil {
			return err
		}
	}

	if *flagRandFile > 0 {
		if err := processRandFile(arg); err != nil {
			return err
		}
	}

	return nil
}

func processRandFile(arg string) error {
	f, err := os.OpenFile(arg, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.CopyN(f, rand.Reader, *flagRandFile)
	return err
}

func processCompareHash(arg string) error {
	sum, err := getHash(*flagHashCompare)
	if err != nil {
		return err
	}

	compareSum, err := ldtools.FileSha256(arg)
	if err != nil {
		return err
	}

	matchStr := "nomatch"
	if bytes.Equal(sum, compareSum) {
		matchStr = "match"
	}

	if len(flag.Args()) > 1 {
		fmt.Printf("%s - %s: %x - %x\n\n", arg, matchStr, compareSum, sum)
	} else {
		fmt.Printf(matchStr)
	}

	return nil
}

func processWriteHash(arg string) error {
	sum, err := ldtools.FileSha256(arg)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*flagHash, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(sum)
	return err
}

func processSig(arg string) error {
	f, err := os.Open(arg)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(v1.LenSig*-1, io.SeekEnd); err != nil {
		return err
	}

	sig := make([]byte, v1.LenSig)
	if _, err := io.ReadFull(f, sig); err != nil {
		return err
	}

	fmt.Printf("file: %s\nSignature: %x\n\n", arg, sig)
	return nil
}

func processHeader(arg string) error {
	f, err := os.Open(arg)
	if err != nil {
		return err
	}
	defer f.Close()

	hb := make([]byte, v1.LenHeader)
	_, err = io.ReadFull(f, hb)
	if err != nil {
		return err
	}

	ch := v1.ExtractCryptoHeader(hb)
	fmt.Printf("file: %s\n%s", arg, ch.String())
	return nil
}

func getHash(hashFilePath string) ([]byte, error) {
	hashFile, err := os.Open(hashFilePath)
	if err != nil {
		return nil, err
	}
	defer hashFile.Close()

	stat, err := hashFile.Stat()
	if err != nil {
		return nil, err
	}

	if stat.Size() != hashSize {
		return nil, errBadHash
	}

	return ioutil.ReadAll(hashFile)
}
