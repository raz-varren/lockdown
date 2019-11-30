package ld_test

import (
	"github.com/raz-varren/lockdown/ld"
	"github.com/raz-varren/lockdown/ld/ldtools"
	"github.com/raz-varren/lockdown/ld/v1"
	"io/ioutil"
	"os"
	"testing"
)

func TestEncDec(t *testing.T) {
	dir, err := ioutil.TempDir("", "lockdown_ld_tests_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	rtf, err := ldtools.NewRandTmpFile(dir, "test_enc_dec_*.file", 1024*128)
	if err != nil {
		t.Fatal(err)
	}
	defer rtf.Close()

	fileName := rtf.File().Name()
	encFileName := fileName + ".lkd"
	decFileName := fileName + ".dec"

	pass := []byte("testpassword")

	err = ld.EncryptFile(pass, v1.CostNormal, fileName, encFileName)
	if err != nil {
		t.Fatal(err)
	}

	err = ld.DecryptFile(pass, encFileName, decFileName)
	if err != nil {
		t.Fatal(err)
	}

	sum, err := ldtools.FileSha256(decFileName)
	if err != nil {
		t.Fatal(err)
	}

	if !rtf.Equal(sum) {
		t.Fatalf("file hashes don't match: %x != %x", rtf.Sum(), sum)
	}
}
