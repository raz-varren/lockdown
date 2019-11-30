package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/awnumar/memguard"
	"github.com/raz-varren/lockdown/ld"
	"github.com/raz-varren/lockdown/ld/v1"
	"github.com/raz-varren/log"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	pws      = NewPWSystem()
	pm       = NewPaddedMsgs()
	firstExt = ""
	extMap   = make(map[string]bool)
	stats    = NewStats()

	costMap = map[string]v1.CostParams{
		"slow":   v1.CostSlow,
		"normal": v1.CostNormal,
		"fast":   v1.CostFast,
	}
	costSelected = costMap["normal"]

	flagDryRun      = flag.Bool("dry", false, fuDryRun)
	flagExt         = flag.String("ext", v1.FileExt, fuExt)
	flagRecurse     = flag.Bool("r", false, fuRecurse)
	flagDecrypt     = flag.Bool("d", false, fuDecrypt)
	flagEncrypt     = flag.Bool("e", false, fuEncrypt)
	flagPass        = flag.String("password", "", fuPass)
	flagCost        = flag.String("cost", "", fuCost)
	flagCostTime    = flag.Uint("costtime", uint(v1.CostNormal.Time), fuCostTime)
	flagCostMemory  = flag.Uint("costmem", uint(v1.CostNormal.Memory/1024), fuCostMemory)
	flagCostThreads = flag.Uint("costthreads", uint(v1.CostNormal.Threads), fuCostThreads)

	errNoFiles       = errors.New("no files provided")
	errQuantumCrypto = errors.New("you can't encrypt AND decrypt a file at the same time... yet")
	errNoCrypto      = errors.New("you must either encrypt files or decrypt files")
	errEmptyExt      = errors.New("file extension can't be blank")
	errFileExists    = errors.New("encrypted and unencrypted version of the same file found. something probabaly went wrong, inspect the files and delete the one you don't need")
)

func main() {
	flag.Usage = ldUsage
	flag.Parse()

	costSelected = v1.CostParams{
		Time:    uint32(*flagCostTime),
		Memory:  uint32(*flagCostMemory * 1024),
		Threads: uint8(*flagCostThreads),
	}
	if costMap[*flagCost] != (v1.CostParams{}) {
		costSelected = costMap[*flagCost]
	}

	if flag.NArg() == 0 {
		log.Err.Println(errNoFiles)
		flag.Usage()
		os.Exit(1)
		return
	}

	if *flagExt == "" {
		log.Err.Fatalln(errEmptyExt)
	}

	mapExtensions()

	if *flagDecrypt && *flagEncrypt {
		log.Err.Fatalln(errQuantumCrypto)
	}

	if !*flagEncrypt && !*flagDecrypt {
		log.Err.Fatalln(errNoCrypto)
	}

	if *flagDryRun {
		log.Warn.Println("doing a dry run, no changes will actually be made")
	}

	termState, err := terminal.GetState(sysTerm)
	if err != nil && hasSysTerm {
		log.Err.Fatalln(err)
	}

	memguard.CatchSignal(func(s os.Signal) {
		if hasSysTerm || err == nil {
			terminal.Restore(sysTerm, termState)
		}
	})
	defer memguard.Purge()
	defer pws.Destroy()

	if *flagPass != "" {
		if len(*flagPass) < minPassLen {
			log.Err.Fatalln(errMinPass{min: minPassLen})
		}
		pws.AddPass([]byte(*flagPass))
	}

	for _, arg := range flag.Args() {
		err := processArg(arg)
		if err != nil {
			log.Err.Fatalln(err)
		}
	}
}

func processArg(arg string) error {
	fmt.Println("")
	arg = filepath.Clean(arg)
	pm.Info("processing file:", arg)
	ext := strings.TrimLeft(filepath.Ext(arg), ".")
	hasMatchingExt := extMap[ext]

	fStat, err := os.Lstat(arg)
	if err != nil {
		return err
	}

	fIsSym := fStat.Mode()&os.ModeSymlink != 0
	//if fIsSym && !*flagFollowSymlinks {
	if fIsSym {
		pm.Info("skipping symlink:", arg)
		stats.AddSkip(arg)
		return nil
	}

	fStat, err = os.Stat(arg)
	if err != nil {
		return err
	}

	if fStat.IsDir() && !*flagRecurse {
		pm.Info("skipping directory", arg, "- recursion flag not set")
		stats.AddSkip(arg)
		return nil
	}

	//recurse if we got here
	if fStat.IsDir() {
		subFiles, err := ioutil.ReadDir(arg)
		if err != nil {
			return err
		}
		for _, sf := range subFiles {
			err = processArg(filepath.Join(arg, sf.Name()))
			if err != nil {
				return err
			}
		}
		return nil
	}

	if *flagEncrypt && hasMatchingExt {
		pm.Info("skipping file:", arg, "- has encrypted file extension")
		stats.AddSkip(arg)
		return nil
	}

	if *flagDecrypt && !hasMatchingExt {
		pm.Info("skipping file:", arg, "- doesn't have encrypted file extension")
		stats.AddSkip(arg)
		return nil
	}

	if *flagEncrypt {
		pm.Info("encrypting file:", arg)
		return encFile(arg)
	}

	if *flagDecrypt {
		pm.Info("decrypting file:", arg)
		return decFile(arg)
	}

	return nil
}

func encFile(arg string) error {
	fName := extFileName(arg)

	if fileExists(fName) {
		return errFileExists
	}

	if !*flagDryRun {
		if pws.Len() < 1 {
			pws.PromptConfirm("please enter a password:", "confirm your password:", "passwords do not match")
		}

		err := ld.EncryptFile(pws.First(), costSelected, arg, fName)
		if err != nil {
			return err
		}
	}

	pm.Info("created file:", fName)
	stats.AddMk(fName)

	if !*flagDryRun {
		os.Remove(arg)
	}

	pm.Info("deleted file:", arg)
	stats.AddDel(arg)

	return nil
}

func decFile(arg string) error {
	fName := strings.TrimSuffix(arg, filepath.Ext(arg))
	if fileExists(fName) {
		return errFileExists
	}

	if !*flagDryRun {
		if pws.Len() == 0 {
			pws.Prompt("please enter your password:", false)
		}

		pws.Rewind()
		for {
			err := ld.DecryptFile(pws.Next(), arg, fName)

			if err == v1.ErrSigMismatch && pws.HasNext() {
				log.Info.Println("password failed, trying other password")
				continue
			}
			if err == v1.ErrSigMismatch {
				log.Warn.Println("Your password didn't match the signature of the encrypted file:", arg)
				log.Warn.Println("This could be because someone tampered with the file, but most likely this file uses a different password that the ones you've entered.")
				if *flagPass != "" {
					log.Err.Fatalln("exitting because -password flag was used")
				}
				fmt.Println("type another password and hit enter to try again to decrypt the file.")
				if nil == pws.Prompt("hit enter without typing a password to skip decrypting this file.\n", true) {
					pm.Info("skipping file:", arg)
					stats.AddSkip(arg)
					return nil
				}
				log.Info.Println("trying new password")
				continue
			}

			//any other errors are show stoppers
			if err != nil {
				return err
			}

			break
		}
	}

	pm.Info("created file:", fName)
	stats.AddMk(fName)

	if !*flagDryRun {
		os.Remove(arg)
	}

	pm.Info("deleted file:", arg)
	stats.AddDel(arg)

	return nil
}

func fileExists(arg string) bool {
	if _, err := os.Stat(arg); os.IsNotExist(err) {
		return false
	}
	return true
}

func extFileName(arg string) string {
	return strings.Join([]string{arg, firstExt}, ".")
}

func mapExtensions() {
	exts := strings.Split(*flagExt, ",")
	for i, ext := range exts {
		ext = strings.Trim(ext, ". \n\r")
		if ext == "" {
			log.Err.Fatalln(errEmptyExt)
		}
		if i == 0 {
			firstExt = ext
		}
		extMap[ext] = true
	}
}

func costOptsStr() string {
	opts := []string{}
	for opt, _ := range costMap {
		opts = append(opts, opt)
	}
	sort.Strings(opts)
	return "(" + strings.Join(opts, ", ") + ")"
}
