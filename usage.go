package main

import (
	"flag"
	"github.com/raz-varren/lockdown/ld/v1"
	"github.com/raz-varren/log"
	"os"
	"text/template"
)

var (
	ldUsage = func() {
		templ, err := template.New("usage").Parse(ldUsageTempl)
		if err != nil {
			log.Err.Fatalln(err)
		}
		data := struct{ Program, Ext string }{
			os.Args[0],
			v1.FileExt,
		}
		err = templ.Execute(flag.CommandLine.Output(), data)
		if err != nil {
			log.Err.Fatalln(err)
		}
		flag.PrintDefaults()
	}

	//flag usages
	fuDryRun = `do a dry run, show what would have happened, without changing anything`
	fuExt    = `the file ` + "`extension`" + ` to use when encrypting or decrypting files. 
multiple extensions may be used, separated by commas. files that match
the set extensions will be skipped on encryption and processed on
decryption. don't change this unless you really need to`
	fuRecurse = `recurse into directories, encrypting or decrypting all files in all
subdirectories`
	fuDecrypt = `decrypt files`
	fuEncrypt = `encrypt files`
	fuPass    = `the ` + "`password`" + ` to use for encrypting/decrypting files. if using
this flag, you will not be prompted for passwords and failed decryptions
will cause the program to exit. using the flag is NOT recommended as doing
so will make the password visible to process managers`
	fuCost = "`cost`" + ` determines the amount of time it will take to generate encryption
keys from your password. the longer it takes, the better, as this parameter
directly determines how long it will take to bruteforce your password. when
in doubt, just use the defaults. possible options are ` + costOptsStr()
	fuCostTime    = `password key time cost parameter`
	fuCostMemory  = `password key memory (in MB) cost parameter`
	fuCostThreads = `password key threads cost parameter`
)

const (
	ldUsageTempl = `
Usage of {{.Program}}:

{{.Program}} is a file encryption tool that takes, as input, a set of 
plaintext files and replaces them with encrypted counterpart 
files, typically with a file extension of (.{{.Ext}}), and vice versa.

When a file is successfully encrypted, the plaintext file is 
deleted from the file system, leaving only the (.{{.Ext}}) encrypted
file remaining.

The same is true of the reverse, successfully decrypting a 
(.{{.Ext}}) file will produce a plaintext counterpart and delete
the encrypted file from the file system.


Examples:
	
//encrypt a file
    {{.Program}} -e /path/to/file.txt

//decrypt a file
    {{.Program}} -d /path/to/file.txt.{{.Ext}}

//encrypt all files in a directory that don't have the (.{{.Ext}}) extension
    {{.Program}} -e -r /path/to/directory

//decrypt all files in a directory that do have the (.{{.Ext}}) extension
    {{.Program}} -d -r /path/to/directory

//encrypt file using different extension
    {{.Program}} -e -ext myext /path/to/file.txt

//decrypt directory of encrypted files with multiple possible extensions
    {{.Program}} -d -r -ext "myext,otherext,{{.Ext}}" /path/to/directory


Options:
`
)
