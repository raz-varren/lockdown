Lockdown [![GoDoc](https://godoc.org/github.com/raz-varren/lockdown?status.svg)](https://godoc.org/github.com/raz-varren/lockdown)
==================

lockdown is a file encryption tool that takes, as input, a set of plaintext files and replaces them with encrypted counterpart files, typically with a file extension of (.lkd), and vice versa.

When a file is successfully encrypted, the plaintext file is deleted from the file system, leaving only the (.lkd) encrypted file remaining.

The same is true of the reverse, successfully decrypting a (.lkd) file will produce a plaintext counterpart and delete the encrypted file from the file system.

### Install:
-----------
```bash
go get github.com/raz-varren/lockdown...
go install github.com/raz-varren/lockdown
```

### Examples:
---------

```bash
#list options
lockdown -h

#encrypt a file
lockdown -e /path/to/file.txt

#decrypt a file
lockdown -d /path/to/file.txt.lkd

#encrypt all files in a directory that don't have the (.lkd) extension
lockdown -e -r /path/to/directory

#decrypt all files in a directory that do have the (.lkd) extension
lockdown -d -r /path/to/directory

#encrypt file using different extension
lockdown -e -ext myext /path/to/file.txt

#decrypt directory of encrypted files with multiple possible extensions
lockdown -d -r -ext "myext,otherext,lkd" /path/to/directory
```