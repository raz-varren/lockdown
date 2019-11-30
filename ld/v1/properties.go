package v1

import (
	"crypto/aes"
	"crypto/sha512"
)

// Below is a representation of the finished data that will be written to the io.Writer passed into NewEnc:
// Data:
//     Version|Argon2Version|CostTime|CostMemory|CostThreads|Salt|IV|EncryptedData|HMACSignature
// Bytes:
//     2|2|4|4|1|64|16|variable|64

const (
	Version uint16 = 1
	FileExt        = "lkd"

	//lengths of the ciphers used for encryption and verification
	keyLenCipher = 32 //keysize for AES-256 cipher block
	keyLenHash   = 64

	//default cost params
	defCostTime   = 4
	defCostMem    = 1024 * 512 //512 MB, the argon2 memory arg is in KB
	defCostThread = 8

	//header data length
	lenVer      = 2
	lenVerArgon = 2
	lenSalt     = 64
	lenIV       = aes.BlockSize

	//time cost data length
	lenCostTime   = 4
	lenCostMem    = 4
	lenCostThread = 1

	//signature length
	lenSig = sha512.Size

	//combined lengths
	lenCostParams = lenCostTime + lenCostMem + lenCostThread
	lenHeader     = lenVer + lenVerArgon + lenSalt + lenIV + lenCostParams
	lenTotalAdded = lenHeader + lenSig

	//exported lengths
	LenHeader = lenHeader
	LenSig    = lenSig
)
