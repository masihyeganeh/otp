package symmetric

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"github.com/andreburgaud/crypt2go/ecb"
)

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS5Data indicates bad input to PKCS5 pad or unpad.
	ErrInvalidPKCS5Data = errors.New("invalid PKCS5 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")

	// ErrInvalidPKCS5Padding indicates PKCS5 unpad fails to bad input.
	ErrInvalidPKCS5Padding = errors.New("invalid padding on input")

	// ErrNotImplemented indicates unimplemented code.
	ErrNotImplemented = errors.New("not implemented")
)

type AES struct {
	key       []byte
	BlockMode BlockMode
	padding   Padding
}

type Padding string
type BlockMode string

const (
	Pkcs5     Padding   = "pkcs5"
	Pkcs7               = "pkcs7"
	NoPadding           = ""
	CBC       BlockMode = "cbc"
	ECB                 = "ecb"
)

func NewAES(key []byte, blockMode BlockMode, padding Padding) *AES {
	return &AES{key, blockMode, padding}
}

func (a *AES) Encrypt(data, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	switch a.padding {
	case Pkcs7:
		data, err = a.pkcs7Pad(data, block.BlockSize())
		if err != nil {
			return nil, err
		}
	case Pkcs5:
		data, err = a.pkcs5Pad(data, block.BlockSize())
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrNotImplemented
	}

	var bm cipher.BlockMode
	switch a.BlockMode {
	case CBC:
		bm = cipher.NewCBCEncrypter(block, iv)
	case ECB:
		bm = ecb.NewECBEncrypter(block)
	default:
		return nil, ErrNotImplemented
	}

	bm.CryptBlocks(data, data)

	return data, nil
}

func (a *AES) Decrypt(data, iv []byte) ([]byte, error) {
	result := make([]byte, len(data))
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	var bm cipher.BlockMode
	switch a.BlockMode {
	case CBC:
		bm = cipher.NewCBCDecrypter(block, iv)
	case ECB:
		bm = ecb.NewECBDecrypter(block)
	default:
		return nil, ErrNotImplemented
	}

	bm.CryptBlocks(result, data)

	switch a.padding {
	case Pkcs7:
		return a.pkcs7Unpad(result, aes.BlockSize)
	case Pkcs5:
		return a.pkcs5Unpad(result, aes.BlockSize)
	default:
		return nil, ErrNotImplemented
	}
	return result, nil
}

func (a *AES) pkcs7Pad(b []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blockSize - (len(b) % blockSize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

func (a *AES) pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blockSize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}

// TODO: PKCS5 Implementation is wrong
func (a *AES) pkcs5Pad(b []byte, blockSize int) ([]byte, error) {
	blockSize = 8
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS5Data
	}
	padding := blockSize - len(b)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(b, padText...), nil
}

func (a *AES) pkcs5Unpad(b []byte, blockSize int) ([]byte, error) {
	blockSize = 8
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS5Data
	}
	if len(b)%blockSize != 0 {
		return nil, ErrInvalidPKCS5Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS5Padding
	}
	return b[:len(b)-n], nil
}
