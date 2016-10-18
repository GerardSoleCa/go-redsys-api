package redsys

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"log"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
)


var iv = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func (r *Redsys) encrypt3DES(str string) string {

	block := getCipher(r.Key)
	cbc := cipher.NewCBCEncrypter(block, iv)

	decrypted := []byte(str)
	decryptedPadded, _ := zeroPad(decrypted, block.BlockSize())
	cbc.CryptBlocks(decryptedPadded, decryptedPadded)

	return base64.StdEncoding.EncodeToString(decryptedPadded)
}

func (r *Redsys) decrypt3DES(str string) string {

	block := getCipher(r.Key)
	cbc := cipher.NewCBCDecrypter(block, iv)

	encrypted, _ := base64.StdEncoding.DecodeString(str)
	cbc.CryptBlocks(encrypted, encrypted)

	unpaddedResult, _ := zeroUnpad(encrypted, block.BlockSize())

	return string(unpaddedResult)
}

func (r *Redsys) mac256(data string, key string) string {
	decodedKey, _ := base64.StdEncoding.DecodeString(key)
	hmac := hmac.New(sha256.New, []byte(decodedKey))
	hmac.Write([]byte(strings.TrimSpace(data)))
	result := hmac.Sum(nil)
	return base64.StdEncoding.EncodeToString(result)
}

func getCipher(key string) cipher.Block {
	secretKey, err := base64.StdEncoding.DecodeString(key)

	if err != nil {
		log.Panic("Error decoding key", err)
	}

	crypto, err := des.NewTripleDESCipher(secretKey)
	if err != nil {
		log.Panic("Error generating cipher", err)
	}
	return crypto
}

// zeroPad function to terminate blocksize in zeros
func zeroPad(data []byte, blocklen int) ([]byte, error) {
	padlen := (blocklen - (len(data) % blocklen)) % blocklen
	pad := bytes.Repeat([]byte{0x00}, padlen)

	return append(data, pad...), nil
}

// zeroUnpad function to remove trailing zeros
func zeroUnpad(data []byte, blocklen int) ([]byte, error) {
	lastIndex := len(data)
	for lastIndex >= 0 && lastIndex > len(data)-blocklen-1 {
		lastIndex--
		if data[lastIndex] != 0 {
			break
		}
	}
	return data[:lastIndex+1], nil
}
